#!/usr/bin/python3
"""Read-only tblocker exporter and SSH/nftables mirror. Python standard library only."""
import datetime as dt
try:
    import fcntl
except ImportError:  # Import pure validators in development on non-Linux hosts.
    fcntl = None
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time

MAX_BYTES = 2 * 1024 * 1024
TABLE = 'tblockerbridge'
LOG = logging.getLogger('tblockerbridge')
VERSION = '1.0.0'

def decode(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError('oversized snapshot')
    def pairs(items):
        result = {}
        for key, val in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = val
        return result
    return json.loads(raw, object_pairs_hook=pairs)

def parse_storage(data):
    if not isinstance(data, dict) or len(data) > 10000:
        raise ValueError('invalid storage map')
    result = {}
    for key, item in data.items():
        if not isinstance(item, dict) or item.get('ip') != key:
            raise ValueError('IP key mismatch')
        address = ipaddress.ip_address(key)
        # Upstream parser and nft set support IPv4 only.
        if address.version != 4:
            raise ValueError('upstream IPv6 unsupported')
        until = dt.datetime.fromisoformat(item['blocked_until'].replace('Z', '+00:00'))
        if until.tzinfo is None:
            raise ValueError('timezone required')
        result[str(address)] = until.timestamp()
    return result

def stable_read(path):
    # Upstream uses os.WriteFile rather than atomic rename. Never treat a
    # truncated/partially written file as an authoritative empty snapshot.
    try:
        with open(path, 'rb') as f:
            first = f.read(MAX_BYTES + 1)
    except FileNotFoundError:
        # Upstream creates storage only on the first violation. Never create it
        # ourselves. A missing parent or dangling symlink is a config/error case.
        path = Path(path)
        if path.parent.is_dir() and not path.is_symlink():
            return {}
        raise
    data = parse_storage(decode(first))
    time.sleep(0.03)
    with open(path, 'rb') as f:
        second = f.read(MAX_BYTES + 1)
    if first != second:
        raise ValueError('storage changed while reading')
    return data

def export(path='/opt/tblocker/blocked_ips.json', check_service=True, service='tblocker.service', interval=1):
    last_error = 0
    while True:
        started = time.monotonic()
        try:
            if check_service and subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', service],
                              timeout=3).returncode:
                raise ValueError('source service inactive')
            blocks = stable_read(path)
            print(json.dumps({'version': 1, 'generated': time.time(), 'blocks': blocks},
                             separators=(',', ':')), flush=True)
        except (ValueError, OSError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
            if time.monotonic() - last_error > 60:
                print('tblockerbridge: source unavailable or invalid; snapshot withheld', file=sys.stderr, flush=True)
                last_error = time.monotonic()
        time.sleep(max(0, interval - (time.monotonic() - started)))

def validate_blocks(blocks, now, excluded, max_ttl=300, allow_test=False):
    if not isinstance(blocks, dict) or len(blocks) > 10000:
        raise ValueError('invalid blocks')
    result = {}
    networks = [ipaddress.ip_network(x) for x in excluded]
    for key, until in blocks.items():
        address = ipaddress.ip_address(key)
        if address.version != 4 or str(address) != key:
            raise ValueError('noncanonical IPv4')
        if isinstance(until, bool) or not isinstance(until, (float, int)) or not math.isfinite(until):
            raise ValueError('invalid expiration')
        if until > now + max_ttl + 5:
            raise ValueError('expiration exceeds configured maximum')
        unsafe = (not address.is_global or address.is_multicast or address.is_reserved
                  or address.is_loopback or address.is_link_local or address.is_unspecified)
        if unsafe and not (allow_test and address in ipaddress.ip_network('192.0.2.0/24')):
            continue
        if any(address in net for net in networks):
            continue
        if until > now:
            result[key] = until
    return result

def snapshot(raw, excluded, max_ttl=300):
    data = decode(raw)
    now = time.time()
    if not isinstance(data, dict) or type(data.get('version')) is not int or data['version'] != 1:
        raise ValueError('invalid protocol version')
    generated = data.get('generated')
    if isinstance(generated, bool) or not isinstance(generated, (int, float)) or not math.isfinite(generated):
        raise ValueError('invalid source time')
    if abs(now - generated) > 5:
        raise ValueError('source clock skew or stale snapshot')
    return validate_blocks(data['blocks'], now, excluded, max_ttl)

class Firewall:
    def __init__(self, table=TABLE, allow_test=False, port=2053, max_ttl=300):
        if table not in (TABLE, 'tbsync_test'):
            raise ValueError('unowned nft table')
        self.table = table
        self.allow_test = allow_test
        if type(port) is not int or not 1 <= port <= 65535 or port == 22:
            raise ValueError('invalid frontend port')
        self.port = port
        self.max_ttl = max_ttl

    def exists(self):
        p = subprocess.run(['/usr/sbin/nft', 'list', 'table', 'inet', self.table],
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=5)
        if p.returncode == 0:
            return True
        if b'No such file or directory' in p.stderr:
            return False
        raise RuntimeError('nft table lookup failed: ' + p.stderr.decode())

    def apply(self, blocks):
        now = time.time()
        # Validate again immediately before constructing commands. Tests can
        # permit TEST-NET only in their separate network namespace.
        blocks = validate_blocks(blocks, now, [], self.max_ttl, self.allow_test)
        t = self.table
        commands = []
        if self.exists():
            commands += [f'flush set inet {t} blocked_v4']
        else:
            commands += [f'add table inet {t} {{ comment "TblockerBridge managed"; }}',
                         f'add set inet {t} blocked_v4 {{ type ipv4_addr; flags timeout; gc-interval 1s; }}',
                         f'add chain inet {t} input {{ type filter hook input priority -20; policy accept; }}',
                         f'add rule inet {t} input tcp dport {self.port} ip saddr @blocked_v4 counter drop']
        elements = []
        for ip, until in sorted(blocks.items()):
            ttl = int((until - now) * 1000)
            if ttl >= 1:
                elements.append(f'{ip} timeout {ttl}ms')
        if elements:
            commands.append(f'add element inet {t} blocked_v4 {{ ' + ', '.join(elements) + ' }')
        # nft -f commits the entire batch atomically: no unblocked window.
        p = subprocess.run(['/usr/sbin/nft', '-f', '-'], input='\n'.join(commands)+'\n',
                           text=True, capture_output=True, timeout=5)
        if p.returncode:
            raise RuntimeError('nft transaction failed: ' + p.stderr)

def atomic_json(path, value):
    path = Path(path)
    temp = path.with_suffix('.tmp')
    with temp.open('w') as f:
        json.dump(value, f, separators=(',', ':'))
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)

def mirror():
    cfg = json.loads(Path('/etc/tblockerbridge/config.json').read_text())
    lock = open('/run/tblockerbridge/lock', 'w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    excluded = cfg['excluded']
    max_ttl = cfg['max_ttl']
    cache = Path('/var/lib/tblockerbridge/state.json')
    blocks = {}
    if cache.exists():
        try:
            blocks = validate_blocks(decode(cache.read_bytes()), time.time(), excluded, max_ttl)
        except (ValueError, OSError, TypeError):
            LOG.warning('Invalid cache ignored')
    firewall = Firewall(port=cfg['port'], max_ttl=max_ttl)
    firewall.apply(blocks)
    last_apply = time.monotonic()
    last_error = 0
    while True:
        command = ['/usr/bin/ssh', '-F', '/etc/tblockerbridge/ssh_config', 'source']
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        buffer = b''
        received = time.monotonic()
        connected = False
        try:
            while True:
                events = selector.select(1)
                if time.monotonic() - received > 8:
                    raise TimeoutError('SSH stream timeout')
                if events:
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        raise ConnectionError('SSH stream closed')
                    buffer += chunk
                    if len(buffer) > MAX_BYTES:
                        raise ValueError('oversized stream')
                    while b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)
                        new = snapshot(line, excluded, max_ttl)
                        received = time.monotonic()
                        if new != blocks:
                            firewall.apply(new)
                            atomic_json(cache, new)
                            LOG.info('State applied: active=%d', len(new))
                            blocks = new
                            last_apply = time.monotonic()
                        if not connected:
                            LOG.info('Source connected; active=%d', len(blocks))
                            connected = True
                        atomic_json('/run/tblockerbridge/status.json', {'source_ok': True,
                                    'last_snapshot': time.time(), 'active': len(blocks)})
                if time.monotonic() - last_apply >= 10:
                    blocks = validate_blocks(blocks, time.time(), excluded, max_ttl)
                    firewall.apply(blocks)
                    atomic_json(cache, blocks)
                    last_apply = time.monotonic()
        except (ValueError, OSError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
            atomic_json('/run/tblockerbridge/status.json', {'source_ok': False, 'error': str(error),
                        'active': sum(x > time.time() for x in blocks.values())})
            if time.monotonic() - last_error > 30:
                LOG.warning('Source/reconcile error: %s; existing TTLs remain finite', error)
                last_error = time.monotonic()
        finally:
            selector.close()
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            process.stdout.close()
        time.sleep(2)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    if sys.argv[1:] == ['--version']:
        print(VERSION)
    elif len(sys.argv) == 3 and sys.argv[1] == 'export':
        cfg = json.loads(Path(sys.argv[2]).read_text())
        export(cfg['storage'], service=cfg['service'])
    elif sys.argv[1:] == ['mirror']:
        mirror()
    else:
        sys.exit('usage: tblockerbridge.py export CONFIG|mirror|--version')
