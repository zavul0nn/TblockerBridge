#!/usr/bin/env python3
"""Interactive installer for a reviewed checkout; all SSH authentication is native."""
import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'src'))
import provision as p
import tblockerbridge as core

def say(message):print(message,flush=True)
def prompt(message,default=None):
    suffix=f' [{default}]' if default is not None else ''
    answer=input(message+suffix+': ').strip()
    return answer if answer else default

def port(value):
    value=int(value)
    if not 1<=value<=65535:raise ValueError('Port must be 1..65535')
    return value

def hostname(value):
    if not value or len(value)>253 or not re.fullmatch(r'[A-Za-z0-9._:-]+',value) or value.startswith('-'):
        raise ValueError('Invalid SSH hostname/IP')
    return value

def username(value):
    if not re.fullmatch('[a-z_][a-z0-9_-]{0,31}',value):raise ValueError('Invalid SSH username')
    return value

def bootstrap(packages,remote=None):
    if not packages:return
    say('Installing missing dependencies, without daemon starts/restarts: '+', '.join(packages))
    script=(ROOT/'scripts-bootstrap.sh').read_text()
    if remote:
        remote.command('sh -s -- '+' '.join(shlex.quote(x) for x in packages),input=script,capture=False)
    else:
        subprocess.run(['/bin/sh',str(ROOT/'scripts-bootstrap.sh'),*packages],check=True)

class Remote:
    def __init__(self,config):
        self.config=config
        self.temp=tempfile.TemporaryDirectory(prefix='tblockerbridge-ssh-',dir='/run')
        self.socket=str(Path(self.temp.name)/'control')
        self.base=['ssh','-p',str(config['ssh_port']),'-o','ConnectTimeout=10',
                   '-o','ControlMaster=auto','-o','ControlPersist=600','-o','ControlPath='+self.socket]
        if config.get('admin_key'):
            self.base+=['-i',config['admin_key'],'-o','IdentitiesOnly=yes']
        self.target=username(config['admin_user'])+'@'+hostname(config['host'])
        self.sudo='' if config['admin_user']=='root' else 'sudo -n '
    def connect(self):
        say('SSH: verify the displayed host-key fingerprint against your server console.')
        # This is the only trust bootstrap. Native ssh asks before accepting new keys;
        # changed known keys are rejected. Passwords/passphrases stay in ssh /dev/tty.
        command=self.sudo+'id -u'
        out=subprocess.run(self.base+['-o','StrictHostKeyChecking=ask',self.target,command],
                           text=True,stdout=subprocess.PIPE,check=True).stdout
        if out.strip()!='0':raise RuntimeError('Remote root or passwordless sudo required')
    def command(self,command,*,input=None,capture=True):
        result=subprocess.run(self.base+['-o','StrictHostKeyChecking=yes',self.target,self.sudo+command],
                              input=input,text=True,stdout=subprocess.PIPE if capture else None,check=True)
        return result.stdout if capture else ''
    def operation(self,request):
        encoded=base64.b64encode(json.dumps(request).encode()).decode()
        module=(ROOT/'src'/'provision.py').read_text()
        script=module+'\nREQUEST=json.loads(base64.b64decode('+repr(encoded)+'))\nprint("TBLOCKERBRIDGE_RESULT="+json.dumps(dispatch(REQUEST)))\n'
        out=self.command('env TBLOCKERBRIDGE_SSH_CONNECTION="$SSH_CONNECTION" python3 -',input=script)
        matches=[x for x in out.splitlines() if x.startswith('TBLOCKERBRIDGE_RESULT=')]
        if len(matches)!=1:raise RuntimeError('Unexpected provisioning response')
        return json.loads(matches[0].split('=',1)[1])
    def known_hosts(self):
        host=self.config['host'];ssh_port=self.config['ssh_port']
        lookup=host if ssh_port==22 else '['+host+']:'+str(ssh_port)
        # Copy only keys already authenticated by the interactive SSH connection.
        lines=[]
        for known in [Path.home()/'.ssh'/'known_hosts',Path('/etc/ssh/ssh_known_hosts')]:
            if not known.exists():continue
            out=p.run(['ssh-keygen','-F',lookup,'-f',str(known)],check=False).stdout
            lines += [line for line in out.splitlines() if line and not line.startswith('#')]
        if not lines:raise RuntimeError('Authenticated host key was not saved to root known_hosts')
        return '\n'.join(lines)+'\n'
    def close(self):
        subprocess.run(self.base+['-O','exit',self.target],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.temp.cleanup()

def local_probe(frontend_port):
    p.check_system()
    listener=p.run(['ss','-H','-ltnp','sport = :'+str(frontend_port)]).stdout
    if not listener.strip() or any('haproxy' not in line for line in listener.splitlines()):
        raise RuntimeError('Expected HAProxy listening in host network on TCP '+str(frontend_port)+
                           '. Docker bridge/DNAT frontend is unsupported; no network changes made.')
    if p.run(['systemctl','is-active','--quiet','tbsync.service'],check=False).returncode==0:
        raise RuntimeError('Legacy tbsync is active. Migrate separately; refusing parallel mirrors.')
    docker='Docker CLI absent'
    if shutil.which('docker'):
        docker=p.run(['docker','ps','--no-trunc','--format','{{.Names}}\t{{.Status}}'],check=False).stdout
    addresses=json.loads(p.run(['ip','-j','address']).stdout)
    ips=[x['local'] for device in addresses for x in device.get('addr_info',[]) if x['family']=='inet']
    say('HAProxy host listener confirmed. Docker inventory (read only):\n'+docker)
    return ips

def fresh_layout():
    for path in [p.APP,p.ETC,p.STATE,p.UNIT,p.JOURNAL]:
        p.no_symlink(path)
        if path.exists():raise RuntimeError('Unmanaged/pre-existing path: '+str(path))
    if p.user_exists(p.USER):raise RuntimeError('Account tblockerbridge already exists')
    if p.run(['nft','list','table','inet','tblockerbridge'],check=False).returncode==0:
        raise RuntimeError('Table inet tblockerbridge already exists')

def ssh_config(config,export_user):
    return f'''Host source
    HostName {hostname(config['host'])}
    Port {port(config['ssh_port'])}
    User {username(export_user)}
    IdentityFile /etc/tblockerbridge/id_ed25519
    IdentitiesOnly yes
    BatchMode yes
    StrictHostKeyChecking yes
    UserKnownHostsFile /etc/tblockerbridge/known_hosts
    GlobalKnownHostsFile /dev/null
    UpdateHostKeys no
    ConnectTimeout 5
    ConnectionAttempts 1
    ServerAliveInterval 2
    ServerAliveCountMax 2
    RequestTTY no
    ClearAllForwardings yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    LogLevel ERROR
'''

def first_snapshot():
    command=['runuser','-u',p.USER,'--','ssh','-F','/etc/tblockerbridge/ssh_config','source']
    proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    sel=selectors.DefaultSelector();sel.register(proc.stdout,selectors.EVENT_READ)
    try:
        if not sel.select(12):raise RuntimeError('No snapshot: check source file permissions and SSH access')
        line=proc.stdout.readline(core.MAX_BYTES+1)
        if not line:raise RuntimeError('Restricted SSH exporter rejected; inspect sshd access rules')
        cfg=json.loads((p.ETC/'config.json').read_text())
        core.snapshot(line,cfg['excluded'],cfg['max_ttl'])
    finally:
        sel.close();proc.terminate()
        try:proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:proc.kill();proc.communicate()

def wait_healthy(seconds=15):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:
            status=json.loads(Path('/run/tblockerbridge/status.json').read_text())
            if status.get('source_ok') and abs(time.time()-status['last_snapshot'])<5:
                say('Source connected. Active bans: '+str(status['active']));return
        except (OSError,ValueError,KeyError):pass
        time.sleep(1)
    raise RuntimeError('Service did not receive a fresh snapshot; installation is not healthy')

def ask_config():
    host=hostname(prompt('Выходная нода: IP или hostname'))
    ssh_port=port(prompt('SSH-порт выходной ноды','22'))
    admin_user=username(prompt('SSH-пользователь (root или sudo без пароля)','root'))
    key=prompt('Путь к административному SSH-ключу; Enter = агент/пароль','')
    if key:
        key=str(Path(key).expanduser().resolve())
        if not Path(key).is_file():raise ValueError('SSH key not found')
    frontend_port=port(prompt('TCP-порт HAProxy для блокировок','2053'))
    if frontend_port==22:raise ValueError('Refusing frontend port 22')
    service=p.service_name(prompt('Systemd-служба tblocker','tblocker.service'))
    config=str(p.absolute_path(prompt('Конфиг tblocker на выходной ноде','/opt/tblocker/config.yaml')))
    extra=prompt('IP/CIDR инфраструктуры, которые нельзя блокировать (через запятую)','')
    excluded=[str(ipaddress.ip_network(x.strip(),strict=False)) for x in extra.split(',') if x.strip()]
    return dict(host=host,ssh_port=ssh_port,admin_user=admin_user,admin_key=key,
                port=frontend_port,service=service,config=config,excluded=excluded)

def install():
    if p.APP.exists():
        owned=p.marker(p.APP)
        if owned.get('role')!='ingress':raise RuntimeError('Unmanaged installation')
        say('TblockerBridge is already installed. Checking health; use update to replace code.')
        wait_healthy(5);return
    config=ask_config()
    packages=[pkg for command,pkg in [('ssh','openssh-client'),('ssh-keygen','openssh-client'),('nft','nftables'),('ss','iproute2'),('runuser','util-linux'),('useradd','passwd')] if not shutil.which(command)]
    bootstrap(list(dict.fromkeys(packages)))
    own_ips=local_probe(config['port']);fresh_layout()
    remote=Remote(config);remote_created=False;local_created=False
    instance=uuid.uuid4().hex[:12]
    request={'instance':instance,'config':config['config'],'service':config['service']}
    try:
        remote.connect()
        # Bootstrap only if the existing SSH server lacks Python/iproute2.
        missing=remote.command("sh -c 'command -v python3 >/dev/null || echo python3; command -v ip >/dev/null || echo iproute2; command -v runuser >/dev/null || echo util-linux; command -v useradd >/dev/null || echo passwd; command -v pkill >/dev/null || echo procps'")
        bootstrap(missing.split(),remote)
        before=time.time();probe=remote.operation(dict(request,operation='probe'));after=time.time()
        if not before-5<=probe['source_time']<=after+5:raise RuntimeError('Clock skew exceeds 5 seconds; synchronize server clocks first')
        observed=probe['connection'][0] if probe.get('connection') else None
        peer=prompt('IP HAProxy, наблюдаемый выходной нодой (для ограничения SSH-ключа)',observed)
        ipaddress.ip_address(peer)
        excluded=set(config['excluded'])
        for value in own_ips+probe['ipv4']+[peer]+os.environ.get('SSH_CONNECTION','').split()[::2][:2]:
            try:excluded.add(str(ipaddress.ip_network(value,strict=False)))
            except ValueError:pass
        for route in json.loads(p.run(['ip','-j','route']).stdout):
            if route.get('gateway'):excluded.add(str(ipaddress.ip_network(route['gateway'],strict=False)))
        saved=p.backup('ingress',instance)
        p.APP.mkdir(mode=0o755);local_created=True
        p.write(p.APP/'install.json',json.dumps({'instance':instance,'role':'ingress','connection':config,'backup':saved}),0o600)
        p.add_user(p.USER,p.STATE)
        os.chown(p.STATE,pwd_uid(p.USER),group_gid(p.USER));os.chmod(p.STATE,0o750)
        p.ETC.mkdir(mode=0o750);os.chown(p.ETC,0,group_gid(p.USER))
        p.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','TblockerBridge-'+instance,'-f',str(p.ETC/'id_ed25519')])
        os.chown(p.ETC/'id_ed25519',0,group_gid(p.USER));os.chmod(p.ETC/'id_ed25519',0o640)
        code=(ROOT/'src'/'tblockerbridge.py').read_bytes()
        req=dict(request,operation='install',peer_ip=peer,public_key=(p.ETC/'id_ed25519.pub').read_text(),code=base64.b64encode(code).decode())
        result=remote.operation(req);remote_created=True
        p.write(p.ETC/'known_hosts',remote.known_hosts(),0o640,p.USER)
        p.write(p.ETC/'ssh_config',ssh_config(config,result['user']),0o640,p.USER)
        runtime={'port':config['port'],'excluded':sorted(excluded),'max_ttl':probe['max_ttl']}
        p.write(p.ETC/'config.json',json.dumps(runtime,indent=2)+'\n',0o640,p.USER)
        p.write(p.APP/'tblockerbridge.py',code,0o755)
        first_snapshot()  # Verify restricted key + file permissions BEFORE firewall service.
        refreshed=remote.operation(dict(request,operation='probe'))
        if refreshed['config_hash']!=probe['config_hash'] or refreshed['service_state']!=probe['service_state']:
            raise RuntimeError('tblocker configuration/process changed during installation')
        p.write(p.UNIT,p.unit())
        p.write(p.JOURNAL,'[Journal]\nStorage=persistent\nSystemMaxUse=32M\nRuntimeMaxUse=8M\nSystemMaxFileSize=8M\nMaxRetentionSec=7day\n')
        p.run(['systemd-analyze','verify',str(p.UNIT)])
        p.run(['systemctl','daemon-reload']);p.run(['systemctl','enable','--now','tblockerbridge.service'])
        wait_healthy()
        say('Готово. journalctl --namespace=tblockerbridge -u tblockerbridge -f')
        say('Backup: '+saved+'; source backup: '+result['backup'])
    except BaseException:
        say('Installation failed. Rolling back ONLY TblockerBridge objects; dependency packages and backups remain.')
        if local_created:
            try:remove_local(instance)
            except Exception as error:say('LOCAL ROLLBACK ERROR: '+str(error))
        # A failed SSH reply may follow a successful remote commit: inspect by ID.
        try:remote.operation(dict(request,operation='remove'))
        except Exception as error:say('REMOTE CLEANUP REQUIRED for instance '+instance+': '+str(error))
        raise
    finally:remote.close()

def pwd_uid(user):return p.pwd.getpwnam(user).pw_uid
def group_gid(user):return p.grp.getgrnam(user).gr_gid

def remove_local(instance):
    owned=p.marker(p.APP)
    if owned.get('role')!='ingress' or owned.get('instance')!=instance:raise RuntimeError('Unowned installation')
    p.run(['systemctl','disable','--now','tblockerbridge.service'],check=False)
    result=p.run(['nft','-j','list','table','inet','tblockerbridge'],check=False)
    if result.returncode==0:
        tables=[x['table'] for x in json.loads(result.stdout)['nftables'] if 'table' in x]
        if not tables or tables[0].get('comment')!='TblockerBridge managed':
            raise RuntimeError('Refusing to delete a table without TblockerBridge ownership comment')
        p.run(['nft','delete','table','inet','tblockerbridge'])
    p.UNIT.unlink(missing_ok=True);p.run(['systemctl','daemon-reload'])
    p.run(['systemctl','stop','systemd-journald@tblockerbridge.service','systemd-journald@tblockerbridge.socket','systemd-journald-varlink@tblockerbridge.socket'],check=False)
    p.JOURNAL.unlink(missing_ok=True)
    if p.user_exists(p.USER):
        if p.pwd.getpwnam(p.USER).pw_dir!=str(p.STATE):raise RuntimeError('Unexpected local account home')
        p.run(['userdel',p.USER])
    for path in [p.ETC,p.STATE,p.RUNTIME,p.APP]:
        p.no_symlink(path)
        if path.exists():shutil.rmtree(path)

def manage(action):
    owned=p.marker(p.APP);instance=p.safe_id(owned['instance']);config=owned['connection']
    if owned.get('role')!='ingress':raise RuntimeError('Unmanaged installation')
    remote=Remote(config)
    try:
        remote.connect()
        request={'instance':instance,'config':config['config'],'service':config['service']}
        if action=='uninstall':
            # Local removal stops the mirror first; remote failure leaves its manifest
            # locally available for retry rather than claiming complete removal.
            p.run(['systemctl','stop','tblockerbridge.service'])
            remote.operation(dict(request,operation='remove'))
            remove_local(instance)
            say('Removed. Backups, journal history, dependency packages and existing services preserved.')
        else:
            code=(ROOT/'src'/'tblockerbridge.py').read_bytes();compile(code,'tblockerbridge.py','exec')
            old=(p.APP/'tblockerbridge.py').read_bytes()
            old_config=(p.ETC/'config.json').read_bytes()
            runtime=json.loads(old_config)
            probe=remote.operation(dict(request,operation='probe'))
            runtime['max_ttl']=probe['max_ttl']
            try:
                remote.operation(dict(request,operation='update',code=base64.b64encode(code).decode()))
                p.write(p.APP/'tblockerbridge.py.previous',old,0o600)
                p.write(p.APP/'tblockerbridge.py',code,0o755)
                p.write(p.ETC/'config.json',json.dumps(runtime,indent=2)+'\n',0o640,p.USER)
                p.run(['systemctl','restart','tblockerbridge.service']);wait_healthy()
            except BaseException:
                p.write(p.APP/'tblockerbridge.py',old,0o755)
                p.write(p.ETC/'config.json',old_config,0o640,p.USER)
                try:remote.operation(dict(request,operation='update',code=base64.b64encode(old).decode()))
                except Exception as error:say('REMOTE UPDATE ROLLBACK ERROR: '+str(error))
                p.run(['systemctl','restart','tblockerbridge.service'])
                raise
            say('Code updated on both servers; keys/config/port unchanged.')
    finally:remote.close()

def main():
    parser=argparse.ArgumentParser(description='TblockerBridge interactive installer')
    parser.add_argument('action',nargs='?',default='install',choices=['install','update','uninstall','status','doctor'])
    args=parser.parse_args()
    p.check_system()
    if sys.version_info<(3,10):raise RuntimeError('Python 3.10+ required')
    if args.action=='status':
        subprocess.run(['systemctl','status','tblockerbridge','--no-pager'])
        status=Path('/run/tblockerbridge/status.json')
        if status.exists():say(status.read_text())
        return
    if args.action=='doctor':
        wait_healthy(3);first_snapshot();say(p.run(['nft','list','table','inet','tblockerbridge']).stdout);return
    import fcntl
    with open('/run/tblockerbridge-install.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.action=='install':install()
        else:manage(args.action)

if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt) as error:
        say('ERROR: '+str(error));sys.exit(1)
