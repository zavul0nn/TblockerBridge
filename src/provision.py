"""Root-only provisioning primitives. No Docker mutations, no global firewall restore."""
import base64
import datetime as dt
try:
    import grp
    import pwd
except ImportError:
    grp = pwd = None
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

APP=Path('/opt/tblockerbridge')
ETC=Path('/etc/tblockerbridge')
STATE=Path('/var/lib/tblockerbridge')
USER='tblockerbridge'
UNIT=Path('/etc/systemd/system/tblockerbridge.service')
JOURNAL=Path('/etc/systemd/journald@tblockerbridge.conf')
RUNTIME=Path('/run/tblockerbridge')

def run(args, *, input=None, check=True):
    p=subprocess.run(args,input=input,text=True,capture_output=True,timeout=120)
    if check and p.returncode:
        raise RuntimeError('Command failed: '+str(args[0])+'; '+p.stderr.strip()[:1500])
    return p

def safe_id(value):
    if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{12}',value):
        raise ValueError('Invalid installation ID')
    return value

def source_paths(instance):
    instance=safe_id(instance)
    return (Path('/opt/tblockerbridge-export-'+instance),
            Path('/var/lib/tblockerbridge-export-'+instance),'tbexp_'+instance)

def check_system():
    if sys.version_info<(3,10):raise RuntimeError('Python 3.10+ is required')
    if os.geteuid()!=0:raise RuntimeError('Root is required')
    if not Path('/run/systemd/system').is_dir():raise RuntimeError('systemd is required')
    values={}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            k,v=line.split('=',1);values[k]=v.strip('"')
    distro=values.get('ID'); version=tuple(int(x) for x in values.get('VERSION_ID','0').split('.') if x.isdigit())
    if not ((distro=='debian' and version>=(12,)) or (distro=='ubuntu' and version>=(22,4))):
        raise RuntimeError('Supported: Debian 12+ / Ubuntu 22.04+')

def no_symlink(path):
    path=Path(path)
    if path.is_symlink():raise RuntimeError('Refusing symlink: '+str(path))
    for parent in path.parents:
        if parent.is_symlink():raise RuntimeError('Refusing symlink parent: '+str(parent))

def write(path,data,mode=0o644,group=None):
    path=Path(path);no_symlink(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.new')
    no_symlink(temp)
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data.encode() if isinstance(data,str) else data);f.flush();os.fsync(f.fileno())
        os.chmod(temp,mode)
        os.chown(temp,0,grp.getgrnam(group).gr_gid if group else 0)
        os.replace(temp,path)
    finally:
        temp.unlink(missing_ok=True)

def user_exists(name):
    try:pwd.getpwnam(name);return True
    except KeyError:return False

def add_user(name,home):
    run(['useradd','--system','--user-group','--no-create-home','--home-dir',str(home),'--shell','/bin/sh','--password','*',name])
    home.mkdir(mode=0o755)

def marker(path):
    no_symlink(path)
    return json.loads((Path(path)/'install.json').read_text())

def backup(role,instance,service=None,config=None):
    path=Path('/var/backups/tblockerbridge')/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'-'+instance+'-'+role)
    path.mkdir(parents=True,mode=0o700)
    if shutil.which('nft'):
        write(path/'nft-before.json',run(['nft','-j','list','ruleset']).stdout,0o600)
    units=['docker.service','haproxy.service']+([service] if service else [])
    write(path/'services-before.txt',run(['systemctl','show',*units,'-p','Id','-p','MainPID','-p','ExecMainStartTimestamp'],check=False).stdout,0o600)
    if config:
        write(path/'source-config.sha256',hashlib.sha256(Path(config).read_bytes()).hexdigest()+'\n',0o600)
    return str(path)

def yaml_scalar(path,key):
    pattern=re.compile(r'^'+re.escape(key)+r':\s*(.*?)\s*$')
    for line in Path(path).read_text().splitlines():
        m=pattern.match(line)
        if not m:continue
        value=m[1]
        # Only simple scalars used by the upstream config. Never evaluate YAML tags.
        if value.startswith(('"',"'")):
            quote=value[0];end=value.rfind(quote)
            if end<=0:raise ValueError('Invalid quoted config scalar')
            scalar=value[:end+1]
            return json.loads(scalar) if quote=='"' else scalar[1:-1].replace("''", "'")
        return value.split(' #',1)[0].strip()
    return None

def service_name(value):
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@-]*\.service',value):raise ValueError('Invalid service name')
    return value

def absolute_path(value):
    path=Path(value)
    if not path.is_absolute() or '..' in path.parts or '\n' in value or '\r' in value:
        raise ValueError('Expected absolute path')
    return path

def probe_source(req):
    check_system()
    service=service_name(req['service']);config=absolute_path(req['config'])
    run(['systemctl','is-active','--quiet',service])
    storage_dir=yaml_scalar(config,'StorageDir')
    if not storage_dir:raise ValueError('StorageDir must be explicit in source config')
    storage=absolute_path(storage_dir)/'blocked_ips.json'
    duration=yaml_scalar(config,'BlockDuration')
    if not duration or not str(duration).isdigit() or not 1<=int(duration)<=1440:
        raise ValueError('BlockDuration must be an integer, 1..1440 minutes')
    if not storage.parent.is_dir():raise ValueError('StorageDir does not exist')
    if storage.is_symlink() and not storage.exists():raise ValueError('Dangling storage symlink')
    data=json.loads(storage.read_text()) if storage.exists() else {}
    if not isinstance(data,dict):raise ValueError('Unsupported source storage format')
    addresses=json.loads(run(['ip','-j','address']).stdout)
    ipv4=[info['local'] for device in addresses for info in device.get('addr_info',[]) if info['family']=='inet']
    connection=os.environ.get('TBLOCKERBRIDGE_SSH_CONNECTION',os.environ.get('SSH_CONNECTION','')).split()
    return {'storage':str(storage),'max_ttl':int(duration)*60,'service':service,
            'ipv4':ipv4,'connection':connection,'source_time':time.time(),
            'config_hash':hashlib.sha256(config.read_bytes()).hexdigest(),
            'service_state':run(['systemctl','show',service,'-p','MainPID','-p','ExecMainStartTimestamp']).stdout}

def source_install(req):
    probe=probe_source(req)
    app,home,user=source_paths(req['instance'])
    for path in [app,home]:
        no_symlink(path)
        if path.exists():raise RuntimeError('Already exists: '+str(path))
    if user_exists(user):raise RuntimeError('Source account already exists')
    saved=backup('source',req['instance'],req['service'],req['config'])
    app.mkdir(mode=0o755)
    write(app/'install.json',json.dumps({'instance':req['instance'],'role':'source','backup':saved}),0o600)
    try:
        add_user(user,home)
        write(app/'tblockerbridge.py',base64.b64decode(req['code']),0o755)
        write(app/'export.json',json.dumps({'storage':probe['storage'],'service':req['service']}))
        parent=str(Path(probe['storage']).parent)
        run(['runuser','-u',user,'--','test','-r',parent])
        run(['runuser','-u',user,'--','test','-x',parent])
        # Check the whole snapshot as the actual unprivileged exporter account.
        run(['runuser','-u',user,'--','/usr/bin/python3','-c',
             'import json,pathlib; p=pathlib.Path('+repr(probe['storage'])+'); d=json.load(p.open()) if p.exists() else {}; assert isinstance(d,dict)'])
        ssh_config=run(['/usr/sbin/sshd','-T','-C','user='+user+',host=localhost,addr='+req['peer_ip']]).stdout
        keys_line=next((x for x in ssh_config.splitlines() if x.startswith('authorizedkeysfile ')),'')
        if '.ssh/authorized_keys' not in keys_line.split():
            raise RuntimeError('Custom sshd AuthorizedKeysFile: per-user default is required')
        ipaddress.ip_address(req['peer_ip'])
        key=req['public_key'].strip()
        if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]+)?',key):raise ValueError('Invalid public key')
        # Do not interpolate user input into the forced shell command.
        command='/usr/bin/python3 -I '+str(app)+'/tblockerbridge.py export '+str(app)+'/export.json'
        write(home/'.ssh'/'authorized_keys',f'from="{req["peer_ip"]}",restrict,command="{command}" '+key+'\n')
        os.chmod(home/'.ssh',0o755)
        if probe_source(req)['config_hash']!=probe['config_hash']:raise RuntimeError('Source config changed during installation')
        return {'user':user,'app':str(app),'backup':saved}
    except Exception:
        source_remove({'instance':req['instance']})
        raise

def source_remove(req):
    app,home,user=source_paths(req['instance'])
    if not app.exists():return {'removed':False}
    owned=marker(app)
    if owned.get('instance')!=req['instance'] or owned.get('role')!='source':raise RuntimeError('Unowned exporter')
    if user_exists(user):
        if pwd.getpwnam(user).pw_dir!=str(home):raise RuntimeError('Unexpected account home')
        # Only this installation's dedicated exporter processes are stopped.
        run(['pkill','-TERM','-u',user],check=False)
        time.sleep(.2)
        run(['userdel',user])
    for path in [home,app]:
        no_symlink(path)
        if path.exists():shutil.rmtree(path)
    return {'removed':True}

def source_update(req):
    app,home,user=source_paths(req['instance'])
    owned=marker(app)
    if owned.get('instance')!=req['instance'] or owned.get('role')!='source':raise RuntimeError('Unowned exporter')
    old=(app/'tblockerbridge.py').read_bytes()
    old_config=(app/'export.json').read_bytes()
    new=base64.b64decode(req['code'])
    compile(new,'tblockerbridge.py','exec')
    probe=probe_source(req)
    try:
        write(app/'tblockerbridge.py.previous',old,0o600)
        write(app/'tblockerbridge.py',new,0o755)
        write(app/'export.json',json.dumps({'storage':probe['storage'],'service':req['service']}))
    except BaseException:
        write(app/'tblockerbridge.py',old,0o755)
        write(app/'export.json',old_config)
        raise
    return {'updated':True}

def unit():
    return '''[Unit]
Description=TblockerBridge - mirror tblocker bans to HAProxy
Wants=network-online.target
After=network-online.target nftables.service ufw.service
StartLimitIntervalSec=0

[Service]
Type=simple
User=tblockerbridge
Group=tblockerbridge
WorkingDirectory=/opt/tblockerbridge
ExecStart=/usr/bin/python3 -I /opt/tblockerbridge/tblockerbridge.py mirror
Restart=always
RestartSec=3
RuntimeDirectory=tblockerbridge
RuntimeDirectoryMode=0750
StateDirectory=tblockerbridge
StateDirectoryMode=0750
UMask=0077
Environment=LC_ALL=C
Environment=PYTHONDONTWRITEBYTECODE=1
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
MemoryMax=128M
TasksMax=16
LogNamespace=tblockerbridge
LogRateLimitIntervalSec=30s
LogRateLimitBurst=60

[Install]
WantedBy=multi-user.target
'''

def dispatch(req):
    check_system()
    operations={'probe':probe_source,'install':source_install,'remove':source_remove,'update':source_update}
    if req.get('operation') not in operations:raise ValueError('Unknown operation')
    return operations[req['operation']](req)
