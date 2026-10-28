import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import installer as i
p=i.p

class ProbeTests(unittest.TestCase):
    def test_fresh_missing_storage_accepted_without_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/'config.yaml'
            config.write_text('StorageDir: '+json.dumps(directory)+'\nBlockDuration: 7\n')
            def command(args,**kwargs):
                out='[]' if args[:2]==['ip','-j'] else 'MainPID=123\n'
                return subprocess.CompletedProcess(args,0,stdout=out,stderr='')
            with patch.object(p,'check_system'),patch.object(p,'run',side_effect=command):
                result=p.probe_source({'service':'tblocker.service','config':str(config)})
            self.assertEqual(result['max_ttl'],420)
            self.assertFalse((Path(directory)/'blocked_ips.json').exists())

    def test_invalid_or_partial_storage_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/'config.yaml';config.write_text('StorageDir: '+json.dumps(directory)+'\nBlockDuration: 5\n')
            (Path(directory)/'blocked_ips.json').write_text('{')
            with patch.object(p,'check_system'),patch.object(p,'run'):
                with self.assertRaises(ValueError):p.probe_source({'service':'tblocker.service','config':str(config)})

    def test_injection_boundaries(self):
        for value in ['-oProxyCommand=evil','host\nHost *','host;reboot']:
            with self.assertRaises(ValueError):i.hostname(value)
        with self.assertRaises(ValueError):p.safe_id('../../')
        with self.assertRaises(ValueError):p.service_name('x;reboot.service')

    def test_bridge_docker_and_mixed_ssh_listener_refused(self):
        for listener in ['LISTEN users:(("docker-proxy",pid=1))',
                         'LISTEN users:(("haproxy",pid=1))\nLISTEN users:(("sshd",pid=2))']:
            with patch.object(p,'check_system'),patch.object(p,'run',return_value=subprocess.CompletedProcess([],0,stdout=listener)):
                with self.assertRaises(RuntimeError):i.local_probe(2053)

class SourceTransactionTests(unittest.TestCase):
    def test_fresh_source_install_does_not_create_upstream_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);app=root/'export';home=root/'home';storage=root/'blocked_ips.json'
            def command(args,**kwargs):
                output='authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n' if args[0]=='/usr/sbin/sshd' else ''
                return subprocess.CompletedProcess(args,0,stdout=output,stderr='')
            req={'instance':'a'*12,'service':'tblocker.service','config':'/example/config','code':'cGFzcw==',
                 'peer_ip':'198.51.100.10','public_key':'ssh-ed25519 QUJDRA== test'}
            with (patch.object(p,'source_paths',return_value=(app,home,'fake_export')),
                  patch.object(p,'probe_source',return_value={'storage':str(storage),'config_hash':'same'}),
                  patch.object(p,'backup',return_value=str(root/'backup')),
                  patch.object(p,'user_exists',return_value=False),
                  patch.object(p,'add_user',side_effect=lambda u,h:h.mkdir()),
                  patch.object(p,'run',side_effect=command),patch.object(p.os,'chown',create=True)):
                result=p.source_install(req)
                self.assertEqual(result['user'],'fake_export')
                self.assertFalse(storage.exists())
                auth=(home/'.ssh'/'authorized_keys').read_text()
                self.assertIn('from="198.51.100.10",restrict,command=',auth)
                self.assertIn(' -I ',auth)
                p.source_remove({'instance':'a'*12})
            self.assertFalse(app.exists());self.assertFalse(home.exists());self.assertFalse(storage.exists())

    def test_failed_read_permission_rolls_back_only_own_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);app=root/'export';home=root/'home';unrelated=root/'docker-data';unrelated.mkdir()
            sentinel=unrelated/'volume';sentinel.write_text('keep')
            def add_user(user,path):path.mkdir()
            def command(args,**kwargs):
                if args[0]=='runuser':raise RuntimeError('permission denied')
                return subprocess.CompletedProcess(args,0,stdout='',stderr='')
            req={'instance':'a'*12,'service':'tblocker.service','config':'/example/config','code':'cGFzcw=='}
            with (patch.object(p,'source_paths',return_value=(app,home,'fake_export')),
                patch.object(p,'probe_source',return_value={'storage':str(root/'missing.json')}),
                patch.object(p,'backup',return_value=str(root/'backup')),
                patch.object(p,'user_exists',return_value=False),patch.object(p,'add_user',side_effect=add_user),
                patch.object(p,'run',side_effect=command),patch.object(p.os,'chown',create=True)):
                with self.assertRaises(RuntimeError):p.source_install(req)
            self.assertFalse(app.exists());self.assertFalse(home.exists());self.assertEqual(sentinel.read_text(),'keep')

class InstallerTransactionTests(unittest.TestCase):
    def scenario(self,fail=False):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root=Path(temp.name)
        config={'host':'egress.example','ssh_port':22,'admin_user':'root','admin_key':'',
                'port':2443,'service':'tblocker.service','config':'/opt/tblocker/config.yaml','excluded':[]}
        calls=[]
        class Remote:
            def __init__(self,c):pass
            def connect(self):calls.append('connect')
            def command(self,*a,**k):return ''
            def known_hosts(self):return 'egress.example ssh-ed25519 PUBLIC\n'
            def close(self):calls.append('close')
            def operation(self,req):
                calls.append(req['operation'])
                if req['operation']=='probe':return {'connection':['198.51.100.10','1','203.0.113.10','22'],
                    'ipv4':['203.0.113.10'],'source_time':time.time(),'max_ttl':420,'config_hash':'hash','service_state':'same'}
                if req['operation']=='install':return {'user':'tbexp_test','backup':'/backup/source'}
                return {'removed':True}
        def command(args,**kwargs):
            if args[0]=='ssh-keygen':
                path=Path(args[-1]);path.write_text('PRIVATE-TEST');path.with_suffix('.pub').write_text('ssh-ed25519 PUBLIC')
            if args[0]=='ip':return subprocess.CompletedProcess(args,0,stdout='[]',stderr='')
            if args[0]=='nft':return subprocess.CompletedProcess(args,1,stdout='',stderr='not found')
            return subprocess.CompletedProcess(args,0,stdout='',stderr='')
        with contextlib.ExitStack() as stack:
            for name in ['APP','ETC','STATE','UNIT','JOURNAL','RUNTIME']:
                stack.enter_context(patch.object(p,name,root/name.lower()))
            for name,replace in [('ask_config',lambda:config),('bootstrap',lambda *a:None),
                                 ('local_probe',lambda n:['198.51.100.10']),('fresh_layout',lambda:None),
                                 ('prompt',lambda message,default:default),('Remote',Remote),
                                 ('pwd_uid',lambda u:0),('group_gid',lambda u:0),('wait_healthy',lambda *a:None)]:
                stack.enter_context(patch.object(i,name,replace))
            stack.enter_context(patch.object(p.os,'chown',create=True))
            stack.enter_context(patch.object(p,'grp',types.SimpleNamespace(getgrnam=lambda u:types.SimpleNamespace(gr_gid=0))))
            stack.enter_context(patch.object(p,'backup',return_value=str(root/'backup')))
            stack.enter_context(patch.object(p,'user_exists',return_value=False))
            stack.enter_context(patch.object(p,'add_user',side_effect=lambda u,h:h.mkdir()))
            stack.enter_context(patch.object(p,'run',side_effect=command))
            stack.enter_context(patch.object(i,'first_snapshot',side_effect=RuntimeError('SSH test failed') if fail else None))
            if fail:
                with self.assertRaises(RuntimeError):i.install()
                self.assertFalse(p.APP.exists());self.assertFalse(p.ETC.exists());self.assertFalse(p.STATE.exists())
                self.assertIn('remove',calls)
            else:
                i.install()
                runtime=json.loads((p.ETC/'config.json').read_text())
                self.assertEqual(runtime['port'],2443);self.assertEqual(runtime['max_ttl'],420)
                self.assertIn('198.51.100.10/32',runtime['excluded'])
                self.assertTrue(p.UNIT.exists())
                self.assertEqual(calls.count('install'),1)
                self.assertIn('StrictHostKeyChecking yes',(p.ETC/'ssh_config').read_text())
                self.assertNotIn('PRIVATE-TEST',(p.APP/'install.json').read_text())
                # Repeated install checks health and does not reconfigure/delete.
                i.install();self.assertEqual(calls.count('install'),1)
        self.assertEqual(calls[-1],'close')

    def test_install_and_idempotent_rerun(self):self.scenario()
    def test_failed_transport_rolls_back(self):self.scenario(fail=True)

if __name__=='__main__':unittest.main()
