"""Run ONLY with unshare --net. No production nftables or source data touched."""
import datetime as dt
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import sys
import shutil
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import tblockerbridge as t

IP = '192.0.2.10'
def nft_json():
    return subprocess.check_output(['nft', '-j', 'list', 'table', 'inet', 'tbsync_test'], text=True)

class MirrorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
            raise RuntimeError('Tests require isolated network namespace')
        subprocess.run(['ip','link','set','lo','up'],check=True)
        for ip in [IP, '192.0.2.11']:
            subprocess.run(['ip','address','add',ip+'/32','dev','lo'],check=True)
        cls.fw=t.Firewall('tbsync_test',allow_test=True)
        cls.fw.apply({})

    def setUp(self):
        subprocess.run(['nft','delete','table','inet','tbsync_test'],check=True)
        self.fw=t.Firewall('tbsync_test',allow_test=True)
        self.fw.apply({})

    def custom_firewall(self,port):
        subprocess.run(['nft','delete','table','inet','tbsync_test'],check=True)
        return t.Firewall('tbsync_test',allow_test=True,port=port)

    def tearDown(self):
        self.fw.apply({})

    def test_source_format_and_partial_write(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'state.json'
            p.write_text(json.dumps({IP:{'ip':IP,'username':'test','blocked_until':'2026-10-28T12:00:00.123456789+02:00'}}))
            self.assertAlmostEqual(t.stable_read(p)[IP],dt.datetime(2026,10,28,10,tzinfo=dt.timezone.utc).timestamp()+.123457,places=5)
            for raw in ['', '{', 'null', '[]', '{"a":1,"a":2}']:
                p.write_text(raw)
                with self.assertRaises((ValueError,TypeError)):
                    t.stable_read(p)

    def test_validation(self):
        now=time.time()
        self.assertEqual(t.validate_blocks({'127.0.0.1':now+10,'8.8.8.8':now+10},now,['8.8.8.8/32']),{})
        for blocks in [{'1.1.1.1; drop':now+2},{'::1':now+2},{'1.1.1.1':float('nan')},{'1.1.1.1':now+99999}]:
            with self.assertRaises(ValueError): t.validate_blocks(blocks,now,[])
        for generated in [now-60,now+60,float('nan')]:
            with self.assertRaises(ValueError): t.snapshot(json.dumps({'version':1,'generated':generated,'blocks':{}}),[])

    def test_add_repeat_extend_remove_expire(self):
        expiry=time.time()+1
        self.fw.apply({IP:expiry})
        self.assertIn(IP,nft_json())
        self.fw.apply({IP:expiry})
        self.fw.apply({IP:time.time()+2})
        time.sleep(1.1)
        self.assertIn(IP,nft_json())
        self.fw.apply({})
        self.assertNotIn(IP,nft_json())
        self.fw.apply({IP:time.time()+.5})
        time.sleep(.8)
        self.assertNotIn(IP,nft_json())

    def test_offline_ttl_and_cache_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'cache.json'
            blocks={IP:time.time()+1.5}
            t.atomic_json(p,blocks)
            self.fw.apply(blocks)
            time.sleep(.3)
            recovered=t.validate_blocks(t.decode(p.read_bytes()),time.time(),[],allow_test=True)
            self.fw.apply(recovered)
            time.sleep(1.5)
            self.assertNotIn(IP,nft_json())
            self.assertEqual(t.validate_blocks(t.decode(p.read_bytes()),time.time(),[],allow_test=True),{})

    def test_drop_established_preserve_others_and_ports(self):
        listeners=[]
        workers=[]
        def echo(conn):
            with conn:
                try:
                    while data:=conn.recv(100): conn.sendall(data)
                except OSError: pass
        def serve(server):
            while True:
                try: conn,_=server.accept()
                except socket.timeout:continue
                except OSError: break
                threading.Thread(target=echo,args=(conn,),daemon=True).start()
        for port in [2053,22,2054]:
            s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.bind(('127.0.0.1',port)); s.listen();s.settimeout(.1); listeners.append(s)
            worker=threading.Thread(target=serve,args=(s,),daemon=True);worker.start();workers.append(worker)
        def client(ip,port):
            s=socket.socket(); s.settimeout(.4); s.bind((ip,0))
            try: s.connect(('127.0.0.1',port)); return s
            except OSError: s.close(); raise
        def ping(s):
            s.sendall(b'x'); self.assertEqual(s.recv(1),b'x')
        clients=[]
        try:
            victim=client(IP,2053); clients.append(victim); ping(victim)
            self.fw.apply({IP:time.time()+5})
            with self.assertRaises(socket.timeout): ping(victim)
            for ip,port in [('192.0.2.11',2053),(IP,22),(IP,2054)]:
                s=client(ip,port); clients.append(s); ping(s)
            with self.assertRaises(socket.timeout):
                s=client(IP,2053); clients.append(s)
            self.fw.apply({})
            s=client(IP,2053); clients.append(s); ping(s)
        finally:
            for s in clients+listeners: s.close()
            for worker in workers:worker.join(timeout=1)

    def test_socket_destroy_dual_stack_with_only_net_admin(self):
        server=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
        server.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)
        server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        server.bind(('::',2445));server.listen(2)
        clients=[];accepted=[]
        try:
            for ip in [IP,'192.0.2.11']:
                c=socket.socket();c.bind((ip,0));c.connect(('127.0.0.1',2445));c.settimeout(1);clients.append(c)
                a,_=server.accept();accepted.append(a)
            command=t.client_socket_command(IP,2445)
            self.assertTrue(subprocess.check_output(command,text=True).strip())
            real_run=subprocess.run
            def limited(args,**kwargs):
                if args[0]=='/usr/bin/ss':
                    args=['setpriv','--reuid=65534','--regid=65534','--clear-groups',
                          '--inh-caps=+net_admin','--ambient-caps=+net_admin',
                          '--bounding-set=-all,+net_admin',*args]
                return real_run(args,**kwargs)
            with patch.object(t.subprocess,'run',side_effect=limited):
                enforcer=t.BanEnforcer(self.custom_firewall(2445))
                enforcer.apply({IP:time.time()+5})
            self.assertIn(IP,enforcer.closed)
            self.assertFalse(subprocess.check_output(command,text=True).strip())
            accepted[1].sendall(b'alive');self.assertEqual(clients[1].recv(5),b'alive')
            self.assertTrue(subprocess.check_output(t.client_socket_command('192.0.2.11',2445),text=True).strip())
            closed=False
            try:
                clients[0].sendall(b'x');closed=not clients[0].recv(1)
            except (ConnectionResetError,ConnectionAbortedError,BrokenPipeError):closed=True
            self.assertTrue(closed)
        finally:
            for s in clients+accepted+[server]:s.close()

    def test_haproxy_active_download_frontend_and_backend_close(self):
        if not shutil.which('haproxy'):self.fail('haproxy required for real proxy test')
        backend=socket.socket();backend.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        backend.bind(('127.0.0.1',8443));backend.listen();backend.settimeout(.1)
        stop=threading.Event();ready={name:threading.Event() for name in ['victim','control']}
        ended={name:threading.Event() for name in ['victim','control']}
        def stream(conn):
            name=None
            with conn:
                try:
                    name=conn.recv(100).decode().strip()
                    if name not in ready:return
                    ready[name].set()
                    while not stop.is_set():
                        conn.sendall(b'x'*16384);time.sleep(.003)
                except OSError:pass
                finally:
                    if name in ended:ended[name].set()
        def serve():
            while not stop.is_set():
                try:conn,_=backend.accept()
                except socket.timeout:continue
                except OSError:break
                threading.Thread(target=stream,args=(conn,),daemon=True).start()
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        clients=[];proxy=None
        try:
            with tempfile.TemporaryDirectory() as directory:
                cfg=Path(directory)/'haproxy.cfg'
                cfg.write_text('global\n    maxconn 32\ndefaults\n    mode tcp\n    timeout connect 2s\n    timeout client 30s\n    timeout server 30s\nfrontend isolated\n    bind 127.0.0.1:2443\n    default_backend download\nbackend download\n    server origin 127.0.0.1:8443\n')
                proxy=subprocess.Popen(['haproxy','-db','-f',str(cfg)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                deadline=time.monotonic()+3
                while not subprocess.check_output(['ss','-H','-ltn','sport = :2443'],text=True).strip():
                    if proxy.poll() is not None:raise RuntimeError(proxy.stderr.read().decode())
                    if time.monotonic()>deadline:raise RuntimeError('test HAProxy did not start')
                    time.sleep(.05)
                for ip,name in [(IP,'victim'),('192.0.2.11','control')]:
                    c=socket.socket();c.settimeout(1);c.bind((ip,0));c.connect(('127.0.0.1',2443));c.sendall((name+'\n').encode());clients.append(c)
                    self.assertTrue(ready[name].wait(1));self.assertTrue(c.recv(4096))
                enforcer=t.BanEnforcer(self.custom_firewall(2443))
                started=time.monotonic();enforcer.apply({IP:time.time()+5})
                self.assertIn(IP,enforcer.closed)
                self.assertFalse(subprocess.check_output(t.client_socket_command(IP,2443),text=True).strip())
                closed=False;deadline=time.monotonic()+2
                while time.monotonic()<deadline:
                    try:
                        if not clients[0].recv(65536):closed=True;break
                    except (ConnectionResetError,ConnectionAbortedError):closed=True;break
                self.assertTrue(closed,'active downloading client did not observe TCP closure')
                self.assertTrue(ended['victim'].wait(2),'HAProxy did not close victim backend')
                self.assertFalse(ended['control'].is_set())
                self.assertTrue(clients[1].recv(4096),'other client download was interrupted')
                self.assertTrue(subprocess.check_output(['ss','-H','-ltn','sport = :2443'],text=True).strip())
                print('Active download terminated (frontend + backend), seconds:',round(time.monotonic()-started,3))
        finally:
            stop.set()
            for s in clients+[backend]:s.close()
            if proxy:
                proxy.terminate()
                try:proxy.communicate(timeout=3)
                except subprocess.TimeoutExpired:proxy.kill();proxy.communicate()
            thread.join(timeout=1)

if __name__=='__main__': unittest.main(verbosity=2)
