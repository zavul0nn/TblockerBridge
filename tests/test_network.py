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
        def echo(conn):
            with conn:
                try:
                    while data:=conn.recv(100): conn.sendall(data)
                except OSError: pass
        def serve(server):
            while True:
                try: conn,_=server.accept()
                except OSError: break
                threading.Thread(target=echo,args=(conn,),daemon=True).start()
        for port in [2053,22,2054]:
            s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.bind(('127.0.0.1',port)); s.listen(); listeners.append(s)
            threading.Thread(target=serve,args=(s,),daemon=True).start()
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

if __name__=='__main__': unittest.main(verbosity=2)
