import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import tblockerbridge as t

class StorageTests(unittest.TestCase):
    def test_fresh_source_no_file_then_first_violation(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'blocked_ips.json'
            self.assertEqual(t.stable_read(path),{})
            self.assertFalse(path.exists(),'reader must never create upstream storage')
            until=dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=5)
            path.write_text(json.dumps({'8.8.8.8':{'ip':'8.8.8.8','username':'example','blocked_until':until.isoformat()}}))
            self.assertAlmostEqual(t.stable_read(path)['8.8.8.8'],until.timestamp())

    def test_missing_directory_is_not_empty_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):t.stable_read(Path(directory)/'missing'/'file.json')

    def test_partial_json_is_not_empty_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'blocked_ips.json'
            for raw in ['', '{', 'null', '[]', '{"x":1,"x":2}']:
                path.write_text(raw)
                with self.assertRaises((ValueError,TypeError)):t.stable_read(path)
            path.write_text('{}')
            self.assertEqual(t.stable_read(path),{})

    def test_export_fresh_source_emits_empty_heartbeat(self):
        with tempfile.TemporaryDirectory() as directory:
            output=io.StringIO()
            with patch.object(t.subprocess,'run',return_value=subprocess.CompletedProcess([],0)),patch.object(t.time,'sleep',side_effect=StopIteration),contextlib.redirect_stdout(output):
                with self.assertRaises(StopIteration):t.export(str(Path(directory)/'blocked_ips.json'))
            self.assertEqual(json.loads(output.getvalue())['blocks'],{})

class ValidationTests(unittest.TestCase):
    def test_runtime_ttl_configurable(self):
        now=time.time()
        data={'version':1,'generated':now,'blocks':{'8.8.8.8':now+1200}}
        with self.assertRaises(ValueError):t.snapshot(json.dumps(data),[])
        self.assertIn('8.8.8.8',t.snapshot(json.dumps(data),[],max_ttl=1800))

    def test_reject_malicious_inputs(self):
        now=time.time()
        for blocks in [{'8.8.8.8;flush ruleset':now+2},{'::1':now+2},{'8.8.8.8':True},{'8.8.8.8':float('inf')}]:
            with self.subTest(blocks=blocks),self.assertRaises(ValueError):t.validate_blocks(blocks,now,[])
        for port in [22,0,65536,'2053']:
            with self.assertRaises(ValueError):t.Firewall(port=port)

    def test_privates_and_infrastructure_excluded(self):
        now=time.time()
        self.assertEqual(t.validate_blocks({x:now+5 for x in ['127.0.0.1','10.0.0.1','169.254.1.2','224.0.0.1','8.8.8.8']},now,['8.8.8.8/32']),{})

    def test_clock_skew_rejected(self):
        for generated in [time.time()-10,time.time()+10,float('nan')]:
            with self.assertRaises(ValueError):t.snapshot(json.dumps({'version':1,'generated':generated,'blocks':{}}),[])

class FirewallTests(unittest.TestCase):
    def test_atomic_port_scoped_batch_and_absolute_ttl(self):
        captured=[]
        def run(args,**kwargs):
            captured.append((args,kwargs));return subprocess.CompletedProcess(args,0,stdout='',stderr='')
        with patch.object(t.subprocess,'run',side_effect=run),patch.object(t.time,'time',return_value=1000):
            fw=t.Firewall(port=2443,max_ttl=1800)
            fw.apply({'8.8.8.8':1123})
            fw.apply({'8.8.8.8':1123})
        transactions=[kw['input'] for args,kw in captured if '-f' in args]
        self.assertEqual(len(transactions),2)
        self.assertTrue(all('timeout 123000ms' in data for data in transactions))
        self.assertTrue(all(data.startswith('flush set inet tblockerbridge blocked_v4\n') for data in transactions))
        self.assertTrue(all('flush ruleset' not in data and 'docker' not in data.lower() for data in transactions))

    def test_creation_uses_only_configured_port(self):
        captured=[]
        def run(args,**kwargs):
            if 'list' in args:return subprocess.CompletedProcess(args,1,stdout='',stderr=b'No such file or directory')
            captured.append(kwargs['input']);return subprocess.CompletedProcess(args,0,stdout='',stderr='')
        with patch.object(t.subprocess,'run',side_effect=run):t.Firewall(port=2443).apply({})
        self.assertIn('tcp dport 2443 ip saddr @blocked_v4 counter drop',captured[0])
        self.assertIn('priority -20',captured[0])
        self.assertIn('TblockerBridge managed',captured[0])

if __name__=='__main__':unittest.main()
