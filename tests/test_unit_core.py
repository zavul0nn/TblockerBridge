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
from unittest.mock import patch, Mock

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

class SocketCloseTests(unittest.TestCase):
    def test_exact_frontend_and_peer_no_shell(self):
        command=t.client_socket_command('8.8.8.8',2443,kill=True)
        self.assertEqual(command[0],'/usr/bin/ss')
        self.assertIn('-K',command)
        self.assertIn('sport = :2443',command[-1])
        self.assertIn('dst = 8.8.8.8/32',command[-1])
        self.assertIn('dst = [::ffff:8.8.8.8]',command[-1])
        self.assertNotIn('dport',command[-1])
        for ip,port in [('8.8.8.8; reboot',2443),('8.8.8.8/24',2443),('8.8.8.8',22)]:
            with self.assertRaises(ValueError):t.client_socket_command(ip,port,True)

    def test_close_verifies_kernel_did_not_silently_skip(self):
        replies=[subprocess.CompletedProcess([],0,stdout='',stderr=''),
                 subprocess.CompletedProcess([],0,stdout='ESTAB client still present',stderr='')]
        with patch.object(t.subprocess,'run',side_effect=replies):
            with self.assertRaises(RuntimeError):t.close_client_sockets('8.8.8.8',2443)

    def test_drop_committed_before_close_and_duplicate_snapshot_no_reclose(self):
        order=[];until=time.time()+30
        firewall=Mock(port=2443)
        firewall.apply.side_effect=lambda blocks:order.append('drop') or set(blocks)
        with patch.object(t,'close_client_sockets',side_effect=lambda *args:order.append('close') or 1):
            enforcer=t.BanEnforcer(firewall)
            enforcer.apply({'8.8.8.8':until})
            enforcer.apply({'8.8.8.8':until+1})
        self.assertEqual(order,['drop','close','drop'])

    def test_firewall_failure_never_closes_sockets(self):
        firewall=Mock(port=2443);firewall.apply.side_effect=RuntimeError('nft failed')
        with patch.object(t,'close_client_sockets') as close:
            with self.assertRaises(RuntimeError):t.BanEnforcer(firewall).apply({'8.8.8.8':time.time()+30})
            close.assert_not_called()

    def test_close_failure_retry_keeps_drop_and_stops_after_unban(self):
        firewall=Mock(port=2443);firewall.apply.side_effect=lambda blocks:set(blocks)
        with patch.object(t,'close_client_sockets',side_effect=[OSError('denied'),1]) as close:
            enforcer=t.BanEnforcer(firewall)
            enforcer.apply({'8.8.8.8':time.time()+30})
            self.assertNotIn('8.8.8.8',enforcer.closed)
            enforcer.retry();self.assertIn('8.8.8.8',enforcer.closed)
            enforcer.apply({});enforcer.retry()
            self.assertEqual(close.call_count,2)

    def test_reban_after_offline_expiration_closes_new_socket(self):
        firewall=Mock(port=2443);firewall.apply.side_effect=lambda blocks:set(blocks)
        enforcer=t.BanEnforcer(firewall)
        enforcer.closed={'8.8.8.8':time.time()-1}
        with patch.object(t,'close_client_sockets',return_value=1) as close:
            enforcer.apply({'8.8.8.8':time.time()+30})
            close.assert_called_once_with('8.8.8.8',2443)

    def test_opt_out_still_applies_drop(self):
        firewall=Mock(port=2443);firewall.apply.return_value={'8.8.8.8'}
        with patch.object(t,'close_client_sockets') as close:
            t.BanEnforcer(firewall,close_connections=False).apply({'8.8.8.8':time.time()+30})
            firewall.apply.assert_called_once();close.assert_not_called()

if __name__=='__main__':unittest.main()
