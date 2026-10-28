import hashlib, socket, tempfile, threading, unittest
from pathlib import Path
from firebox.modules import network, password_tools, log_analyzer, integrity, vulns

class Tests(unittest.TestCase):
    def test_password_hash_and_strength(self):
        p=password_tools.generate_password(20); self.assertEqual(len(p),20); self.assertGreaterEqual(password_tools.strength(p)['score'],3)
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'abc'); f.flush(); self.assertEqual(password_tools.sha256_file(f.name),hashlib.sha256(b'abc').hexdigest())
    def test_local_port_scan(self):
        s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); port=s.getsockname()[1]
        try: self.assertTrue(network.check_port('127.0.0.1',port).open)
        finally: s.close()
    def test_log_analyzer(self):
        with tempfile.NamedTemporaryFile(mode='w',delete=False) as f:
            for _ in range(5): f.write('Oct 28 10:00:00 host sshd: Failed password for root from 192.0.2.1 port 22 ssh2\n')
            f.write('Oct 28 10:05:00 host sshd: Accepted publickey for root from 192.0.2.1 port 22 ssh2\n'); name=f.name
        self.assertEqual(log_analyzer.analyze(name,5)['suspicious_sources'][0]['ip'],'192.0.2.1')
    def test_integrity(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'a'; p.write_text('one'); b=Path(d)/'b.json'; integrity.create_baseline(d,str(b)); p.write_text('two'); r=integrity.compare(d,str(b)); self.assertIn('a',r['modified'])
    def test_vulnerability_db(self):
        with tempfile.TemporaryDirectory() as d:
            db=vulns.VulnerabilityDB(str(Path(d)/'x.db')); i=db.add('TLS','medium','host','evidence','fix'); self.assertEqual(i,1); self.assertEqual(len(db.list()),1)

if __name__=='__main__': unittest.main()
