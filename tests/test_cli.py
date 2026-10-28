"""End-to-end CLI contract tests; Python is only a test driver."""
import datetime as dt
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

EXE = str(Path(sys.argv.pop(1)).resolve())
STAMP = '28/Oct/2026:00:00:00 +0000'

def line(path='/health', status=200, size=10, stamp=STAMP, tail=''):
    return f'192.0.2.10 - - [{stamp}] "GET {path} HTTP/1.1" {status} {size}{tail}\n'.encode()

class CLI(unittest.TestCase):
    def run_cli(self, data=b'', *flags):
        return subprocess.run([EXE, '--json', *flags, '-'], input=data, capture_output=True, timeout=15)

    def report(self, data, *flags):
        result=self.run_cli(data,*flags)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        return json.loads(result.stdout)

    def test_empty(self):
        r=self.report(b'');self.assertEqual(r['requests'],0);self.assertIsNone(r['first_unix']);self.assertEqual(r['top_paths'],[])
    def test_common_and_combined(self):
        r=self.report(line()+line('/api',503,'-',tail=' "https://example.test/" "Agent/1"'))
        self.assertEqual((r['requests'],r['server_errors'],r['bytes'],r['unknown_size_requests']),(2,1,10,1))
    def test_query_fragment_removed(self):
        r=self.report(line('/login?token=SECRET')+line('/login#SECRET'))
        self.assertEqual(r['distinct_paths'],1);self.assertNotIn('SECRET',json.dumps(r))
    def test_timezone(self):
        r=self.report(line(stamp='28/Oct/2026:07:00:00 +0700'))
        self.assertEqual(r['first_unix'],int(dt.datetime(2026,10,28,tzinfo=dt.timezone.utc).timestamp()))
    def test_half_open_time_window(self):
        r=self.report(line(stamp='28/Oct/2026:00:00:00 +0000')+line(stamp='28/Oct/2026:01:00:00 +0000'), '--since','2026-10-28T00:00:00Z','--until','2026-10-28T01:00:00Z')
        self.assertEqual((r['requests'],r['filtered']),(1,1))
    def test_unsorted_input_range(self):
        r=self.report(line(stamp='28/Oct/2026:01:00:00 +0000')+line())
        self.assertEqual(r['last_unix']-r['first_unix'],3600)
    def test_no_final_newline(self):
        self.assertEqual(self.report(line().rstrip(b'\n'))['requests'],1)
    def test_crlf(self):
        self.assertEqual(self.report(line().replace(b'\n',b'\r\n'))['requests'],1)
    def test_invalid_skip(self):
        r=self.report(b'bad\n'+line());self.assertEqual((r['lines'],r['invalid'],r['requests']),(2,1,1))
    def test_strict_no_partial_report(self):
        r=self.run_cli(line()+b'bad\n','--strict');self.assertEqual(r.returncode,2);self.assertEqual(r.stdout,b'')
    def test_nul_is_not_a_truncated_valid_line(self):
        r=self.report(line().rstrip(b'\n')+b'\0junk\n'+line());self.assertEqual((r['requests'],r['binary']),(1,1))
    def test_long_line_is_drained(self):
        r=self.report(b'x'*100000+b'\n'+line());self.assertEqual((r['lines'],r['overlong'],r['requests']),(2,1,1))
    def test_exact_line_limit(self):
        base=line(tail=' "-" ""').rstrip(b'\n');n=8192-len(base)
        exact=base[:-1]+b'a'*n+b'"'
        for end in (b'\n',b'\r\n',b''):
            self.assertEqual(self.report(exact+end)['requests'],1)
        self.assertEqual(self.report(exact+b'x\n')['overlong'],1)
    def test_numeric_overflow_parse(self):
        self.assertEqual(self.report(line(size=2**64))['invalid'],1)
    def test_max_uint64(self):
        self.assertEqual(self.report(line(size=2**64-1))['bytes'],2**64-1)
    def test_aggregate_overflow_is_fatal(self):
        r=self.run_cli(line(size=2**64-1)+line());self.assertEqual(r.returncode,3);self.assertEqual(r.stdout,b'')
    def test_distinct_limit_is_fatal(self):
        r=self.run_cli(line('/a')+line('/b'),'--max-paths','1');self.assertEqual(r.returncode,3);self.assertEqual(r.stdout,b'')
    def test_filtered_paths_do_not_use_capacity(self):
        r=self.report(line('/old',stamp='27/Oct/2026:00:00:00 +0000')+line('/new'),'--since','2026-10-28T00:00:00Z','--max-paths','1');self.assertEqual(r['distinct_paths'],1)
    def test_tie_break_and_top(self):
        r=self.report(line('/z')+line('/a')+line('/m'),'--top','2');self.assertEqual([x['path'] for x in r['top_paths']],['/a','/m'])
    def test_fail_on_5xx(self):
        r=self.run_cli(line(status=500),'--fail-on-5xx');self.assertEqual(r.returncode,1);self.assertEqual(json.loads(r.stdout)['server_errors'],1)
    def test_filtered_5xx_does_not_trigger(self):
        r=self.run_cli(line(status=500),'--fail-on-5xx','--since','2026-10-29T00:00:00Z');self.assertEqual(r.returncode,0)
    def test_invalid_dates(self):
        for stamp in ['31/Feb/2026:00:00:00 +0000','29/Feb/2100:00:00:00 +0000','01/Jan/2026:25:00:00 +0000','01/Jan/2026:00:00:00 +0060']:
            with self.subTest(stamp=stamp):self.assertEqual(self.report(line(stamp=stamp))['invalid'],1)
    def test_status_range(self):
        r=self.report(line(status=100)+line(status=599)+line(status=600)+line(status=99));self.assertEqual((r['requests'],r['invalid']),(2,2))
    def test_escaped_quotes_and_json(self):
        r=self.report(line('/a\\"b',tail=' "-" "Agent \\"quoted\\""'))
        self.assertEqual(r['top_paths'][0]['path'],'/a\\"b')
    def test_terminal_escape_rejected(self):
        self.assertEqual(self.report(line('/a\x1bb'))['invalid'],1)
    def test_raw_high_bytes_are_json_escaped(self):
        r=self.report(line('/a').replace(b'/a ',b'/\xff '));self.assertEqual(r['top_paths'][0]['path'],'/\u00ff')
    def test_missing_request_marker(self):
        r=self.report(line().replace(b'GET /health HTTP/1.1',b'-'));self.assertEqual(r['top_paths'][0]['path'],'-')
    def test_path_limit(self):
        self.assertEqual(self.report(line('/'+'a'*2047))['requests'],1)
        self.assertEqual(self.report(line('/'+'a'*2048))['invalid'],1)
    def test_multiple_files_and_missing_file(self):
        with tempfile.TemporaryDirectory() as t:
            a=Path(t)/'a.txt';b=Path(t)/'b.txt';a.write_bytes(line());b.write_bytes(line(status=503))
            r=subprocess.run([EXE,'--json',str(a),str(b)],capture_output=True,timeout=15);self.assertEqual(json.loads(r.stdout)['requests'],2)
            r=subprocess.run([EXE,'--json',str(a),str(Path(t)/'missing')],capture_output=True,timeout=15);self.assertEqual(r.returncode,3);self.assertEqual(r.stdout,b'')
    def test_invalid_arguments(self):
        for args in [[],['--top','0','-'],['--top','101','-'],['--max-paths','100001','-'],['--top','-1','-'],['--top','99999999999999999999','-'],['--json','--json','-'],['-','-'],['--bogus','-'],['--since','2026-99-01T00:00:00Z','-'],['--since','2026-10-29T00:00:00Z','--until','2026-10-28T00:00:00Z','-']]:
            with self.subTest(args=args):self.assertEqual(subprocess.run([EXE,*args],input=b'',capture_output=True,timeout=15).returncode,2)
    def test_end_of_options(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t)/'--json').write_bytes(line());r=subprocess.run([EXE,'--json','--','--json'],cwd=t,capture_output=True,timeout=15);self.assertEqual(json.loads(r.stdout)['requests'],1)
    def test_text_output(self):
        r=subprocess.run([EXE,'-'],input=line(),capture_output=True,timeout=15);self.assertEqual(r.returncode,0);self.assertIn(b'PATH (query removed)',r.stdout)
    def test_version_help(self):
        for flag in ['--help','--version']:
            self.assertEqual(subprocess.run([EXE,flag],capture_output=True,timeout=15).returncode,0)
    @unittest.skipUnless(os.path.exists('/dev/full'),'POSIX /dev/full only')
    def test_output_error(self):
        with open('/dev/full','wb') as out:
            r=subprocess.run([EXE,'--json','-'],input=line(),stdout=out,stderr=subprocess.PIPE,timeout=15);self.assertEqual(r.returncode,3)
    def test_differential_random_dataset(self):
        rng=random.Random(71028);data=[];expected={};statuses={};total=0;errors=0
        for _ in range(3000):
            path=f'/route/{rng.randrange(50)}';status=rng.choice([200,201,301,404,500,503]);size=rng.randrange(100000)
            data.append(line(path+'?secret=value',status,size));total+=size;errors+=status>=500;statuses[str(status)]=statuses.get(str(status),0)+1
            record=expected.setdefault(path,{'path':path,'requests':0,'server_errors':0,'bytes':0});record['requests']+=1;record['server_errors']+=status>=500;record['bytes']+=size
        r=self.report(b''.join(data),'--top','100');self.assertEqual(r['bytes'],total);self.assertEqual(r['server_errors'],errors);self.assertEqual(r['statuses'],statuses);self.assertEqual(r['top_paths'],sorted(expected.values(),key=lambda p:(-p['requests'],p['path'])))

if __name__=='__main__':unittest.main(verbosity=2)
