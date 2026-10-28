"""Generate synthetic input, check totals, and report elapsed scan time (not peak RSS)."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument("executable", type=Path)
parser.add_argument("--lines", type=int, default=1000000)
args = parser.parse_args()
if args.lines < 1:
    parser.error("--lines must be positive")
with tempfile.TemporaryDirectory() as directory:
    source = Path(directory) / "access.txt"
    with source.open("wb") as output:
        for i in range(args.lines):
            status = 503 if i % 100 == 0 else 200
            output.write(f'192.0.2.1 - - [28/Oct/2026:00:00:00 +0000] "GET /api/{i % 100}?q=demo HTTP/1.1" {status} 100\n'.encode())
    start = time.perf_counter()
    result = subprocess.run([str(args.executable.resolve()), "--json", str(source)], capture_output=True, check=True, timeout=300)
    elapsed = time.perf_counter() - start
    report = json.loads(result.stdout)
    assert report["requests"] == args.lines
    assert report["bytes"] == args.lines * 100
    assert report["server_errors"] == (args.lines + 99) // 100
    assert report["distinct_paths"] == min(args.lines, 100)
    print(json.dumps({"lines": args.lines, "input_bytes": source.stat().st_size, "scan_seconds": round(elapsed, 3), "lines_per_second": round(args.lines / elapsed), "verified_totals": True}, indent=2))
