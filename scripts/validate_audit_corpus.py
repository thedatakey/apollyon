#!/usr/bin/env python3
"""Gate labeled synthetic behavior and pinned upstream negative samples; never execute fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[1]
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    for item in json.loads((ROOT/'benchmarks/upstream/manifest.json').read_text()):
        assert hashlib.sha256((ROOT/item['local_path']).read_bytes()).hexdigest() == item['sha256'], item['local_path']
    results = {}
    with tempfile.TemporaryDirectory(prefix='apollyon-corpus-') as directory:
        root = Path(directory)
        for index, item in enumerate(json.loads((ROOT/'benchmarks/audit-corpus.json').read_text())):
            fixture = root/f"case{index}.{item['extension']}"
            fixture.write_text(item['source'])
            scan = subprocess.run([str(binary),'scan',str(fixture),'--json','--only',item['rule'],'--no-auto-baseline'], capture_output=True, timeout=15, check=True)
            report = json.loads(scan.stdout)
            assert report['summary']['complete'], item
            found = bool(report['findings'])
            counts = results.setdefault(item['rule'], dict(tp=0,fp=0,tn=0,fn=0))
            counts[('tp' if found else 'fn') if item['label']=='positive' else ('fp' if found else 'tn')] += 1
    for counts in results.values():
        counts['precision'] = counts['tp']/(counts['tp']+counts['fp']) if counts['tp']+counts['fp'] else None
        counts['recall'] = counts['tp']/(counts['tp']+counts['fn'])
    upstream = subprocess.run([str(binary),'scan',str(ROOT/'benchmarks/upstream'),'--json','--only','APO007,APO012','--no-auto-baseline'],capture_output=True,timeout=30,check=True)
    report=json.loads(upstream.stdout)
    assert report['summary']['complete'] and not report['findings'], 'upstream negative corpus regression'
    output = dict(scope='44 synthetic labeled cases; three pinned upstream source-file negative samples for APO007/APO012. These are regression measurements, not estimated production precision.', rules=results, upstream_findings=0)
    if args.output: args.output.write_text(json.dumps(output,indent=2)+'\n')
    failures={rule:counts for rule,counts in results.items() if counts['fp'] or counts['fn']}
    if failures: raise SystemExit(json.dumps(failures,indent=2))
    print(f'Passed {len(results)} rule pairs and pinned upstream negative samples')
if __name__ == '__main__': main()
