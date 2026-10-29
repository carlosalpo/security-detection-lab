"""Verify public evidence bytes, nested replay manifests and factual claims."""
from pathlib import Path
import hashlib
import json
import re
import sys

root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
preseal = '--preseal' in sys.argv

def read(p): return json.loads((root / p).read_text())
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def info(p): return dict(bytes=p.stat().st_size, sha256=sha(p))
def jpeg_size(p):
    b = p.read_bytes()
    assert b[:2] == b'\xff\xd8', p
    i = 2
    while i < len(b):
        assert b[i] == 255
        while b[i] == 255: i += 1
        marker = b[i]; i += 1
        if marker in [0x01, 0xd8, 0xd9] or 0xd0 <= marker <= 0xd7: continue
        n = int.from_bytes(b[i:i+2], 'big')
        if marker in [0xc0,0xc1,0xc2]:
            return int.from_bytes(b[i+5:i+7], 'big'), int.from_bytes(b[i+3:i+5], 'big')
        i += n
    raise ValueError('JPEG dimensions missing')

run = read('logs/run.json')
assert run['source_commit'] == 'dc31cf4c138123775185c41612e139082d383070'
for k in ['source_clean_before','source_clean_after','tracked_files_match_commit','tracked_files_unchanged','installed_python_files_match_commit']:
    assert run[k] is True
for file, digest in run['installed_python_sha256'].items():
    assert digest == run['source_sha256']['src/detectionlab/'+file]
assert all(c['exit_code'] == 0 for c in run['commands'])
assert '126 passed' in (root/'logs/pytest.stdout.log').read_text()
assert (root/'logs/ruff-check.stdout.log').read_text().strip() == 'All checks passed!'
assert (root/'logs/ruff-format.stdout.log').read_text().strip() == '8 files already formatted'
assert all(not p.read_bytes() for p in (root/'logs').glob('*.stderr.log'))

matrix = read('outputs/verification.json')
assert len(matrix) == 9
assert len({r['scenario'] for r in matrix}) == 9
nested_count = 0
for row in matrix:
    s = row['scenario']
    if s == 'conflicting-id':
        assert row['exit_code'] == 2
        assert row['output'] == 'Input error: Conflicting payloads share an event ID.'
        assert not (root/'outputs/invalid-output').exists()
        conflict = [json.loads(l) for l in (root/'outputs/conflicting-id.jsonl').read_text().splitlines()]
        assert len(conflict) == 2 and conflict[0]['id'] == conflict[1]['id'] and conflict[0] != conflict[1]
        continue
    assert row['exit_code'] == (1 if s == 'expectation-mismatch' else 0)
    pkg = root/'outputs'/s
    manifest = read(f'outputs/{s}/manifest.json')
    assert len(manifest['files']) == 8
    for file, details in manifest['files'].items():
        assert details == info(pkg/file), (s,file)
        nested_count += 1
    for key,file in [('events','events.jsonl'),('rules','rules.json'),('expected','expected.json')]:
        src=root/'outputs'/(s+'-input')/file
        assert sha(src) == manifest['source_sha256'][key]
        assert sha(src) == run['source_sha256'][f'examples/{s}/{file}']
    r=read(f'outputs/{s}/replay.json')
    assert r['evaluation'] == read(f'outputs/{s}/evaluation.json')
    assert r['evaluation']['status'] == ('failed' if s == 'expectation-mismatch' else 'passed')
    assert len(r['alerts']) == (0 if s == 'benign' else 1)
    ids={json.loads(l)['id'] for l in (pkg/'events.jsonl').read_text().splitlines()}
    for a in r['alerts']:
        assert a['trigger_id'] in ids and set(a['evidence_ids']) <= ids

auth=read('outputs/auth-burst/replay.json')
a=auth['alerts'][0]
assert a['trigger_id']=='fail-5' and a['evidence_ids']==[f'fail-{i}' for i in range(1,6)]
assert (a['threshold'],a['window_seconds']) == (5,300)
m=next(x for x in auth['rules'] if x['rule_id']=='auth-failure-burst')
assert (m['matched_events'],m['qualifying_triggers'],m['emitted_alerts'],m['suppressed_triggers']) == (6,2,1,1)
deny=read('outputs/denied-ports/replay.json')['alerts'][0]
assert (deny['metric'],deny['value'],deny['window_seconds'],deny['trigger_id']) == ('distinct_ports',5,60,'deny-5')
ports={json.loads(l)['dst_port'] for l in (root/'outputs/denied-ports/events.jsonl').read_text().splitlines()}
assert ports == {22,80,443,445,3389}
w=read('outputs/window-boundary/replay.json')['alerts'][0]
assert w['evidence_ids']==['edge-first','edge-inclusive']
assert (w['threshold'],w['window_seconds'],w['window_start'],w['timestamp']) == (2,300,'2026-10-29T12:00:00Z','2026-10-29T12:05:00Z')
d=read('outputs/duplicate-replay/replay.json')
assert d['counts']==dict(input_records=7,unique_events=6,duplicates_removed=1) and len(d['alerts'])==1
source=[json.loads(l) for l in (root/'outputs/duplicate-replay-input/events.jsonl').read_text().splitlines()]
assert len([x for x in source if x['id']=='fail-6'])==2
assert source[0]==source[-1]
e=read('outputs/expectation-mismatch/evaluation.json')
assert (e['expected_alerts'],e['actual_alerts'],e['status']) == (0,1,'failed')

pages=read('provenance/pages.json')
assert len(pages)==5
maps=read('provenance/page-sources.json')
assert len(maps['05-verification']['additional_dependencies']) == 8
for p in pages:
    slug=p['id']
    width,height=jpeg_size(root/'images'/(slug+'.jpg'))
    assert width == 1280 and height > 720
    content=(root/'viewer'/(slug+'.html')).read_text()
    assert 'EVIDENCE VIEWER' in content and 'Not product UI' in content and 'dc31cf4c1381' in content
    for dep in maps[slug]['sources']+maps[slug].get('additional_dependencies',[]):
        assert (root/dep).is_file(), dep
    for link in re.findall(r'href="([^"#]+)"',content):
        if not link.startswith('http'):
            assert (root/'viewer'/link).resolve().is_file(), link
for f in (root/'provenance/source').rglob('*'):
    if f.is_file(): assert sha(f)==run['source_sha256'][f.relative_to(root/'provenance/source').as_posix()]

# Targeted privacy scan, plus manual review of synthetic inputs and screenshots.
# These checks are not a general secret detection guarantee.
patterns=['/'+'Users/', '/'+'home/', '/'+'private/', 'MacBook'+'-Pro', 'BEGIN '+'PRIVATE KEY', 'github_'+'pat_', 'gh'+'p_']
for f in root.rglob('*'):
    assert not f.is_symlink(), f
    if f.is_file() and f.suffix.lower() not in ['.jpg','.png']:
        content=f.read_text()
        assert not any(p in content for p in patterns), f

report=dict(schema_version=1,status='passed',source_commit=run['source_commit'],nested_replay_packages=8,nested_artifact_hashes_checked=nested_count,original_fixture_files_checked=24,cli_scenarios=9,pytest_passed=126,screenshots=5,installed_python_files_match_commit=True,source_provenance_checks='recorded checks from independent run plus internal hash consistency',conflicting_id_has_no_output=True,privacy_scan='targeted personal-path, hostname and credential patterns; no matches',screenshot_validation='JPEG signature/dimensions and human visual review; originals captured with CUA')
if preseal:
    (root/'logs/package-verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
else:
    manifest=read('manifest.json')
    actual={p.relative_to(root).as_posix():info(p) for p in sorted(root.rglob('*')) if p.is_file() and p.name not in [] and p.relative_to(root).as_posix() not in ['manifest.json','SHA256SUMS']}
    assert manifest['files']==actual
    sums={}
    for line in (root/'SHA256SUMS').read_text().splitlines():
        digest,name=line.split('  ',1)
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        assert sha(root/name)==digest, name
        sums[name]=digest
    files={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}-{'SHA256SUMS'}
    assert set(sums)==files
    for c in manifest['captures']:
        assert sha(root/c['image'])==c['sha256']
        for dep in c['sources']:
            assert sha(root/dep['path'])==dep['sha256']
    print(f"PASS: {len(sums)} SHA256SUMS entries; {len(actual)} manifest files; 8 replay manifests; 24 original fixtures; 5 captures; 9 CLI scenarios; 126 tests.")
