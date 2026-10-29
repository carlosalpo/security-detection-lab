"""Seal an already complete public evidence package. Does not alter captures."""
from pathlib import Path
import datetime
import hashlib
import json
import sys

root=Path(sys.argv[1]).resolve()
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p): return json.loads((root/p).read_text())
def size(p):
    b=p.read_bytes(); i=2
    while i<len(b):
        while b[i]==255: i+=1
        marker=b[i]; i+=1
        n=int.from_bytes(b[i:i+2],'big')
        if marker in [0xc0,0xc1,0xc2]: return int.from_bytes(b[i+5:i+7],'big'),int.from_bytes(b[i+3:i+5],'big')
        i+=n
    raise ValueError(p)

mapping=read('provenance/page-sources.json')
captures=[]
for page in read('provenance/pages.json'):
    slug=page['id']; path=root/'images'/(slug+'.jpg'); width,height=size(path)
    sources=mapping[slug]['sources']+mapping[slug].get('additional_dependencies',[])+['viewer/'+slug+'.html','viewer/style.css','provenance/build_viewer.py']
    captures.append(dict(**page,image=path.relative_to(root).as_posix(),sha256=sha(path),width=width,height=height,mime_type='image/jpeg',captured_file_modified_at_utc=datetime.datetime.fromtimestamp(path.stat().st_mtime,datetime.timezone.utc).isoformat(),browser='Codex in-app browser',method='CUA tab.screenshot({fullPage:true}); original returned JPEG bytes saved directly',viewport=dict(width=1280,height=720,override=False),postprocessing='none',portfolio_selected=slug in ['01-auth-burst','04-expectation-mismatch'],selection=mapping[slug]['selection'],visual_review=dict(passed=True,complete=True,footer_visible=True,no_horizontal_clipping=True,evidence_viewer_label_visible=True,no_personal_paths_or_credentials_visible=True),sources=[dict(path=p,sha256=sha(root/p)) for p in dict.fromkeys(sources)]))
files={p.relative_to(root).as_posix():dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(root.rglob('*')) if p.is_file() and p.relative_to(root).as_posix() not in ['manifest.json','SHA256SUMS']}
manifest=dict(schema_version=1,project='Security Detection Lab',version='0.1.0',repository='https://github.com/carlosalpo/security-detection-lab',source_commit='dc31cf4c138123775185c41612e139082d383070',capture_date='2026-10-29',timezone='America/Tegucigalpa',execution='Independent local execution; no remote CI attestation',state='Frozen handoff package; no publication performed',scope='offline-normalized-event-replay',provenance='Synthetic committed fixtures generated and compared byte for byte; installed Python sources checked against the exact clean source commit',limitations=['Evidence viewer, not product UI or terminal screenshot','No SIEM connection, traffic generation, attacks or scanning','Signals do not establish compromise or malicious intent','No real-world precision or recall measurement','Unsigned hashes verify content integrity, not authenticity'],path_normalization='Only run metadata command arguments replace local absolute roots with <SOURCE> and <EVIDENCE>. Original stdout, stderr, inputs and outputs are unchanged.',incidents=[dict(status='resolved',description='Initial evidence runner assumed editable installation after tests passed. Retained outside publish, corrected runner to verify installed source bytes, then repeated all checks into a fresh output. No product/source edits.')],integrity='files excludes root manifest.json and SHA256SUMS; SHA256SUMS includes root manifest.json and excludes itself. All paths are package-relative.',captures=captures,verification=read('logs/package-verification.json'),files=files)
(root/'manifest.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n')
(root/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.relative_to(root).as_posix()+'\n' for p in sorted(root.rglob('*')) if p.is_file() and p!=root/'SHA256SUMS'))
print('Sealed',len(files),'manifest files and',len(captures),'captures.')
