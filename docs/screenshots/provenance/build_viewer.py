"""Build a static evidence viewer from the retained real execution artifacts."""
from pathlib import Path
import hashlib
import html
import json
import sys

root = Path(sys.argv[1]).resolve()
viewer = root / 'viewer'
viewer.mkdir(exist_ok=True)
H = lambda s: html.escape(str(s))
def read(p): return json.loads((root / p).read_text())
def replay(s): return read(f'outputs/{s}/replay.json')
def events(s): return [json.loads(line) for line in (root / f'outputs/{s}/events.jsonl').read_text().splitlines()]
def digest(p): return hashlib.sha256((root / p).read_bytes()).hexdigest()
def table(head, rows):
    return '<table><thead><tr>' + ''.join('<th>'+H(c)+'</th>' for c in head) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>'+H(c)+'</td>' for c in row) + '</tr>' for row in rows) + '</tbody></table>'
def section(title, body): return '<section><h2>'+H(title)+'</h2>'+body+'</section>'
def pre(text): return '<pre>'+H(text)+'</pre>'
def note(text): return '<p class="note">'+H(text)+'</p>'
def kv(items): return table(['Campo / Field','Valor / Value'],items)
verification = read('outputs/verification.json')
checks = {x['scenario']:x for x in verification}
def cli(s): return section('Salida CLI literal / Literal CLI output', pre(checks[s]['output'])+f'<p class="exit">Exit code: <strong>{checks[s]["exit_code"]}</strong></p>')
page_sources={}
pages=[]
def page(slug, title, en, intro, body, sources, selection):
    n=len(pages)+1
    sources=list(dict.fromkeys(sources))
    sourcehtml='<div class="sources"><b>FUENTES / SOURCES · SHA-256 abreviado; valores completos en manifest.json</b><br>'+ '<br>'.join(f'<a href="../{H(p)}">{H(p)}</a> · {digest(p)[:16]}' for p in sources)+'</div>'
    text=f'''<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{H(title)} | Security Detection Lab</title><link rel="stylesheet" href="style.css"></head><body><main><header><h1>{H(title)}</h1><p class="english" lang="en">{H(en)}</p><p class="label">Security Detection Lab · VISOR DE EVIDENCIA / EVIDENCE VIEWER · No es UI del producto</p><p class="intro">{H(intro)}</p></header>{body}{sourcehtml}<footer><b>OFFLINE · Eventos sintéticos / Synthetic events · Not product UI</b><p>Sin conexión a SIEM, tráfico, ataques ni escaneos. Las señales no prueban compromiso.<br>No SIEM connection, traffic, attacks or scanning. Signals do not establish compromise.</p><div class="meta"><span>v0.1.0 · commit dc31cf4c1381</span><span>2026-10-29 · America/Tegucigalpa · {n}/5</span></div></footer></main></body></html>'''
    (viewer/(slug+'.html')).write_text(text)
    page_sources[slug]=dict(sources=sources,selection=selection)
    pages.append(dict(id=slug,title_es=title,title_en=en))

r=replay('auth-burst'); a=r['alerts'][0]; m=next(x for x in r['rules'] if x['rule_id']==a['rule_id'])
body=section('fail-5 dispara la alerta / fail-5 triggers the alert', kv([('rule_id',a['rule_id']),('Grupo / Group', ' · '.join(f'{k}={v}' for k,v in a['group'].items())),('threshold / value / window_seconds',f'{a["threshold"]} / {a["value"]} / {a["window_seconds"]}'),('trigger_id',a['trigger_id'])]))
body+=section('Evidencia completa y siguiente evento / Complete evidence and next event',table(['ID','UTC · 2026-10-29','outcome','Pertenece a la alerta / In alert'],[(e['id'],e['timestamp'][11:],e['outcome'],'Sí / Yes' if e['id'] in a['evidence_ids'] else 'No') for e in events('auth-burst')]))
body+=section('Métricas de auth-failure-burst',table(['matched_events','qualifying_triggers','emitted_alerts','suppressed_triggers'],[[m[k] for k in ['matched_events','qualifying_triggers','emitted_alerts','suppressed_triggers']]]))
body+=note('La alerta contiene fail-1…fail-5. El sexto fallo califica durante el cooldown y se suprime. / The alert contains fail-1…fail-5; the sixth qualifying failure is suppressed during cooldown.')+cli('auth-burst')
page('01-auth-burst','Una alerta con cinco eventos de evidencia','One alert, five evidence events','auth-burst · Umbral 5 · Ventana 300 s · Evaluación: passed',body,['outputs/auth-burst/replay.json','outputs/auth-burst/events.jsonl','outputs/verification.json'],'All six input events; all evidence IDs; selected alert fields and auth-failure-burst metrics; exact CLI message and observed exit.')

r=replay('denied-ports');a=r['alerts'][0]
body=section('Cinco puertos distintos / Five distinct ports',table(['ID','UTC · 2026-10-29','dst_port','transport','action'],[(e['id'],e['timestamp'][11:],e['dst_port'],e['transport'],e['action']) for e in events('denied-ports')]))
body+=section('Contrato de la alerta / Alert contract',kv([('rule_id / metric',a['rule_id']+' / '+a['metric']),('Grupo / Group',' · '.join(f'{k}={v}' for k,v in a['group'].items())),('threshold / value / window_seconds',f'{a["threshold"]} / {a["value"]} / {a["window_seconds"]}'),('trigger_id',a['trigger_id']),('evidence_ids',', '.join(a['evidence_ids']))]))
body+=note('Estos son eventos sintéticos de denegación: no se enviaron paquetes ni se comprobó que los puertos estuvieran abiertos. / These are synthetic deny events; no packets were sent and no open ports were established.')+cli('denied-ports')
page('02-denied-ports','Cinco puertos denegados, una señal','Five denied ports, one signal','denied-ports · Conteo distinto por origen, destino y transporte · Evaluación: passed',body,['outputs/denied-ports/replay.json','outputs/denied-ports/events.jsonl','outputs/verification.json'],'All five denied events and ports; selected alert fields including group, evidence, threshold, window and trigger; exact CLI message and exit.')

r=replay('window-boundary');a=r['alerts'][0];d=replay('duplicate-replay')
body=section('Límite inferior inclusivo / Inclusive lower boundary',table(['ID','Timestamp UTC','Evidencia de la única alerta'],[(e['id'],e['timestamp'],'Sí / Yes' if e['id'] in a['evidence_ids'] else 'No') for e in events('window-boundary')]))
body+=kv([('Ventana de la alerta / Alert window',a['window_start']+' → '+a['timestamp']),('threshold / value / window_seconds',f'{a["threshold"]} / {a["value"]} / {a["window_seconds"]}'),('trigger_id',a['trigger_id'])])
body+=note('12:00:00 sigue dentro de la ventana a las 12:05:00. A las 12:10:01, el evento de las 12:05:00 tiene 301 s y ha expirado; no hay otra alerta. / The 300-second lower boundary is included; the later event is 301 seconds after the previous event and produces no further alert.')
body+=section('duplicate-replay · 7 registros → 6 únicos → 1 alerta',table(['input_records','unique_events','duplicates_removed','actual_alerts'],[[d['counts']['input_records'],d['counts']['unique_events'],d['counts']['duplicates_removed'],len(d['alerts'])]]))
body+=pre('trigger_id: '+d['alerts'][0]['trigger_id']+'\nevidence_ids: '+', '.join(d['alerts'][0]['evidence_ids']))
body+=note('fail-6 aparece dos veces con el mismo contenido en la entrada original. Se elimina una copia antes del replay. / The original input repeats fail-6 exactly; one copy is removed before replay.')
page('03-window-and-duplicates','El borde cuenta; el duplicado no','The boundary counts; the duplicate does not','window-boundary + duplicate-replay · Dos casos independientes · Ambos: passed / exit 0',body,['outputs/window-boundary/replay.json','outputs/window-boundary/events.jsonl','outputs/duplicate-replay/replay.json','outputs/duplicate-replay-input/events.jsonl','outputs/verification.json'],'All boundary event timestamps; alert bounds and threshold; duplicate counts and complete alert evidence. Timing and duplicate explanations derived from retained inputs and output.')

s='expectation-mismatch';e=read(f'outputs/{s}/evaluation.json')
body=section('Esperado frente a observado / Expected versus observed',table(['expected_alerts','actual_alerts','matched_alerts','status','CLI exit'],[[e['expected_alerts'],e['actual_alerts'],e['matched_alerts'],e['status'],checks[s]['exit_code']]]))
body+=note('Fallo deliberado: este fixture espera cero alertas aunque los eventos producen una. El verificador exige exit 1. / Deliberate failure: this fixture expects zero alerts while the events produce one. The verification script requires exit 1.')
body+=section('Evaluación JSON literal / Literal evaluation JSON',pre((root/f'outputs/{s}/evaluation.json').read_text()))
body+=cli(s)
page('04-expectation-mismatch','Una expectativa incorrecta falla','An incorrect expectation fails','expectation-mismatch · El contrato detecta una alerta inesperada',body,[f'outputs/{s}/expected.json',f'outputs/{s}/evaluation.json',f'outputs/{s}/replay.json','outputs/verification.json'],'Complete literal evaluation.json, expected and actual counts, actual exit code and literal CLI message. Deliberate failure explicitly identified.')

run=read('logs/run.json')
rows=[]
for c in verification:
    s=c['scenario'];rr=None if s=='conflicting-id' else replay(s)
    rows.append([s,rr['counts']['input_records'] if rr else '—',rr['counts']['unique_events'] if rr else '—',len(rr['alerts']) if rr else '—',rr['evaluation']['status'] if rr else 'invalid input',c['exit_code']])
body=section('Pruebas locales reales / Actual local tests',pre((root/'logs/pytest.stdout.log').read_text()))
body+=table(['Comprobación / Check','Salida literal / Literal output','Exit'],[[k,(root/f'logs/{k}.stdout.log').read_text().strip(),next(c['exit_code'] for c in run['commands'] if c['name']==k)] for k in ['ruff-check','ruff-format']])
body+=section('Matriz completa / Complete CLI matrix',table(['Scenario','Raw','Unique','Alerts','Evaluation','Exit'],rows))
body+=note('benign: 0 alertas no certifica seguridad. expectation-mismatch: exit 1 esperado. conflicting-id: exit 2 esperado y sin directorio de salida. / Expected exits 1 and 2 are verified; zero alerts is not a security certification.')
body+=section('Conflicto de identidad / Identity conflict',pre(checks['conflicting-id']['output']))
body+=section('Resumen literal del verificador / Literal verifier summary',pre((root/'logs/examples.stdout.log').read_text().splitlines()[-1]))
body+=section('Entorno y procedencia / Environment and provenance',pre((root/'logs/environment.stdout.log').read_text())+'<p>Fuente limpia antes y después. Archivos Python instalados idénticos al commit.<br>Clean source before and after. Installed Python files match the commit byte for byte.</p>')
page('05-verification','126 pruebas y nueve escenarios verificados','126 tests and nine verified scenarios','Ejecución local independiente · Sin atribución a CI remota / Independent local execution',body,['logs/pytest.stdout.log','logs/ruff-check.stdout.log','logs/ruff-format.stdout.log','outputs/verification.json','logs/examples.stdout.log','logs/environment.stdout.log','logs/run.json'],'Full pytest and ruff stdout; all nine CLI scenario rows; literal conflict message and runner summary; environment stdout and source identity checks.')

(viewer/'style.css').write_text('''*{box-sizing:border-box}html{color-scheme:light}body{margin:0;background:#edf1f3;color:#172c3c;font:17px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1440px;margin:auto;padding:30px 42px 26px;background:#fff}header{border-top:5px solid #203d50;padding-top:18px}h1{font-size:36px;line-height:1.12;letter-spacing:-.025em;margin:0 0 5px}h2{font-size:20px;margin:0 0 10px;line-height:1.3}p{margin:9px 0}.english{font-size:22px;color:#476174;margin:6px 0 15px}.label{font-size:14px;font-weight:700;color:#8b371f;padding:9px 0;border-top:1px solid #d8e0e5;border-bottom:1px solid #d8e0e5}.intro{color:#476174;margin-bottom:20px}section{margin:24px 0 17px}table{width:100%;border-collapse:collapse;font-size:16px}th{text-align:left;background:#eaf0f4;font-size:14px}th,td{padding:9px 12px;border-bottom:1px solid #d8e0e5;overflow-wrap:anywhere}td{font-variant-numeric:tabular-nums}pre{font:15px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;background:#f1f5f7;padding:15px 18px;margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.note{background:#fff5e8;padding:13px 17px;font-size:16px;margin-top:18px}.exit{font-size:16px}.sources{font:12px/1.6 ui-monospace,SFMono-Regular,monospace;color:#425d6d;overflow-wrap:anywhere;margin-top:24px}a{color:#245771;text-underline-offset:3px}a:hover{color:#8b371f}a:focus-visible{outline:2px solid #8b371f;outline-offset:3px}::selection{background:#d4e6ef;color:#172c3c}footer{border-top:2px solid #c4d0d8;padding-top:13px;margin-top:20px;font-size:14px;color:#465d6d}footer b{color:#203d50}footer p{margin:6px 0}.meta{display:flex;justify-content:space-between;gap:15px;margin-top:10px;font-size:12px}@media(max-width:600px){main{padding:22px 16px}h1{font-size:29px}.english{font-size:19px}table{font-size:12px}th{font-size:12px}th,td{padding:7px 5px}.meta{flex-direction:column;gap:4px}pre{font-size:12px}.label{font-size:12px}}''')
page_sources['05-verification']['additional_dependencies'] = [f'outputs/{c["scenario"]}/replay.json' for c in verification if c['scenario'] != 'conflicting-id']
(root/'provenance/page-sources.json').write_text(json.dumps(page_sources,indent=2,ensure_ascii=False)+'\n')
(root/'provenance/pages.json').write_text(json.dumps(pages,indent=2,ensure_ascii=False)+'\n')
(viewer/'index.html').write_text('<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security Detection Lab · Evidence index</title><link rel="stylesheet" href="style.css"><main><h1>Security Detection Lab</h1><p class="label">VISOR DE EVIDENCIA / EVIDENCE VIEWER · Not product UI</p><p>v0.1.0 · dc31cf4c138123775185c41612e139082d383070 · Offline, synthetic events</p><ol>'+''.join(f'<li><a href="{p["id"]}.html">{H(p["title_es"])} / {H(p["title_en"])}</a></li>' for p in pages)+'</ol><p><a href="../README.md">README</a> · <a href="../manifest.json">Manifest</a> · <a href="../SHA256SUMS">SHA256SUMS</a></p></main></html>')
print('Built five evidence pages from retained artifacts.')
