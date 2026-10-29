"""Run from the original frozen checkout; all writes stay in a NEW evidence root."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

repo = Path(sys.argv[1]).resolve()
root = Path(sys.argv[2]).resolve()
commit = 'dc31cf4c138123775185c41612e139082d383070'
logs = root / 'execution/logs'
runtime = root / 'execution/runtime'
logs.mkdir(parents=True, exist_ok=True)
runtime.mkdir(parents=True, exist_ok=True)

def git(*args):
    return subprocess.check_output(['git', '-C', str(repo), *args])

assert git('rev-parse', 'HEAD').decode().strip() == commit
assert git('status', '--porcelain=v1') == b''
tracked = git('ls-files', '-z').decode().split('\0')[:-1]
before = {f: hashlib.sha256((repo / f).read_bytes()).hexdigest() for f in tracked}
for f in tracked:
    assert (repo / f).read_bytes() == git('show', commit + ':' + f), f
venv = repo / '.venv/bin'
env = dict(os.environ, PATH=str(venv) + os.pathsep + os.environ['PATH'], PYTHONDONTWRITEBYTECODE='1', PYTHONPYCACHEPREFIX=str(runtime / 'pycache'), RUFF_CACHE_DIR=str(runtime / 'ruff'), TMPDIR=str(runtime), PYTEST_ADDOPTS='')
module = subprocess.check_output([str(venv / 'python'), '-c', 'import detectionlab; print(detectionlab.__file__)'], cwd=repo, env=env).decode().strip()
installed = Path(module).parent
source = repo / 'src/detectionlab'
installed_files = sorted(p.relative_to(installed).as_posix() for p in installed.rglob('*.py'))
source_files = sorted(p.relative_to(source).as_posix() for p in source.rglob('*.py'))
assert installed_files == source_files
installed_hashes = {}
for f in source_files:
    assert (installed / f).read_bytes() == (source / f).read_bytes(), f
    installed_hashes[f] = hashlib.sha256((installed / f).read_bytes()).hexdigest()
commands = [
    ('environment', [str(venv / 'python'), '-c', 'import sys,importlib.metadata as m,detectionlab; print("Python " + sys.version.split()[0]); print("security-detection-lab " + m.version("security-detection-lab")); print("pytest " + m.version("pytest")); print("ruff " + m.version("ruff"))']),
    ('ruff-check', [str(venv / 'ruff'), 'check', '--no-cache', 'src', 'tests', 'scripts']),
    ('ruff-format', [str(venv / 'ruff'), 'format', '--check', '--no-cache', 'src', 'tests', 'scripts']),
    ('pytest', [str(venv / 'pytest'), '-q', '-p', 'no:cacheprovider', '--basetemp', str(runtime / 'pytest')]),
    ('examples', [str(venv / 'python'), 'scripts/check_examples.py', '--output', os.path.relpath(root / 'execution/outputs', repo)]),
]
records = []
for name, args in commands:
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    p = subprocess.run(args, cwd=repo, env=env, capture_output=True, check=False)
    (logs / (name + '.stdout.log')).write_bytes(p.stdout)
    (logs / (name + '.stderr.log')).write_bytes(p.stderr)
    public_args = [a.replace(str(repo), '<SOURCE>').replace(str(root), '<EVIDENCE>') for a in args]
    records.append(dict(name=name, argv=public_args, cwd='<SOURCE>', started_at_utc=start, finished_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), exit_code=p.returncode))
    print(name, 'exit', p.returncode, p.stdout.decode(), p.stderr.decode(), flush=True)
    assert p.returncode == 0, name
assert before == {f: hashlib.sha256((repo / f).read_bytes()).hexdigest() for f in tracked}
assert git('status', '--porcelain=v1') == b''
assert installed_hashes == {f: hashlib.sha256((installed / f).read_bytes()).hexdigest() for f in source_files}
record = dict(source_commit=commit, version='0.1.0', source_clean_before=True, source_clean_after=True, tracked_files_match_commit=True, tracked_files_unchanged=True, import_source=Path(module).relative_to(repo).as_posix(), installed_python_files_match_commit=True, installed_python_sha256=installed_hashes, source_sha256=before, environment={'PATH': '<SOURCE>/.venv/bin prepended', 'PYTHONDONTWRITEBYTECODE': '1', 'cache_and_temp': '<EVIDENCE>/execution/runtime', 'PYTEST_ADDOPTS': ''}, commands=records)
(logs / 'run.json').write_text(json.dumps(record, indent=2) + '\n')
