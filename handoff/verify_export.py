"""Offline integrity and reproduction checks; historical outputs stay untouched."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SUITES = ['dg239-protocol-takeover-20261018',
          'dg239-response-buffer-provenance-20261019',
          'dg239-protocol-receive-binding-20261019']
SCRIPTS = {
    'dg239-gap-reconciliation-20261019': ['gap', 'parse_site_single_interface', 'step2_logind1'],
    'dg239-logind0-receive-parser-bridge-20261019': ['bridge', 'parser_sites'],
}


def run():
    inventory = json.loads((ROOT / 'EXPORT_INVENTORY.json').read_text())
    for entry in inventory['files']:
        path = ROOT / entry['path']
        if not path.is_file() or path.stat().st_size != entry['bytes']:
            raise RuntimeError('Missing/size mismatch: ' + entry['path'])
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
            raise RuntimeError('SHA mismatch: ' + entry['path'])
    print('Export hashes verified:', len(inventory['files']), flush=True)
    for suite in SUITES:
        subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover', '-s',
                        str(ROOT / 'work' / suite / 'evidence'), '-v'], check=True, cwd=ROOT)
    with tempfile.TemporaryDirectory(prefix='dg-offline-reproduction-') as directory:
        temporary = Path(directory)
        shutil.copytree(ROOT / 'work', temporary / 'work',
                        ignore=shutil.ignore_patterns('__pycache__'))
        for case, scripts in SCRIPTS.items():
            for script in scripts:
                relative = Path('work') / case / 'evidence' / (script + '.py')
                # Historical scripts print derived metadata; keep their output out of chat/CI logs.
                result = subprocess.run([sys.executable, '-B', str(temporary / relative)],
                                        cwd=temporary, capture_output=True)
                if result.returncode:
                    raise RuntimeError(f'{relative}: exit {result.returncode}')
                saved = relative.with_name(script + '.result.json')
                if json.loads((ROOT / saved).read_bytes()) != json.loads((temporary / saved).read_bytes()):
                    raise RuntimeError('Result mismatch: ' + str(saved))
                print('Temporary reproduction matches:', relative, flush=True)
    print('PASS: export integrity and local reproductions only; protocol completeness NOT asserted.')


if __name__ == '__main__':
    run()
