"""Verify first-run installation and hooks from a built VSIX without an editor UI."""
import argparse
import subprocess
import tempfile
import zipfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('vsix', type=Path)
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix='distill-package-extract-') as directory:
    with zipfile.ZipFile(args.vsix) as archive:
        archive.extractall(directory)
    subprocess.run(['node', str(Path(__file__).with_name('package-smoke.js')), str(Path(directory) / 'extension')], check=True)
