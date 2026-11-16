"""Build an offline, platform-specific VSIX using the official VS Code packager."""
import argparse
import hashlib
import json
import platform
import shutil
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree


def native_matches(content, system, arch):
    if len(content) < 20:
        return False
    if system == 'darwin':
        return content[:4] == bytes.fromhex('cffaedfe') and struct.unpack_from('<I', content, 4)[0] == {'arm64': 0x100000c, 'x64': 0x1000007}[arch]
    return content[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', content, 18)[0] == {'arm64': 183, 'x64': 62}[arch]


def verify_package(target, target_platform, native):
    with zipfile.ZipFile(target) as archive:
        for name in ['package.json', 'src/extension.js', 'config/extension-policy.toml']:
            if f'extension/{name}' not in archive.namelist():
                raise SystemExit(f'Package is missing {name}.')
        for name, digest in [('distill', native['sha256']), ('distill-service', native['service']['sha256'])]:
            if hashlib.sha256(archive.read(f'extension/bin/{name}')).hexdigest() != digest:
                raise SystemExit(f'Packaged {name} checksum mismatch.')
        if json.loads(archive.read('extension/bin/manifest.json')) != native:
            raise SystemExit('Packaged native manifest mismatch.')
        manifest = ElementTree.fromstring(archive.read('extension.vsixmanifest'))
        ns = {'v': 'http://schemas.microsoft.com/developer/vsx-schema/2011'}
        if manifest.find('v:Metadata/v:Identity', ns).get('TargetPlatform') != target_platform:
            raise SystemExit('VSIX target platform mismatch.')
        assets = {asset.get('Type') for asset in manifest.findall('v:Assets/v:Asset', ns)}
        if not {'Microsoft.VisualStudio.Services.Content.Details', 'Microsoft.VisualStudio.Services.Content.License'}.issubset(assets):
            raise SystemExit('Marketplace README/license assets are missing.')
        for asset in manifest.findall('v:Assets/v:Asset', ns):
            if asset.get('Path') not in archive.namelist():
                raise SystemExit(f"Missing Marketplace asset: {asset.get('Path')}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, help='Use an already-built release CLI and its sibling service')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    workspace = root.parents[1]
    package = json.loads((root / 'package.json').read_text())
    system = platform.system().lower()
    arch = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'x64', 'amd64': 'x64'}.get(platform.machine().lower())
    if system not in ('darwin', 'linux') or arch is None:
        raise SystemExit('Package on a supported macOS/Linux arm64/x64 host.')
    local_vsce = root / 'node_modules/.bin/vsce'
    vsce = str(local_vsce) if local_vsce.exists() else shutil.which('vsce')
    if not vsce or subprocess.check_output([vsce, '--version'], text=True).strip() != package['devDependencies']['@vscode/vsce']:
        raise SystemExit('Run npm ci in extensions/vscode to install the pinned VS Code packager.')
    if args.binary is None:
        subprocess.run(['cargo', 'build', '--release', '--locked', '-p', 'distill-cli', '-p', 'distill-service'], cwd=workspace, check=True)
    binary = (args.binary or workspace / 'target/release/distill').resolve()
    service = binary.with_name('distill-service')
    if not binary.is_file() or not service.is_file():
        raise SystemExit('Build distill and distill-service beside each other before packaging.')
    content, service_content = binary.read_bytes(), service.read_bytes()
    for name, data in [('CLI', content), ('service', service_content)]:
        if not native_matches(data, system, arch):
            raise SystemExit(f'The {name} binary does not match the packaging host platform.')
    health = json.loads(subprocess.check_output([str(binary), 'doctor', '--json']))
    required = json.loads(subprocess.check_output(['node', '-e', "process.stdout.write(JSON.stringify(require('./src/install').REQUIRED))"], cwd=root))
    if health.get('trace_protocol') != 1 or not set(required).issubset(health.get('capabilities', [])):
        raise SystemExit('Rebuild the CLI: required extension capabilities are missing.')
    target_platform = f'{system}-{arch}'
    target = root / f"{package['name']}-{package['version']}-{target_platform}.vsix"
    native = {'schema_version': 1, 'platform': system, 'arch': arch, 'version': health['product_version'], 'sha256': hashlib.sha256(content).hexdigest(), 'service': {'sha256': hashlib.sha256(service_content).hexdigest()}}
    with tempfile.TemporaryDirectory(prefix='distill-vsix-') as directory:
        stage = Path(directory)
        for name in ['package.json', 'README.md', 'CHANGELOG.md', '.vscodeignore']:
            shutil.copy2(root / name, stage / name)
        for name in ['src', 'media', 'config']:
            shutil.copytree(root / name, stage / name)
        shutil.copy2(workspace / 'LICENSE', stage / 'LICENSE')
        (stage / 'bin').mkdir()
        shutil.copy2(binary, stage / 'bin/distill')
        shutil.copy2(service, stage / 'bin/distill-service')
        (stage / 'bin/manifest.json').write_text(json.dumps(native, indent=2) + '\n')
        repository = package['repository']['url']
        subprocess.run([vsce, 'package', '--no-dependencies', '--target', target_platform, '--out', str(target),
                        '--baseContentUrl', f'{repository}/blob/main/extensions/vscode',
                        '--baseImagesUrl', f'{repository}/raw/main/extensions/vscode'], cwd=stage, check=True)
    verify_package(target, target_platform, native)
    print(target)


if __name__ == '__main__':
    main()
