"""Build a platform-specific offline VSIX with its native CLI, using the stdlib."""
import argparse
import hashlib
import json
import platform
import struct
import subprocess
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, help='Use an already-built release CLI')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    workspace = root.parents[1]
    package = json.loads((root / 'package.json').read_text())
    system = platform.system().lower()
    arch = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'x64', 'amd64': 'x64'}.get(platform.machine().lower())
    if system not in ('darwin', 'linux') or arch is None:
        raise SystemExit('Package on a supported macOS/Linux arm64/x64 host.')
    if args.binary is None:
        subprocess.run(['cargo', 'build', '--release', '--locked', '-p', 'distill-cli'], cwd=workspace, check=True)
    binary = (args.binary or workspace / 'target/release/distill').resolve()
    content = binary.read_bytes()
    if system == 'darwin':
        valid = content[:4] == bytes.fromhex('cffaedfe') and struct.unpack_from('<I', content, 4)[0] == {'arm64': 0x100000c, 'x64': 0x1000007}[arch]
    else:
        valid = content[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', content, 18)[0] == {'arm64': 183, 'x64': 62}[arch]
    if not valid:
        raise SystemExit('The CLI binary does not match the packaging host platform.')
    health = json.loads(subprocess.check_output([str(binary), 'doctor', '--json']))
    if not {'critical-hook-block', 'shell-context-coverage', 'node-hook-launcher', 'coding-workflows', 'native-critical-approval', 'foreground-critical-approval'}.issubset(health['capabilities']):
        raise SystemExit('Rebuild the CLI: required hook protections are missing.')
    target_platform = f'{system}-{arch}'
    target = root / f"{package['name']}-{package['version']}-{target_platform}.vsix"
    native = {'schema_version': 1, 'platform': system, 'arch': arch, 'version': health['product_version'], 'sha256': hashlib.sha256(content).hexdigest()}
    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
<Metadata><Identity Language="en-US" Id="{escape(package['name'])}" Version="{escape(package['version'])}" Publisher="{escape(package['publisher'])}" TargetPlatform="{target_platform}"/><DisplayName>{escape(package['displayName'])}</DisplayName><Description xml:space="preserve">{escape(package['description'])}</Description><Tags>commands,trace,severity</Tags><Categories>Other</Categories><GalleryFlags>Public</GalleryFlags><Properties><Property Id="Microsoft.VisualStudio.Code.Engine" Value="{escape(package['engines']['vscode'])}"/><Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="ui"/><Property Id="Microsoft.VisualStudio.Code.ExecutesCode" Value="true"/></Properties><License>extension/LICENSE</License></Metadata>
<Installation><InstallationTarget Id="Microsoft.VisualStudio.Code"/></Installation><Dependencies/><Assets><Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/></Assets></PackageManifest>'''
    content_types = '''<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="json" ContentType="application/json"/><Default Extension="js" ContentType="application/javascript"/><Default Extension="css" ContentType="text/css"/><Default Extension="svg" ContentType="image/svg+xml"/><Default Extension="md" ContentType="text/markdown"/><Default Extension="toml" ContentType="text/plain"/><Default Extension="vsixmanifest" ContentType="text/xml"/><Default Extension="" ContentType="application/octet-stream"/></Types>'''
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('extension.vsixmanifest', manifest)
        archive.writestr('[Content_Types].xml', content_types)
        for file in [root / 'package.json', root / 'README.md', *sorted((root / 'src').glob('*.js')), *sorted((root / 'media').iterdir()), *sorted((root / 'config').glob('*.toml'))]:
            archive.write(file, f'extension/{file.relative_to(root)}')
        archive.write(workspace / 'LICENSE', 'extension/LICENSE')
        archive.write(binary, 'extension/bin/distill')
        archive.writestr('extension/bin/manifest.json', json.dumps(native, indent=2) + '\n')
    print(target)


if __name__ == '__main__':
    main()
