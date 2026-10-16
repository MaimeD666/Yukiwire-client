"""Build the narrow network helper and its self-contained, one-time installer."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def build():
    framework = Path(os.environ['WINDIR']) / 'Microsoft.NET/Framework64/v4.0.30319'
    compiler = framework / 'csc.exe'
    generated = ROOT / 'build/network'
    generated.mkdir(parents=True, exist_ok=True)
    destination = ROOT / 'runtime/network'
    destination.mkdir(parents=True, exist_ok=True)
    assets = {'xray.exe': ROOT / 'runtime/core/xray.exe',
              'wintun.dll': ROOT / 'runtime/core/wintun.dll',
              'recover-tun.ps1': ROOT / 'scripts/recover-tun.ps1'}
    sources = [ROOT / 'native' / name for name in ('ProtectedStorage.cs', 'NetworkPolicy.cs', 'NetworkBroker.cs', 'NetworkInstaller.cs', 'NetworkFilter.cs', 'NetworkKillSwitch.cs', 'NetworkCleanup.cs')]
    # Any implementation, build, or pinned-payload change gets an isolated install.
    source_sha256 = hashlib.sha256(b''.join(path.read_bytes() for path in [*sources, *assets.values(), ROOT / 'native/app.manifest', Path(__file__)])).hexdigest()
    manifest_path = destination / 'component.json'
    if manifest_path.exists():
        previous = json.loads(manifest_path.read_text(encoding='utf-8'))
        if previous.get('source_sha256') == source_sha256 and all(
                (destination / name).is_file() and hashlib.sha256((destination / name).read_bytes()).hexdigest() == previous[key]
                for name, key in [('Yukiwire.Network.exe', 'helper_sha256'), ('Yukiwire.Network.Setup.exe', 'installer_sha256')]):
            return destination
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in assets.items()}
    constants = generated / 'NetworkBuild.cs'

    def write_constants(identity=None):
        constants.write_text('namespace Yukiwire { public static class NetworkBuild {\n'
                             + ('public const string Identity = ' + json.dumps(identity) + ';\n' if identity else
                                'public static string Identity { get { return ProtectedStorage.Digest(System.Reflection.Assembly.GetExecutingAssembly().Location).Substring(0,32); } }\n')
                             + 'public static readonly string[] Names = new string[] {' + ','.join(map(json.dumps, hashes)) + '};\n'
                             + 'public static readonly string[] Hashes = new string[] {' + ','.join(map(json.dumps, hashes.values())) + '};\n'
                             + '} }\n', encoding='utf-8')

    write_constants()
    common = [str(compiler), '/nologo', '/target:winexe', '/platform:x64',
              '/win32manifest:' + str(ROOT / 'native/app.manifest'),
              '/reference:' + str(framework / 'System.Web.Extensions.dll')]
    helper = destination / 'Yukiwire.Network.exe'
    subprocess.run(common + ['/out:' + str(helper), str(constants), *map(str, sources[:3] + sources[4:])], check=True)
    assets['Yukiwire.Network.exe'] = helper
    hashes['Yukiwire.Network.exe'] = hashlib.sha256(helper.read_bytes()).hexdigest()
    identity = hashes['Yukiwire.Network.exe'][:32]
    write_constants(identity)
    installer = destination / 'Yukiwire.Network.Setup.exe'
    subprocess.run(common + ['/out:' + str(installer), str(constants), str(sources[0]), str(sources[3])]
                   + ['/resource:' + str(path) + ',' + name for name, path in assets.items()], check=True)
    manifest = {'identity': identity, 'source_sha256': source_sha256, 'helper_sha256': hashes['Yukiwire.Network.exe'],
                'installer_sha256': hashlib.sha256(installer.read_bytes()).hexdigest()}
    (destination / 'component.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return destination


if __name__ == '__main__':
    print(build())
