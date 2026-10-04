"""Pinned Inno Setup in portable mode and a signed Microsoft WebView2 bootstrapper."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'build' / 'installer-tools'
INNO_VERSION = '6.7.3'
# Digest published by the immutable official GitHub release.
INNO_SHA256 = '9c73c3bae7ed48d44112a0f48e66742c00090bdb5bef71d9d3c056c66e97b732'
INNO_URL = f'https://github.com/jrsoftware/issrc/releases/download/is-6_7_3/innosetup-{INNO_VERSION}.exe'
# Resolved from Microsoft's official Evergreen bootstrapper link, signature verified.
WEBVIEW_URL = 'https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/c289719c-c70c-464b-81ea-9efa692d5428/MicrosoftEdgeWebview2Setup.exe'
WEBVIEW_SHA256 = 'aa38a8cfce6179b87181609b1c730a29eaf26138fc833af5759e67576770f3a3'


def signed_download(url, filename, digest, publisher):
    TOOLS.mkdir(parents=True, exist_ok=True)
    target = TOOLS / filename
    if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        with urllib.request.urlopen(url, timeout=90) as response:
            data = response.read(32 * 1024 * 1024 + 1)
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('Installer dependency SHA256 mismatch: ' + filename)
        target.write_bytes(data)
    payload = base64.b64encode(json.dumps({'path': str(target), 'publisher': publisher}).encode()).decode()
    # A pwsh parent can export PowerShell 7's modules to Windows PowerShell 5.1.
    # Let Windows PowerShell reconstruct its own module paths at startup.
    environment = {key: value for key, value in os.environ.items() if key.upper() != 'PSMODULEPATH'}
    script = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
    script += "$data=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + payload + "')) | ConvertFrom-Json; "
    script += "$sig=Get-AuthenticodeSignature -LiteralPath $data.path; $publisher=''; if ($sig.SignerCertificate) { $publisher=$sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) }; "
    script += "if ($sig.Status -ne 'Valid' -or $publisher -ne $data.publisher) { throw ('Dependency signature: ' + $sig.Status + '; publisher: ' + $publisher + '; ' + $sig.StatusMessage) }"
    encoded = base64.b64encode(script.encode('utf-16-le')).decode()
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-OutputFormat', 'Text', '-EncodedCommand', encoded],
                            capture_output=True, timeout=45, env=environment,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        details = (result.stdout + result.stderr).decode('utf-8', errors='replace').strip()
        raise RuntimeError('Dependency signature verification failed for ' + filename + ': ' +
                           (details or 'PowerShell exited with code ' + str(result.returncode)))
    return target


def install():
    setup = signed_download(INNO_URL, f'innosetup-{INNO_VERSION}.exe', INNO_SHA256, 'Pyrsys B.V.')
    compiler = TOOLS / ('inno-' + INNO_VERSION)
    marker = compiler / 'verified.json'
    valid = False
    if marker.is_file():
        saved = json.loads(marker.read_text())
        valid = saved.get('archive') == INNO_SHA256 and all(
            (compiler / name).is_file() and hashlib.sha256((compiler / name).read_bytes()).hexdigest() == digest
            for name, digest in saved['files'].items())
    if not valid:
        # Official /PORTABLE=1 creates no uninstall registration, associations or shortcuts.
        subprocess.run([str(setup), '/PORTABLE=1', '/CURRENTUSER', '/VERYSILENT', '/SUPPRESSMSGBOXES',
                        '/NORESTART', '/NOICONS', '/DIR=' + str(compiler)],
                       check=True, timeout=90, creationflags=subprocess.CREATE_NO_WINDOW)
        if not (compiler / 'ISCC.exe').is_file():
            raise RuntimeError('Inno Setup portable extraction failed')
        hashes = {path.relative_to(compiler).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in compiler.rglob('*') if path.is_file() and path != marker}
        marker.write_text(json.dumps({'archive': INNO_SHA256, 'files': hashes}))
    bootstrapper = signed_download(WEBVIEW_URL, 'MicrosoftEdgeWebview2Setup.exe', WEBVIEW_SHA256, 'Microsoft Corporation')
    return compiler / 'ISCC.exe', bootstrapper


if __name__ == '__main__':
    for asset in install():
        print(asset)
