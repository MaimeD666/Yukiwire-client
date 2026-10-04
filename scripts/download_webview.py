"""Fetch the pinned Microsoft WebView2 SDK from NuGet, verifying its package digest."""
import hashlib
import io
from pathlib import Path
import urllib.request
import zipfile

VERSION = '1.0.4258.31'
SHA256 = '56f7f4b8bf9aee4b8efefbbdd4f67d5f74ebd1b100ed0806da71bf76af481aa9'
ROOT = Path(__file__).resolve().parents[1]


def install():
    destination = ROOT / 'runtime' / 'webview'
    if (destination / 'version.txt').is_file() and (destination / 'version.txt').read_text() == VERSION:
        if all((destination / name).is_file() for name in ('Microsoft.Web.WebView2.Core.dll', 'Microsoft.Web.WebView2.Wpf.dll', 'WebView2Loader.dll', 'LICENSE.txt')):
            return destination
    url = f'https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/{VERSION}/microsoft.web.webview2.{VERSION}.nupkg'
    with urllib.request.urlopen(url, timeout=90) as response:
        data = response.read(32 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise RuntimeError('WebView2 SDK integrity check failed')
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in ('Microsoft.Web.WebView2.Core.dll', 'Microsoft.Web.WebView2.Wpf.dll'):
            (destination / name).write_bytes(archive.read('lib/net462/' + name))
        (destination / 'WebView2Loader.dll').write_bytes(archive.read('runtimes/win-x64/native/WebView2Loader.dll'))
        (destination / 'LICENSE.txt').write_bytes(archive.read('LICENSE.txt'))
    (destination / 'version.txt').write_text(VERSION)
    return destination


if __name__ == '__main__':
    print(install())
