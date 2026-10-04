"""Compile the Windows WebView2 host using installed .NET Framework."""
import os
from pathlib import Path
import subprocess
import shutil
import hashlib
from download_webview import install

ROOT = Path(__file__).resolve().parents[1]


def build():
    framework = Path(os.environ.get('WINDIR', r'C:\Windows')) / 'Microsoft.NET' / 'Framework64' / 'v4.0.30319'
    compiler = framework / 'csc.exe'
    icon = ROOT / 'ui' / 'assets' / 'yukiwire.ico'
    icon_source = ROOT / 'native' / 'IconBuilder.cs'
    if not icon.is_file() or icon.stat().st_mtime < icon_source.stat().st_mtime:
        generator = ROOT / 'build' / 'icon-builder.exe'
        generator.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([str(compiler), '/nologo', '/target:exe', '/out:' + str(generator),
                        '/reference:' + str(framework / 'System.Drawing.dll'), str(icon_source)], check=True)
        subprocess.run([str(generator), str(icon)], check=True)
    output = ROOT / 'runtime' / 'Yukiwire.exe'
    output.parent.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'native' / 'WebShell.cs'
    sdk = install()
    for name in ('Microsoft.Web.WebView2.Core.dll', 'Microsoft.Web.WebView2.Wpf.dll', 'WebView2Loader.dll'):
        destination = output.parent / name
        if not destination.is_file() or hashlib.sha256(destination.read_bytes()).digest() != hashlib.sha256((sdk / name).read_bytes()).digest():
            shutil.copy2(sdk / name, destination)
    worker_source = ROOT / 'native' / 'NetworkWorker.cs'
    manifest = ROOT / 'native' / 'app.manifest'
    launcher = ROOT / 'Yukiwire.exe'
    launcher_source = ROOT / 'native' / 'Launcher.cs'
    if not launcher.is_file() or launcher.stat().st_mtime < max(launcher_source.stat().st_mtime, icon.stat().st_mtime, manifest.stat().st_mtime):
        subprocess.run([str(compiler), '/nologo', '/target:winexe', '/platform:x64', '/out:' + str(launcher),
                        '/reference:' + str(framework / 'System.Windows.Forms.dll'), '/win32manifest:' + str(manifest),
                        '/win32icon:' + str(icon), str(launcher_source)], check=True)
    if output.exists() and output.stat().st_mtime >= max(source.stat().st_mtime, worker_source.stat().st_mtime, icon.stat().st_mtime, manifest.stat().st_mtime, Path(__file__).stat().st_mtime):
        return output
    references = [framework / 'WPF' / name for name in ('PresentationFramework.dll', 'PresentationCore.dll', 'WindowsBase.dll')]
    references.append(framework / 'System.Web.Extensions.dll')
    references.append(framework / 'System.Xaml.dll')
    references.append(framework / 'System.Drawing.dll')
    references.append(framework / 'System.Windows.Forms.dll')
    references.extend(sdk / name for name in ('Microsoft.Web.WebView2.Core.dll', 'Microsoft.Web.WebView2.Wpf.dll'))
    if not compiler.is_file():
        raise RuntimeError('Нет компилятора .NET Framework 4.x для Windows-хоста.')
    command = [str(compiler), '/nologo', '/target:winexe', '/platform:x64', '/out:' + str(output)]
    command += ['/win32manifest:' + str(manifest), '/win32icon:' + str(icon)]
    command += ['/reference:' + str(reference) for reference in references]
    command.append(str(source))
    command.append(str(worker_source))
    subprocess.run(command, check=True)
    return output


if __name__ == '__main__':
    print(build())
