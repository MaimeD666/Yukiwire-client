# Third-party components

Yukiwire uses these projects. Their licenses remain their own; no ownership of their code or datasets is claimed.

| Component | Version/source | License and source |
|---|---|---|
| Xray-core | v26.9.30, official Windows x64 release | [MPL-2.0](https://github.com/XTLS/Xray-core/blob/v26.9.30/LICENSE); distributed in core/Xray-LICENSE.txt; [source](https://github.com/XTLS/Xray-core/tree/v26.9.30) |
| Wintun, optional | 0.14.1, official AMD64 DLL | Official [distribution and license](https://www.wintun.net/); distributed in core/Wintun-LICENSE.txt |
| Microsoft WebView2 SDK | 1.0.4258.31, official NuGet package | [Package](https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.4258.31); unchanged SDK license in licenses/WebView2-LICENSE.txt |
| Built-in geodata | Unchanged files from the pinned Xray distribution, whose [asset workflow](https://github.com/XTLS/Xray-core/blob/v26.9.30/.github/workflows/scheduled-assets-update.yml) uses Loyalsoldier/v2ray-rules-dat | [GPL-3.0 and build sources](https://github.com/Loyalsoldier/v2ray-rules-dat); licenses/Loyalsoldier-LICENSE.txt; upstream [geoip](https://github.com/v2fly/geoip) CC-BY-SA-4.0 and [domain-list-community](https://github.com/v2fly/domain-list-community) MIT notices in licenses/Geoip-LICENSE.txt and licenses/Geosite-LICENSE.txt |
| Russia routing lists, optional download | runetfreedom/russia-v2ray-rules-dat, pinned commit per update | [Upstream repository](https://github.com/runetfreedom/russia-v2ray-rules-dat), upstream datasets and licenses; not included in the initial archive |
| Python | Official embedded 3.14.8; developer fallback can use build interpreter | [PSF license](https://docs.python.org/3/license.html); aggregate bundled notices in licenses/Python-LICENSE.txt; [release and checksums](https://www.python.org/downloads/release/python-3148/) |
| OpenSSL | CPython's bundled OpenSSL 3.x, version recorded in portable.json | [Apache-2.0](https://github.com/openssl/openssl/blob/openssl-3.5.9/LICENSE.txt); distributed in licenses/OpenSSL-LICENSE.txt |
| Inno Setup | 6.7.3, installer engine and portable build compiler | [Unmodified upstream source and license](https://github.com/jrsoftware/issrc/tree/is-6_7_3); Copyright Jordan Russell and Martijn Laan |
| Microsoft WebView2 Evergreen bootstrapper | Official signed Microsoft bootstrapper, SHA256 pinned in scripts/download_installer_tools.py | [Microsoft distribution documentation](https://learn.microsoft.com/microsoft-edge/webview2/concepts/distribution); embedded unchanged in Setup only |

The portable build includes unchanged Xray, Wintun, WebView2 SDK binaries and official Python executables/DLLs. The Python standard-library ZIP is filtered to exclude developer packages/tests. No PyInstaller bootloader, Tk/Tcl, Node or Electron runtime is distributed. WebView2 Runtime is a shared Microsoft Windows prerequisite under its own terms; Setup invokes the official bootstrapper only when the Runtime is absent. OpenSSL version is recorded in portable.json (3.5.9 in the default Python 3.14.8 runtime); the PSF notice bundle also includes upstream library acknowledgements. Yukiwire and its installer are unsigned previews.

The geometric application icon is generated from the project's own source in native/IconBuilder.cs; its SVG counterpart is in ui/assets/icon.svg.
