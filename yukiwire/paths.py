import sys
from pathlib import Path

ROOT = Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[1]
PORTABLE = bool(getattr(sys, 'frozen', False) or (ROOT / 'portable.json').is_file())
RUNTIME = ROOT if PORTABLE else ROOT / 'runtime'
STATE = RUNTIME / 'state'
CORE = RUNTIME / 'core' / 'xray.exe'
