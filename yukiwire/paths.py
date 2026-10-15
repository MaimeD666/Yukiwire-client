import sys
import os
from pathlib import Path

ROOT = Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[1]
PORTABLE = bool(getattr(sys, 'frozen', False) or (ROOT / 'portable.json').is_file())
RUNTIME = ROOT if PORTABLE else ROOT / 'runtime'
STATE = RUNTIME / 'state'
if os.environ.get('YUKIWIRE_TEST_SESSION') == '1' and os.environ.get('YUKIWIRE_TEST_STATE'):
    candidate = Path(os.environ['YUKIWIRE_TEST_STATE']).resolve()
    if not candidate.is_relative_to((RUNTIME / 'native-tests').resolve()):
        raise ValueError('Test state must remain inside the native test workspace')
    STATE = candidate
CORE = RUNTIME / 'core' / 'xray.exe'
