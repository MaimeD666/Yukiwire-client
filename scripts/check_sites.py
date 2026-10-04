"""Network matrix via an owned core; does not modify Nekoray or Windows."""
import argparse
import json
from pathlib import Path
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from yukiwire.backend import Session
from yukiwire.health import check_connection
from yukiwire.routing import DEFAULTS
from yukiwire.network import conflicts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', type=Path, required=True)
    args = parser.parse_args()
    session = Session()
    try:
        session.start(args.profile.read_text(encoding='utf-8-sig'), dict(DEFAULTS, capture='local', preset='all', auto_reconnect=False))
        report = check_connection()
        results = report['results']
        time.sleep(.3)
        print(json.dumps({'environment': conflicts(), 'through': 'Yukiwire local proxy; may be over Nekoray TUN',
                          **report, 'diagnostics': session.core.diagnostics()}, ensure_ascii=True, indent=2))
        return 0 if all(item['accessible'] for item in results) else 1
    finally:
        session.stop()


if __name__ == '__main__':
    raise SystemExit(main())
