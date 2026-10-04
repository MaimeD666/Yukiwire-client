import argparse
from pathlib import Path
from .storage import SecureFile
from .network import recover_journal


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--journal', required=True, type=Path)
    args = parser.parse_args()
    result = recover_journal(SecureFile(args.journal), stale_only=True, cleanup_empty=True)
    if result.get('conflict') and result.get('reason') != 'active_owner':
        raise SystemExit(1)  # Task Scheduler retries; the journal/task are retained.


if __name__ == '__main__':
    main()
