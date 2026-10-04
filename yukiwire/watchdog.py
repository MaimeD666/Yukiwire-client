"""Independent network recovery; owner/core are tracked by kernel handles, not PID polling."""
import argparse
import ctypes
from ctypes import wintypes
from pathlib import Path
import time

from .network import recover_journal
from .storage import SecureFile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--journal', required=True, type=Path)
    args = parser.parse_args()
    journal = SecureFile(args.journal)
    record = journal.read()
    if not record:
        return
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    handles = [api.OpenProcess(0x100000 | 0x1000, False, record[key]) for key in ('owner', 'core')]
    try:
        if not all(handles):
            # Do not advertise armed if the owner/core cannot be watched.
            return
        for key, handle in zip(('owner', 'core'), handles):
            values = [wintypes.FILETIME() for _ in range(4)]
            if not api.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)):
                return
            created = (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime
            if created != record.get(key + '_start'):
                return  # Never arm for a reused PID or an unverifiable legacy record.
        print('READY', flush=True)
        while journal.path.exists():
            states = [api.WaitForSingleObject(handle, 0) for handle in handles]
            if any(state not in (0, 258) for state in states):
                return  # Unknown handle state: retain durable recovery, no blind cleanup.
            if 0 in states:
                for _ in range(5):
                    try:
                        recover_journal(journal, expected_id=record.get('lease_id'))
                        return
                    except Exception:
                        time.sleep(1)
                return  # Durable journal allows recovery on next app start.
            time.sleep(.2)
    finally:
        for handle in handles:
            if handle:
                api.CloseHandle(handle)


if __name__ == '__main__':
    main()
