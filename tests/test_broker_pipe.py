"""Exercise real Windows pipe I/O in a bounded child; no UAC or network changes."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import queue
import struct
import subprocess
import sys
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from yukiwire.broker import Pipe, LIMIT


def exercise(mode):
    pipe = Pipe()
    ready, stop = threading.Event(), threading.Event()
    errors = queue.Queue()
    payload = {'text': 'x' * 262144, 'id': 123}

    def client():
        api = ctypes.WinDLL('kernel32', use_last_error=True)
        api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                   wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        api.CreateFileW.restype = wintypes.HANDLE
        api.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        api.WriteFile.argtypes = api.ReadFile.argtypes
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = api.CreateFileW('\\\\.\\pipe\\' + pipe.name, 0xc0000000, 0, None, 3, 0, None)
        assert handle != ctypes.c_void_p(-1).value
        def write(data):
            count = wintypes.DWORD()
            assert api.WriteFile(handle, data, len(data), ctypes.byref(count), None)
            assert count.value == len(data)
        def read(size):
            data = bytearray()
            while len(data) < size:
                buffer = ctypes.create_string_buffer(size - len(data))
                count = wintypes.DWORD()
                assert api.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None) and count.value
                data.extend(buffer.raw[:count.value])
            return bytes(data)
        try:
            if mode == 'wrong-peer':
                stop.wait(3)
            elif mode == 'oversized':
                write(struct.pack('<I', LIMIT + 1))
            else:
                write(b'\x02\x00\x00\x00{}')
                if mode == 'exchange':
                    size, = struct.unpack('<I', read(4))
                    assert json.loads(read(size)) == payload
                    write(b'\x0b\x00\x00\x00{"ok":true}')
                else:
                    stop.wait(3)
        except BaseException as error:
            errors.put(error)
        finally:
            api.CloseHandle(handle)

    def reader():
        try:
            pipe.connect(os.getpid() + (1 if mode == 'wrong-peer' else 0))
            if mode in ('wrong-peer', 'cancel-connect'):
                raise AssertionError('Unexpected connection')
            pipe.receive()
            if mode == 'oversized':
                raise AssertionError('Oversized frame accepted')
            ready.set()
            response = pipe.receive()
            assert mode == 'exchange' and response == {'ok': True}
        except ValueError as error:
            if mode not in ('oversized', 'wrong-peer'):
                errors.put(error)
        except (OSError, EOFError) as error:
            if mode not in ('cancel-read', 'cancel-connect'):
                errors.put(error)
        except BaseException as error:
            errors.put(error)

    receiver = threading.Thread(target=reader, daemon=True)
    peer = threading.Thread(target=client, daemon=True)
    receiver.start()
    if mode != 'cancel-connect':
        peer.start()
    try:
        if mode in ('exchange', 'cancel-read'):
            assert ready.wait(3), 'Peer never became ready'
            time.sleep(.1)  # Reader is waiting while the other thread sends/cancels.
        if mode == 'exchange':
            pipe.send(payload)
        elif mode in ('cancel-read', 'cancel-connect'):
            time.sleep(.1)
            pipe.close()
        receiver.join(3)
        assert not receiver.is_alive(), 'Pipe operation remained blocked'
    finally:
        pipe.close()
        stop.set()
        if peer.ident:
            peer.join(3)
    assert errors.empty(), repr(list(errors.queue))


@unittest.skipUnless(os.name == 'nt', 'Windows named pipes')
class PipeIntegrationTests(unittest.TestCase):
    def test_full_duplex_framing_peer_binding_and_cancellation(self):
        for mode in ('exchange', 'cancel-read', 'cancel-connect', 'oversized', 'wrong-peer'):
            with self.subTest(mode=mode):
                subprocess.run([sys.executable, '-B', __file__, mode], check=True, timeout=10)


if __name__ == '__main__':
    exercise(sys.argv[1])
