"""Verify the protected installation boundary before requesting elevation."""
import ctypes
from ctypes import wintypes
from pathlib import Path
import re

TRUSTED_OWNERS = {
    'S-1-5-18',  # SYSTEM
    'S-1-5-32-544',  # Administrators (filtered out of a normal user token)
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464',  # TrustedInstaller
}
WRITE_MASK = 0x500D0156  # Includes GENERIC_ALL/WRITE as well as concrete file rights.


def program_files():
    buffer = ctypes.create_unicode_buffer(32768)
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    shell.SHGetFolderPathW.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR]
    if shell.SHGetFolderPathW(None, 0x26, None, 0, buffer) != 0:
        raise OSError('Не удалось определить защищённую папку установки Windows.')
    return Path(buffer.value)


def helper_directory(identity):
    if not isinstance(identity, str) or not re.fullmatch(r'[a-f0-9]{32}', identity):
        raise ValueError('Некорректная версия сетевого компонента.')
    return program_files() / 'YukiwireNetwork' / identity


def protected_acl(path):
    """Reject writable owners/allow ACEs, a missing DACL, and reparse points."""
    path = Path(path)
    if not path.exists() or path.stat(follow_symlinks=False).st_file_attributes & 0x400:
        return False
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    pointer = ctypes.c_void_p
    advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD] + [ctypes.POINTER(pointer)] * 5
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.GetAce.argtypes = [pointer, wintypes.DWORD, ctypes.POINTER(pointer)]
    advapi.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(pointer)]
    kernel.LocalFree.argtypes = [pointer]
    owner, group, dacl, sacl, descriptor = (pointer() for _ in range(5))
    result = advapi.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), ctypes.byref(group),
                                        ctypes.byref(dacl), ctypes.byref(sacl), ctypes.byref(descriptor))
    if result:
        raise OSError(result, 'Не удалось проверить права сетевого компонента.')
    def sid_string(sid):
        allocated = pointer()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(allocated)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(allocated)
        finally:
            kernel.LocalFree(allocated)
    try:
        if not owner or sid_string(owner) not in TRUSTED_OWNERS or not dacl:
            return False
        # ACL header: revision, reserved, size (WORD), AceCount (WORD), reserved.
        count = ctypes.c_ushort.from_address(dacl.value + 4).value
        for index in range(count):
            ace = pointer()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise ctypes.WinError(ctypes.get_last_error())
            kind = ctypes.c_ubyte.from_address(ace.value).value
            flags = ctypes.c_ubyte.from_address(ace.value + 1).value
            if flags & 0x08 or kind == 1:  # Inherit-only or a deny ACE grants no write.
                continue
            if kind != 0:  # Do not guess the semantics/layout of an unsupported allow ACE.
                return False
            mask = wintypes.DWORD.from_address(ace.value + 4).value
            if mask & WRITE_MASK and sid_string(pointer(ace.value + 8)) not in TRUSTED_OWNERS:
                return False
        return True
    finally:
        kernel.LocalFree(descriptor)


def require_protected_helper(executable, identity):
    expected = helper_directory(identity) / 'Yukiwire.Network.exe'
    path = Path(executable).absolute()
    if path != expected:
        raise ValueError('Сетевой компонент должен запускаться из защищённой установки.')
    # Do not resolve away a junction before checking each path component.
    for candidate in (path, path.parent, path.parent.parent, program_files()):
        if not protected_acl(candidate):
            raise ValueError('Права сетевого компонента небезопасны. Переустановите его перед использованием TUN.')
    return path
