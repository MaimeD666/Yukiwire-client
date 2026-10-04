"""Read-only IP Helper snapshots; no administrator, WMI or network reset required."""
import ctypes as c
from ctypes import wintypes as w
import ipaddress
import re


class SocketAddress(c.Structure):
    _fields_ = [('address', c.c_void_p), ('length', c.c_int)]


class Unicast(c.Structure):
    pass


Unicast._fields_ = [('length', w.ULONG), ('flags', w.DWORD), ('next', c.POINTER(Unicast)),
                   ('socket', SocketAddress), ('prefix_origin', c.c_int), ('suffix_origin', c.c_int),
                   ('dad', c.c_int), ('valid', w.ULONG), ('preferred', w.ULONG), ('lease', w.ULONG),
                   ('prefix_length', c.c_ubyte)]


class DnsServer(c.Structure):
    pass


DnsServer._fields_ = [('length', w.ULONG), ('reserved', w.DWORD), ('next', c.POINTER(DnsServer)),
                     ('socket', SocketAddress)]


class Adapter(c.Structure):
    pass


Adapter._fields_ = [('length', w.ULONG), ('index', w.DWORD), ('next', c.POINTER(Adapter)),
                   ('adapter_name', c.c_char_p), ('unicast', c.POINTER(Unicast)),
                   ('anycast', c.c_void_p), ('multicast', c.c_void_p), ('dns', c.POINTER(DnsServer)),
                   ('dns_suffix', w.LPWSTR), ('description', w.LPWSTR), ('name', w.LPWSTR),
                   ('physical', c.c_ubyte * 8), ('physical_length', w.DWORD), ('flags', w.DWORD),
                   ('mtu', w.DWORD), ('kind', w.DWORD), ('status', c.c_int), ('index6', w.DWORD),
                   ('zones', w.DWORD * 16), ('prefix', c.c_void_p)]


class InetAddress(c.Union):
    _fields_ = [('raw', c.c_ubyte * 28), ('alignment', w.ULONG)]


class Prefix(c.Structure):
    _fields_ = [('address', InetAddress), ('length', c.c_ubyte)]


class Route(c.Structure):
    _fields_ = [('luid', c.c_uint64), ('index', w.DWORD), ('destination', Prefix), ('hop', InetAddress),
                   ('site_length', c.c_ubyte), ('valid', w.ULONG), ('preferred', w.ULONG),
                   ('metric', w.ULONG), ('protocol', c.c_int), ('loopback', c.c_ubyte),
                   ('autoconfigure', c.c_ubyte), ('publish', c.c_ubyte), ('immortal', c.c_ubyte),
                   ('age', w.ULONG), ('origin', c.c_int)]


class RouteTable(c.Structure):
    _fields_ = [('count', w.ULONG), ('first', Route)]


def decode_address(pointer, length):
    data = c.string_at(pointer, length)
    family = int.from_bytes(data[:2], 'little')
    if family == 2 and length >= 16:
        return str(ipaddress.IPv4Address(data[4:8]))
    if family == 23 and length >= 28:
        return str(ipaddress.IPv6Address(data[8:24]))
    raise ValueError('Unknown Windows address family')


def adapters():
    api = c.WinDLL('iphlpapi', use_last_error=True)
    api.GetAdaptersAddresses.argtypes = [w.ULONG, w.ULONG, c.c_void_p, c.c_void_p, c.POINTER(w.ULONG)]
    api.GetAdaptersAddresses.restype = w.ULONG
    size = w.ULONG(15000)
    for _ in range(3):
        buffer = c.create_string_buffer(size.value)
        code = api.GetAdaptersAddresses(0, 0x2 | 0x4 | 0x10 | 0x100, None, buffer, c.byref(size))
        if code == 232:
            return []
        if code == 111 and size.value <= 16 * 1024 * 1024:
            continue
        if code:
            raise c.WinError(code)
        break
    else:
        raise RuntimeError('Windows adapter snapshot is unstable')
    result = []
    pointer = c.cast(buffer, c.POINTER(Adapter))
    while pointer:
        adapter = pointer.contents
        addresses, servers = [], []
        node = adapter.unicast
        while node:
            item = node.contents
            addresses.append(decode_address(item.socket.address, item.socket.length) + '/' + str(item.prefix_length))
            node = item.next
        node = adapter.dns
        while node:
            item = node.contents
            servers.append(decode_address(item.socket.address, item.socket.length))
            node = item.next
        result.append({'index': adapter.index, 'index6': adapter.index6, 'name': adapter.name,
                       'description': adapter.description, 'up': adapter.status == 1,
                       'kind': adapter.kind,
                       'addresses': sorted(addresses), 'dns': sorted(servers)})
        pointer = adapter.next
    return result


def routes():
    api = c.WinDLL('iphlpapi', use_last_error=True)
    api.GetIpForwardTable2.argtypes = [w.USHORT, c.POINTER(c.c_void_p)]
    api.GetIpForwardTable2.restype = w.ULONG
    api.FreeMibTable.argtypes = [c.c_void_p]
    pointer = c.c_void_p()
    code = api.GetIpForwardTable2(0, c.byref(pointer))
    if code:
        raise c.WinError(code)
    try:
        count = c.cast(pointer, c.POINTER(RouteTable)).contents.count
        if count > 100000:
            raise ValueError('Unreasonable Windows route table size')
        rows = (Route * count).from_address(pointer.value + RouteTable.first.offset)
        result = []
        for row in rows:
            address = decode_address(c.addressof(row.destination.address), c.sizeof(InetAddress))
            prefix = str(ipaddress.ip_network(address + '/' + str(row.destination.length), strict=False))
            result.append({'index': row.index, 'prefix': prefix, 'next_hop': decode_address(c.addressof(row.hop), c.sizeof(InetAddress)),
                           'metric': row.metric})
        return sorted(result, key=lambda item: (item['index'], item['prefix'], item['next_hop'], item['metric']))
    finally:
        api.FreeMibTable(pointer)


def foreign_snapshot():
    entries = adapters()
    foreign = [item for item in entries if not (re.fullmatch(r'Yukiwire-[0-9a-f]{12}', item['name'] or '') and
               item['description'] == 'Yukiwire ' + item['name'][9:] + ' Tunnel')]
    indexes = {index for item in foreign for index in (item['index'], item['index6']) if index}
    return {'adapters': sorted(foreign, key=lambda item: item['index']),
            'routes': [item for item in routes() if item['index'] in indexes]}


def foreign_capture_present():
    state = foreign_snapshot()
    by_index = {}
    for route in state['routes']:
        by_index.setdefault(route['index'], set()).add(route['prefix'])
    for prefixes in by_index.values():
        if {'0.0.0.0/1', '128.0.0.0/1'}.issubset(prefixes) or {'::/1', '8000::/1'}.issubset(prefixes):
            return True
    for adapter in state['adapters']:
        vpn_interface = adapter['kind'] in (23, 131) or bool(re.search(
            r'wireguard|wintun|tap-windows|openvpn|tailscale', adapter.get('description') or '', re.I))
        if vpn_interface and adapter['up']:
            prefixes = by_index.get(adapter['index'], set()) | by_index.get(adapter['index6'], set())
            if '0.0.0.0/0' in prefixes or '::/0' in prefixes:
                return True
    return False
