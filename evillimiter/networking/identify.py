"""Bounded, read-only device identification for hosts found by ARP."""

import ipaddress
import re
import secrets
import socket
import struct
import time
import unicodedata

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver
from scapy.all import conf


SERVICES = {
    '_googlecast._tcp.local.': 'Google Cast',
    '_airplay._tcp.local.': 'AirPlay',
    '_ipp._tcp.local.': 'Printer',
    '_ipps._tcp.local.': 'Printer',
    '_device-info._tcp.local.': '',
    '_adb._tcp.local.': 'Android',
    '_adb-tls-connect._tcp.local.': 'Android',
}


def clean_label(value, limit=64):
    """Device-supplied names must not inject terminal escapes or extra rows."""
    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='replace')
    value = ''.join(c for c in str(value) if not unicodedata.category(c).startswith('C'))
    return ' '.join(value.split()).strip().rstrip('.')[:limit]


def short_hostname(value):
    value = clean_label(value)
    return value[:-6] if value.lower().endswith('.local') else value


class HostIdentifier:
    def __init__(self, interface=None, timeout=3.0):
        self.interface = interface
        self.timeout = timeout

    def _socket(self, kind):
        sock = socket.socket(socket.AF_INET, kind)
        try:
            # Match the interface used for ARP, including machines with VPNs.
            if self.interface and hasattr(socket, 'SO_BINDTODEVICE'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                                self.interface.encode() + b'\0')
            return sock
        except OSError:
            sock.close()
            raise

    def identify(self, ip, mac):
        deadline = time.monotonic() + self.timeout
        hostname = self._reverse_dns(ip, min(0.5, self.timeout))
        details = self._mdns(ip, min(deadline, time.monotonic() + 1.0))
        hostname = hostname or details.get('hostname', '')
        model = details.get('model', '')
        friendly = details.get('friendly', '')
        kind = details.get('kind', '')

        # Only contact ADB when the device explicitly advertises it. Read the
        # greeting; never authenticate, pair, open a shell, or execute a command.
        if details.get('adb_port') and time.monotonic() < deadline:
            model = self._adb_model(ip, details['adb_port'], deadline) or model
        if not (hostname or friendly or model) and time.monotonic() < deadline:
            hostname = self._netbios(ip, min(deadline, time.monotonic() + 0.4))

        parts = []
        for value in (friendly or hostname, model or kind):
            value = clean_label(value)
            if value and value.casefold() not in [p.casefold() for p in parts]:
                parts.append(value)
        if parts:
            return clean_label(' — '.join(parts), limit=80)

        # Scapy's bundled/local OUI database; no external MAC lookup service.
        vendor = conf.manufdb._get_manuf(mac)
        if vendor and vendor.lower() != mac.lower():
            return '{} device'.format(clean_label(vendor, limit=60))
        return 'Unknown device'

    @staticmethod
    def _reverse_dns(ip, timeout):
        try:
            resolver = dns.resolver.Resolver()
            answer = resolver.resolve(ipaddress.ip_address(ip).reverse_pointer,
                                      'PTR', lifetime=timeout, search=False)
            return short_hostname(next(iter(answer)).target.to_text())
        except (dns.exception.DNSException, OSError, StopIteration):
            return ''

    def _mdns(self, ip, deadline):
        records = []
        requested = set()
        reverse = ipaddress.ip_address(ip).reverse_pointer + '.'

        def query(sock, name, rtype):
            key = (name.lower(), rtype)
            if key in requested or len(requested) >= 32:
                return
            requested.add(key)
            message = dns.message.make_query(name, rtype)
            message.id = 0
            message.flags = 0
            message.question[0].rdclass = 0x8001  # request a unicast response
            sock.sendto(message.to_wire(), (ip, 5353))

        try:
            with self._socket(socket.SOCK_DGRAM) as sock:
                for name in [reverse] + list(SERVICES):
                    query(sock, name, 'PTR')
                for _ in range(32):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    data, sender = sock.recvfrom(9000)
                    if sender != (ip, 5353):
                        continue
                    try:
                        message = dns.message.from_wire(data)
                    except dns.exception.DNSException:
                        continue
                    if not message.flags & dns.flags.QR or message.rcode():
                        continue
                    for rrset in message.answer + message.additional:
                        if not rrset.ttl:  # goodbye records withdraw an announcement
                            continue
                        owner = rrset.name.to_text().lower()
                        for record in rrset:
                            if len(records) >= 128:
                                break
                            records.append((owner, rrset.rdtype, record))
                            if rrset.rdtype == dns.rdatatype.PTR and owner in SERVICES:
                                instance = record.target.to_text()
                                query(sock, instance, 'SRV')
                                query(sock, instance, 'TXT')
        except OSError:
            pass
        return self._mdns_details(records, reverse)

    @staticmethod
    def _mdns_details(records, reverse):
        result = {}
        instances = {}
        for owner, rtype, record in records:
            if rtype == dns.rdatatype.PTR:
                if owner == reverse.lower():
                    result['hostname'] = short_hostname(record.target.to_text())
                elif owner in SERVICES:
                    instances[record.target.to_text().lower()] = (owner, record.target)
        for service, instance in instances.values():
            kind = SERVICES[service]
            if kind:
                result.setdefault('kind', kind)
            if service in ('_googlecast._tcp.local.', '_airplay._tcp.local.',
                           '_ipp._tcp.local.', '_ipps._tcp.local.'):
                # Name labels are decoded directly, preserving spaces/Unicode.
                name = instance.labels[0]
                result.setdefault('friendly', clean_label(name))
        for owner, rtype, record in records:
            instance = instances.get(owner)
            if not instance:
                continue
            service = instance[0]
            if rtype == dns.rdatatype.SRV:
                result.setdefault('hostname', short_hostname(record.target.to_text()))
                if service == '_adb._tcp.local.' and 0 < record.port < 65536:
                    result['adb_port'] = record.port
            elif rtype == dns.rdatatype.TXT:
                fields = {}
                for entry in record.strings:
                    key, sep, value = entry.partition(b'=')
                    if sep:
                        fields[key.lower()] = clean_label(value)
                if fields.get(b'fn'):
                    result['friendly'] = fields[b'fn']
                for key in (b'model', b'md', b'ty'):
                    if fields.get(key):
                        result.setdefault('model', fields[key])
                        break
        return result

    def _netbios(self, ip, deadline):
        transaction = secrets.randbelow(65536)
        name = b'*' + b'\0' * 15
        encoded = bytes(nibble + 65 for c in name for nibble in (c >> 4, c & 15))
        packet = struct.pack('!6H', transaction, 0, 1, 0, 0, 0)
        packet += b'\x20' + encoded + b'\0' + struct.pack('!HH', 33, 1)
        try:
            with self._socket(socket.SOCK_DGRAM) as sock:
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                sock.sendto(packet, (ip, 137))
                data, sender = sock.recvfrom(4096)
                if sender == (ip, 137):
                    return self._netbios_name(data, transaction)
        except (OSError, ValueError, struct.error, dns.exception.DNSException):
            pass
        return ''

    @staticmethod
    def _netbios_name(data, transaction):
        ident, flags, questions, answers, _, _ = struct.unpack('!6H', data[:12])
        if ident != transaction or not flags & 0x8000 or flags & 15:
            return ''
        if questions > 16 or answers > 16:
            return ''
        offset = 12
        for _ in range(questions):
            _, length = dns.name.from_wire(data, offset)
            offset += length + 4
        for _ in range(answers):
            _, length = dns.name.from_wire(data, offset)
            offset += length
            rtype, _, _, size = struct.unpack('!HHIH', data[offset:offset + 10])
            offset += 10
            payload = data[offset:offset + size]
            offset += size
            if rtype != 33 or not payload or len(payload) != size:
                continue
            for index in range(payload[0]):
                entry = payload[1 + index * 18:1 + (index + 1) * 18]
                if len(entry) != 18:
                    break
                # Workstation name (suffix 00), excluding workgroup names.
                if entry[15] == 0 and not struct.unpack('!H', entry[16:])[0] & 0x8000:
                    return clean_label(entry[:15])
        return ''

    def _adb_model(self, ip, port, deadline):
        deadline = min(deadline, time.monotonic() + 0.6)

        def read_exact(sock, length):
            data = bytearray()
            while len(data) < length:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout()
                sock.settimeout(remaining)
                part = sock.recv(length - len(data))
                if not part:
                    raise OSError('Connection closed')
                data.extend(part)
            return bytes(data)

        try:
            with self._socket(socket.SOCK_STREAM) as sock:
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                sock.connect((ip, port))
                command = int.from_bytes(b'CNXN', 'little')
                payload = b'host::\0'
                packet = struct.pack('<6I', command, 0x01000000, 4096,
                                     len(payload), sum(payload), command ^ 0xffffffff)
                sock.sendall(packet + payload)
                header = read_exact(sock, 24)
                reply, _, _, length, checksum, magic = struct.unpack('<6I', header)
                if reply != command or magic != reply ^ 0xffffffff or length > 4096:
                    return ''  # AUTH/STLS: no authentication or pairing attempted
                banner = read_exact(sock, length)
                if checksum != sum(banner):
                    return ''
                match = re.search(rb'(?:device::|;)ro\.product\.model=([^;\x00]+)', banner)
                return clean_label(match.group(1)) if match else ''
        except (OSError, ValueError, struct.error):
            return ''
