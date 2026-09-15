import base64
import socket
import struct
import threading
import time
import unittest
from unittest.mock import Mock, patch

import dns.exception
import dns.message
import dns.rrset

from evillimiter.networking.identify import HostIdentifier, clean_label
# Match the application's import order for its existing shell/IO dependency.
import evillimiter.console.shell
from evillimiter.networking.host import Host
from evillimiter.networking.scan import HostScanner


IP = '192.0.2.22'
MAC = '00:00:00:00:00:01'
REVERSE = '22.2.0.192.in-addr.arpa.'


class DatagramSocket:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def settimeout(self, timeout):
        if timeout <= 0:
            raise AssertionError('Timeout must be positive')

    def sendto(self, data, target):
        self.sent.append((data, target))

    def recvfrom(self, size):
        try:
            return next(self.responses)
        except StopIteration:
            raise socket.timeout()


class StreamSocket(DatagramSocket):
    def __init__(self, response, fragment=3):
        super().__init__([])
        self.response = response
        self.fragment = fragment

    def connect(self, target):
        self.target = target

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        size = min(size, self.fragment)
        data, self.response = self.response[:size], self.response[size:]
        return data


def adb_packet(payload, command=b'CNXN', checksum=None):
    cmd = int.from_bytes(command, 'little')
    return struct.pack('<6I', cmd, 0x01000000, 4096, len(payload),
                       sum(payload) if checksum is None else checksum,
                       cmd ^ 0xffffffff) + payload


def response(*rrsets):
    message = dns.message.Message(id=0)
    message.flags = 0x8400
    message.answer.extend(rrsets)
    return message.to_wire()


class IdentificationTests(unittest.TestCase):
    def setUp(self):
        self.identifier = HostIdentifier()

    def test_android_discovery_and_fragmented_model_banner(self):
        ptr = dns.rrset.from_text('_adb._tcp.local.', 10, 'IN', 'PTR',
                                 'adb-example._adb._tcp.local.')
        srv = dns.rrset.from_text('adb-example._adb._tcp.local.', 10, 'IN', 'SRV',
                                 '0 0 7896 Android-2.local.')
        udp = DatagramSocket([(response(ptr, srv), (IP, 5353))])
        tcp = StreamSocket(adb_packet(b'device::ro.product.name=p281;'
                                     b'ro.product.model=TX6s;\0'))
        with patch.object(self.identifier, '_reverse_dns', return_value=''), \
                patch.object(self.identifier, '_socket', side_effect=[udp, tcp]):
            name = self.identifier.identify(IP, MAC)
        self.assertEqual(name, 'Android-2 — TX6s')
        self.assertEqual(tcp.target, (IP, 7896))
        self.assertEqual(len(tcp.sent), 1)  # greeting only, no shell/auth packets
        for packet, target in udp.sent:
            query = dns.message.from_wire(packet)
            self.assertEqual(query.question[0].rdclass, 0x8001)
            self.assertEqual(target, (IP, 5353))

    def test_compressed_mdns_packet(self):
        # Synthetic fixture with compressed PTR/SRV/TXT/A/AAAA records.
        packet = base64.b64decode(
            'AACEAAAAAAEAAAAEBF9hZGIEX3RjcAVsb2NhbAAADAABAAAACgAOC2FkYi1leGFtcGxlwAzA'
            'JwAhAAEAAAAKABIAAAAAHtgJQW5kcm9pZC0ywBbAJwAQAAEAAAAKAAEAwEcAAQABAAAACgAE'
            'wAACFsBHABwAAQAAAAoAECABDbgAAAAAAAAAAAAAACI=')
        udp = DatagramSocket([(packet, (IP, 5353))])
        with patch.object(self.identifier, '_socket', return_value=udp):
            details = self.identifier._mdns(IP, time.monotonic() + 1)
        self.assertEqual(details['hostname'], 'Android-2')
        self.assertEqual(details['adb_port'], 7896)

    def test_friendly_name_and_model_from_txt(self):
        ptr = dns.rrset.from_text('_googlecast._tcp.local.', 10, 'IN', 'PTR',
                                 'Cast._googlecast._tcp.local.')
        txt = dns.rrset.from_text('Cast._googlecast._tcp.local.', 10, 'IN', 'TXT',
                                 '"fn=Living Room" "md=Chromecast"')
        udp = DatagramSocket([(response(ptr, txt), (IP, 5353))])
        with patch.object(self.identifier, '_reverse_dns', return_value=''), \
                patch.object(self.identifier, '_socket', return_value=udp):
            self.assertEqual(self.identifier.identify(IP, MAC),
                             'Living Room — Chromecast')

    def test_unrelated_txt_is_not_used(self):
        txt = dns.rrset.from_text('unrelated.local.', 10, 'IN', 'TXT',
                                 '"fn=Wrong device"')
        udp = DatagramSocket([(response(txt), (IP, 5353))])
        with patch.object(self.identifier, '_socket', return_value=udp):
            self.assertEqual(self.identifier._mdns(IP, time.monotonic() + 1), {})

    def test_service_name_case_is_preserved_without_txt(self):
        ptr = dns.rrset.from_text('_ipp._tcp.local.', 10, 'IN', 'PTR',
                                 'OfficePrinter._ipp._tcp.local.')
        udp = DatagramSocket([(response(ptr), (IP, 5353))])
        with patch.object(self.identifier, '_socket', return_value=udp):
            details = self.identifier._mdns(IP, time.monotonic() + 1)
        self.assertEqual(details['friendly'], 'OfficePrinter')

    def test_withdrawn_mdns_records_are_ignored(self):
        ptr = dns.rrset.from_text(REVERSE, 0, 'IN', 'PTR', 'Old.local.')
        udp = DatagramSocket([(response(ptr), (IP, 5353))])
        with patch.object(self.identifier, '_socket', return_value=udp):
            self.assertEqual(self.identifier._mdns(IP, time.monotonic() + 1), {})

    def test_malformed_and_other_host_mdns_are_ignored(self):
        ptr = dns.rrset.from_text(REVERSE, 10, 'IN', 'PTR', 'Wrong.local.')
        udp = DatagramSocket([(b'bad', (IP, 5353)),
                              (response(ptr), ('192.0.2.99', 5353))])
        with patch.object(self.identifier, '_socket', return_value=udp):
            self.assertEqual(self.identifier._mdns(IP, time.monotonic() + 1), {})

    def test_reverse_dns_is_retained_when_mdns_absent(self):
        with patch.object(self.identifier, '_reverse_dns', return_value='Office-PC'), \
                patch.object(self.identifier, '_mdns', return_value={}), \
                patch.object(self.identifier, '_netbios') as netbios:
            self.assertEqual(self.identifier.identify(IP, MAC), 'Office-PC')
        netbios.assert_not_called()

    def test_router_name_is_preferred_to_generic_mdns_hostname(self):
        with patch.object(self.identifier, '_reverse_dns', return_value='Office-PC'), \
                patch.object(self.identifier, '_mdns', return_value={'hostname': 'android-123'}):
            self.assertEqual(self.identifier.identify(IP, MAC), 'Office-PC')

    def test_dns_timeout_is_nonfatal_and_bounded(self):
        resolver = Mock()
        resolver.resolve.side_effect = dns.exception.Timeout
        with patch('dns.resolver.Resolver', return_value=resolver):
            self.assertEqual(self.identifier._reverse_dns(IP, 0.5), '')
        self.assertEqual(resolver.resolve.call_args.kwargs['lifetime'], 0.5)

    def test_netbios_workstation_not_workgroup(self):
        entries = b'WORKGROUP      ' + b'\0\x80\x00'
        entries += b'OFFICE-PC      ' + b'\0\x00\x00'
        payload = b'\x02' + entries
        packet = struct.pack('!6H', 42, 0x8400, 0, 1, 0, 0)
        packet += b'\0' + struct.pack('!HHIH', 33, 1, 10, len(payload)) + payload
        self.assertEqual(self.identifier._netbios_name(packet, 42), 'OFFICE-PC')
        self.assertEqual(self.identifier._netbios_name(packet, 43), '')

    def test_netbios_used_for_unnamed_host(self):
        with patch.object(self.identifier, '_reverse_dns', return_value=''), \
                patch.object(self.identifier, '_mdns', return_value={}), \
                patch.object(self.identifier, '_netbios', return_value='OFFICE-PC'):
            self.assertEqual(self.identifier.identify(IP, MAC), 'OFFICE-PC')

    def test_unknown_and_manufacturer_fallback(self):
        with patch.object(self.identifier, '_reverse_dns', return_value=''), \
                patch.object(self.identifier, '_mdns', return_value={}), \
                patch.object(self.identifier, '_netbios', return_value=''), \
                patch('evillimiter.networking.identify.conf') as config:
            config.manufdb._get_manuf.return_value = MAC
            self.assertEqual(self.identifier.identify(IP, MAC), 'Unknown device')
            config.manufdb._get_manuf.return_value = 'Example Inc.'
            self.assertEqual(self.identifier.identify(IP, MAC), 'Example Inc device')

    def test_adb_auth_request_is_not_answered(self):
        tcp = StreamSocket(adb_packet(b'token', command=b'AUTH'))
        with patch.object(self.identifier, '_socket', return_value=tcp):
            self.assertEqual(self.identifier._adb_model(IP, 7896, time.monotonic() + 1), '')
        self.assertEqual(len(tcp.sent), 1)

    def test_adb_invalid_checksum_and_truncated_banner(self):
        banner = b'device::ro.product.model=Untrusted;'
        for packet in (adb_packet(banner, checksum=0), adb_packet(banner)[:-3]):
            with self.subTest(packet=packet), \
                    patch.object(self.identifier, '_socket', return_value=StreamSocket(packet)):
                self.assertEqual(self.identifier._adb_model(IP, 7896, time.monotonic() + 1), '')

    def test_adb_oversized_payload_is_rejected(self):
        tcp = StreamSocket(adb_packet(b'x' * 4097))
        with patch.object(self.identifier, '_socket', return_value=tcp):
            self.assertEqual(self.identifier._adb_model(IP, 7896, time.monotonic() + 1), '')
        self.assertEqual(len(tcp.response), 4097)

    def test_unadvertised_adb_is_not_contacted(self):
        with patch.object(self.identifier, '_reverse_dns', return_value=''), \
                patch.object(self.identifier, '_mdns', return_value={'hostname': 'Android'}), \
                patch.object(self.identifier, '_adb_model') as adb:
            self.identifier.identify(IP, MAC)
        adb.assert_not_called()

    def test_terminal_controls_and_long_names(self):
        result = clean_label('TV\x1b[31m\n\r\t\u202e' + 'x' * 100)
        self.assertNotIn('\x1b', result)
        self.assertNotIn('\n', result)
        self.assertNotIn('\u202e', result)
        self.assertLessEqual(len(result), 64)


class ScannerTests(unittest.TestCase):
    def test_host_names_never_remain_blank(self):
        for value in (None, '', '  ', '\n\t'):
            with self.subTest(value=value):
                host = Host(IP, MAC, value)
                self.assertEqual(host.name, 'Unknown device')
                host.name = 'Office PC'
                self.assertEqual(host.name, 'Office PC')
                host.name = value
                self.assertEqual(host.name, 'Unknown device')

    def test_names_are_resolved_concurrently(self):
        scanner = HostScanner('eth0', [IP, '192.0.2.23'])
        rendezvous = threading.Barrier(2)

        def identify(ip, mac):
            rendezvous.wait(timeout=2)
            return 'Device at ' + ip

        with patch.object(scanner, '_sweep', side_effect=lambda ip: Host(ip, MAC, '')), \
                patch.object(scanner.identifier, 'identify', side_effect=identify):
            hosts = scanner.scan()
        self.assertEqual(len(hosts), 2)
        self.assertTrue(all(host.name.startswith('Device at ') for host in hosts))

    def test_scan_identifies_only_live_hosts(self):
        scanner = HostScanner('eth0', [IP, '192.0.2.23'])
        scanner.identifier = Mock()
        scanner.identifier.identify.return_value = 'Office PC'
        with patch.object(scanner, '_sweep', side_effect=lambda ip: Host(ip, MAC, '') if ip == IP else None):
            hosts = scanner.scan()
        self.assertEqual([host.name for host in hosts], ['Office PC'])
        scanner.identifier.identify.assert_called_once_with(IP, MAC)

    def test_reconnect_preserves_name_without_identification(self):
        scanner = HostScanner('eth0', ['192.0.2.23'])
        scanner.identifier = Mock()
        old = Host(IP, MAC, 'Living Room TV')
        new = Host('192.0.2.23', MAC, '')
        with patch.object(scanner, '_sweep', return_value=new):
            changed = scanner.scan_for_reconnects([old])
        self.assertEqual(changed[old].name, 'Living Room TV')
        scanner.identifier.identify.assert_not_called()


if __name__ == '__main__':
    unittest.main()
