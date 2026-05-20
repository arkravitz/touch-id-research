import unittest

from touchid_lab import manager as m
from touchid_lab.codec import HostCommand, ProtocolError


class ManagerTests(unittest.TestCase):
    def test_find_accessories_result_is_count_and_uids(self):
        raw=bytes.fromhex('02000000')+bytes(range(32))
        self.assertEqual(m.encode_result('find_accessories',uids=[bytes(range(16)),bytes(range(16,32))]),raw)
        self.assertEqual(m.decode_result('find_accessories',raw),dict(uids=[bytes(range(16)),bytes(range(16,32))]))
        for data in [raw[:-1],raw+b'X',bytes.fromhex('ffffffff')+raw[4:]]:
            with self.assertRaises(ProtocolError):m.decode_result('find_accessories',data)

    def test_property_result_offsets_and_boundaries(self):
        raw=m.encode_result('get_property',property=7,data=b'ABC')
        self.assertEqual(len(raw),72)
        self.assertEqual(raw[:11].hex(),'0700000003000000414243')
        result=m.decode_result('get_property',raw)
        self.assertEqual(result,dict(property=7,data=b'ABC',padding=bytes(61)))
        self.assertEqual(m.encode_result('get_property',**result),raw)
        for data in [raw[:-1],raw[:4]+bytes.fromhex('41000000')+raw[8:]]:
            with self.assertRaises(ProtocolError):m.decode_result('get_property',data)

    def test_boolean_and_pairing_results_have_different_sizes(self):
        self.assertEqual(m.encode_result('is_connected',connected=True),b'\1')
        self.assertEqual(m.decode_result('is_connected',b'\1'),dict(connected=True))
        raw=bytes.fromhex('0100010005')
        self.assertEqual(m.encode_result('query_pairing',flags=raw),raw)
        self.assertEqual(m.decode_result('query_pairing',raw),dict(flags=raw))
        with self.assertRaises(ProtocolError):m.decode_result('query_pairing',raw[:-1])

    def test_command_inventory_and_version_gate(self):
        self.assertEqual(sorted(m.COMMANDS.values()),list(range(2,16)))
        raw=m.encode_command('test_session',uid=bytes(range(16)))
        self.assertEqual(raw[:8].hex(),'54410a0001000000')
        self.assertEqual(raw[8:],bytes(range(16)))
        self.assertEqual(m.decode_command(raw)['fields']['uid'],bytes(range(16)))
        for obj in [HostCommand(1,1,0),HostCommand(10,2,0,bytes(16))]:
            with self.assertRaises(ProtocolError):m.decode_command(obj.encode())

    def test_pair_input_has_opaque_prefix_and_length_at_52(self):
        raw=m.encode_payload('pair',uid=b'U'*16,opaque36=b'P'*36,blob=b'XYZ')
        self.assertEqual(raw,b'U'*16+b'P'*36+bytes.fromhex('03000000')+b'XYZ')
        self.assertEqual(m.decode_payload('pair',raw)['blob'],b'XYZ')
        with self.assertRaises(ProtocolError):m.decode_payload('pair',raw[:-1])

    def test_authorization_has_reserved_region_then_optional_blob(self):
        raw=m.encode_payload('authorize',authorization_type=3,uid=b'U'*16,authorization=b'AB',extra=b'XYZ')
        self.assertEqual(raw[:24],bytes.fromhex('03000000')+b'U'*16+bytes.fromhex('02000000'))
        self.assertEqual(raw[24:56],b'AB'+bytes(30))
        self.assertEqual(raw[56:],bytes.fromhex('03000000')+b'XYZ')
        fields=m.decode_payload('authorize',raw)
        self.assertEqual(fields['extra'],b'XYZ')
        self.assertEqual(m.encode_payload('authorize',**fields),raw)
        with self.assertRaises(ProtocolError):m.encode_payload('authorize',authorization_type=3,uid=bytes(16),authorization=bytes(33))

    def test_property_filter_records_are_72_bytes(self):
        records=[dict(property=7,data=b'ABC'),dict(property=9,data=b'XY')]
        raw=m.encode_payload('find_accessories',records=records)
        self.assertEqual(len(raw),148)
        self.assertEqual(raw[:15].hex(),'020000000700000003000000414243')
        self.assertEqual(raw[76:86].hex(),'09000000020000005859')
        decoded=m.decode_payload('find_accessories',raw)
        self.assertEqual([x['data'] for x in decoded['records']],[b'ABC',b'XY'])
        self.assertEqual(m.encode_payload('find_accessories',**decoded),raw)
        for data in [raw[:-1],bytes.fromhex('ffffffff')+raw[4:]]:
            with self.assertRaises(ProtocolError):m.decode_payload('find_accessories',data)

    def test_host_padding_is_preserved_without_becoming_field_data(self):
        raw=HostCommand(13,1,0,bytes(range(16))+bytes.fromhex('02000000')).encode(buffer_size=16384)
        decoded=m.decode_command(raw)
        self.assertEqual(decoded['fields']['input_type'],2)
        self.assertEqual(len(decoded['fields']['trailing']),16356)
        self.assertEqual(m.encode_command(decoded['operation'],in_value=decoded['in_value'],**decoded['fields']),raw)

    def test_fixed_uid_requests_and_value_fields_reject_truncation(self):
        for name in ['unpair','is_connected','query_pairing','test_session','enclave_16']:
            self.assertEqual(len(m.encode_payload(name,uid=bytes(16))),16)
            with self.assertRaises(ProtocolError):m.decode_payload(name,bytes(15))
        raw=m.encode_payload('get_property',uid=bytes(16),property=11)
        self.assertEqual(raw[-4:].hex(),'0b000000')
        with self.assertRaises(ProtocolError):m.decode_payload('get_property',raw[:-1])
