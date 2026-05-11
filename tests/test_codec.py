import struct
import unittest
from touchid_lab import codec as c


class CodecTests(unittest.TestCase):
    def test_unpair_feature_reply_has_status_without_interrupt_header(self):
        self.assertEqual(c.encode_reply('unpair',status=0x12345678),bytes.fromhex('78563412'))
        self.assertEqual(c.decode_reply('unpair',bytes.fromhex('78563412')),{'status':0x12345678})
        for data in [b'',bytes(3),bytes(5)]:
            with self.assertRaises(c.ProtocolError):c.decode_reply('unpair',data)

    def test_host_header_golden_bytes(self):
        obj = c.HostCommand(0x1234, 2, 0xabcd, b'\xde\xad')
        self.assertEqual(obj.encode().hex(), '544134120200cdabdead')
        self.assertEqual(c.HostCommand.decode(bytes.fromhex('544134120200cdabdead')), obj)

    def test_host_rejects_bad_magic_truncation_and_overflow(self):
        for data in [b'', b'TA\0', bytes.fromhex('000034120200cdab')]:
            with self.subTest(data=data), self.assertRaises(c.ProtocolError):
                c.HostCommand.decode(data)
        for n in [-1, 65536]:
            with self.assertRaises(c.ProtocolError):
                c.HostCommand(n, 1, 0).encode()

    def test_host_native_buffer_padding_and_size(self):
        obj=c.HostCommand(1,1,0,b'ABC')
        data=obj.encode(buffer_size=16384)
        self.assertEqual(len(data),16384)
        self.assertEqual(data[:11].hex(),'5441010001000000414243')
        self.assertEqual(data[11:],bytes(16373))
        self.assertEqual(c.HostCommand.decode(data,payload_length=3),obj)
        with self.assertRaises(c.ProtocolError):obj.encode(buffer_size=10)
        with self.assertRaises(c.ProtocolError):c.HostCommand.decode(data,payload_length=16377)

    def test_protocol_discovery_and_unknown_version(self):
        self.assertEqual(c.encode_reply('protocol_info', version=1), b'TACP\1\0\0\0')
        self.assertEqual(c.decode_reply('protocol_info', b'TACP\3\0\0\0')['version'], 3)
        self.assertEqual(c.negotiate_version(b'TACP\3\0\0\0'), b'TACP\1\0\0\0')
        with self.assertRaises(c.ProtocolError):
            c.decode_reply('protocol_info', b'FAIL\1\0\0\0')

    def test_key_request_and_reply_have_different_framing(self):
        self.assertEqual(c.encode_request('generate_key', 0x12345678, key_type=2).hex(), '7856341202000000')
        reply = bytes.fromhex('477856341200000000') + bytes(range(65))
        decoded = c.decode_reply('generate_key', reply)
        self.assertEqual(decoded, dict(report_id=0x47, counter=0x12345678, status=0, key=bytes(range(65))))
        self.assertEqual(c.encode_reply('generate_key', **decoded), reply)

    def test_query_pairing_is_flags_not_status(self):
        data = bytes.fromhex('4201000000010005')
        self.assertEqual(c.decode_reply('query_pairing', data), dict(report_id=0x42, counter=1, flag5=1, flag6=0, slots=5))
        request = c.encode_request('query_pairing', 1, identity=b'ABC')
        self.assertEqual(request[:11].hex(), '0100000003000000414243')
        self.assertEqual(len(request), 137)
        self.assertEqual(c.decode_request('query_pairing', request)['identity'], b'ABC')
        with self.assertRaises(c.ProtocolError):
            c.encode_request('query_pairing', 1, identity=b'x'*130)

    def test_identity_must_be_nonempty_and_pair_reply_exact_size(self):
        for name in ['query_pairing','pair_prepare','pair']:
            with self.subTest(name=name),self.assertRaises(c.ProtocolError):
                c.encode_request(name,1,identity=b'',key=b'K'*65)
        data=c.encode_reply('pair',counter=1,blob_a=b'A',blob_b=b'')
        with self.assertRaises(c.ProtocolError):c.decode_reply('pair',data+b'\0')

    def test_pair_key_offset_is_fixed_not_length_dependent(self):
        key = bytes(range(65))
        data = c.encode_request('pair', 4, identity=b'A', key=key)
        self.assertEqual(len(data), 202)
        self.assertEqual(data[:9].hex(), '040000000100000041')
        self.assertEqual(data[137:], key)
        self.assertEqual(c.decode_request('pair', data)['key'], key)

    def test_session_request_bounds_and_opaque_challenge(self):
        key = b'K'*65
        data = c.encode_request('compute_session', 7, key=key, challenge=b'XYZ')
        self.assertEqual(len(data), 329)
        self.assertEqual(data[69:76].hex(), '0300000058595a')
        self.assertEqual(c.decode_request('compute_session', data)['challenge'], b'XYZ')
        for n in [0,257]:
            with self.assertRaises(c.ProtocolError):
                c.encode_request('compute_session', 7, key=key, challenge=b'x'*n)
        self.assertEqual(len(c.encode_request('compute_session', 7, key=key, challenge=b'x'*256)), 329)

    def test_pair_reply_uses_reserved_regions_and_rejects_truncation(self):
        data = c.encode_reply('pair', counter=9, status=0, blob_a=b'A', blob_b=b'BC')
        self.assertEqual(len(data), 0xe11)
        self.assertEqual(data[:14].hex(), '4309000000000000000100000041')
        self.assertEqual(data[0x60d:0x613].hex(), '020000004243')
        self.assertEqual(c.decode_reply('pair', data)['blob_b'], b'BC')
        for n in [0,1537]:
            with self.assertRaises(c.ProtocolError):
                c.encode_reply('pair', counter=9, blob_a=b'x'*n, blob_b=b'')
        with self.assertRaises(c.ProtocolError):
            c.decode_reply('pair', data[:-1])
        corrupt=bytearray(data);struct.pack_into('<I',corrupt,9,0xffffffff)
        with self.assertRaises(c.ProtocolError):
            c.decode_reply('pair', corrupt)

    def test_manifest_maximum_and_trailing_transport_padding(self):
        self.assertEqual(c.encode_reply('manifest', manifest=b'ABC').hex(), '03000000414243')
        self.assertEqual(c.decode_reply('manifest', bytes.fromhex('030000004142430000'))['manifest'], b'ABC')
        self.assertEqual(len(c.encode_reply('manifest', manifest=b'x'*2560)),2564)
        with self.assertRaises(c.ProtocolError):
            c.encode_reply('manifest', manifest=b'x'*2561)
        with self.assertRaises(c.ProtocolError):
            c.decode_reply('manifest', b'\x10\0\0\0short')

    def test_transfer_chunk_boundaries_and_same_counter(self):
        chunks=c.transfer_chunks(8,2,b'a'*513)
        self.assertEqual(len(chunks),2)
        self.assertEqual(chunks[0][:20].hex(),'0800000002000000010200000000000000020000')
        self.assertEqual(chunks[1][:20].hex(),'0800000002000000010200000002000001000000')
        self.assertEqual(len(chunks[1]),532)
        self.assertEqual(c.reassemble_transfer(chunks),b'a'*513)
        with self.assertRaises(c.ProtocolError):c.reassemble_transfer(chunks[::-1])
        with self.assertRaises(c.ProtocolError):c.reassemble_transfer(chunks[:1])
        with self.assertRaises(c.ProtocolError):c.reassemble_transfer(chunks+chunks[-1:])
        with self.assertRaises(c.ProtocolError):c.transfer_chunks(8,0,b'a')

    def test_no_counter_on_secure_intent_nonce(self):
        data=c.encode_request('secure_intent_nonce',nonce=b'n'*48)
        self.assertEqual(data,b'n'*48)
        self.assertEqual(c.encode_request('start_intent',3).hex(),'030000000100000001000000')
        self.assertEqual(c.encode_request('cancel',3).hex(),'030000000000000000000000')

    def test_sep_manifest_and_pair_completion_offsets(self):
        uid=bytes(range(16));key=b'k'*65
        data=c.encode_sep_manifest(uid,True,b'ABC')
        self.assertEqual(data.hex(),'000102030405060708090a0b0c0d0e0f0103000000414243')
        self.assertEqual(c.decode_sep_manifest(data),dict(uid=uid,flag=True,manifest=b'ABC'))
        data=c.encode_sep_pair_completion(uid,key,b'A',b'BC')
        self.assertEqual(data[0x51:0x56].hex(),'0100000041')
        self.assertEqual(data[0x655:].hex(),'020000004243')
        self.assertEqual(c.decode_sep_pair_completion(data)['blob_b'],b'BC')

    def test_unknown_operation_and_wrong_reply_id_fail(self):
        with self.assertRaises(c.ProtocolError):c.encode_request('imaginary',1)
        with self.assertRaises(c.ProtocolError):c.decode_reply('public_key',b'\x47'+bytes(73))
        for name in ['public_key','generate_key','query_pairing','pair','compute_session','verify_challenge']:
            with self.subTest(name=name),self.assertRaises(c.ProtocolError):c.decode_reply(name,b'')


if __name__=='__main__':unittest.main()
