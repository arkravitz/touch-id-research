import unittest

from touchid_lab.codec import ProtocolError
from touchid_lab import stac


class StacTests(unittest.TestCase):
    def test_generic_request_routes_all_observed_opcodes(self):
        uid=bytes(range(16))
        for opcode in [2,4,8,13,18,22]:
            self.assertEqual(stac.encode_request(opcode,uid=uid),uid)
            self.assertEqual(stac.decode_request(opcode,uid),dict(uid=uid))
        for opcode in [1,10,11,12,17]:
            self.assertEqual(stac.encode_request(opcode),b'')
            self.assertEqual(stac.decode_request(opcode,b''),{})
        self.assertEqual(stac.encode_request(9,uid=uid,present=True),uid+b'\1')
        self.assertEqual(stac.decode_request(9,uid+b'\0'),dict(uid=uid,present=False))
        self.assertEqual(stac.encode_request(15,value=1),bytes.fromhex('01000000'))
        self.assertEqual(stac.decode_request(15,bytes.fromhex('01000000')),dict(value=1))
        self.assertEqual(sorted(stac.REQUEST_SHAPES),list(range(1,23)))
        for opcode,data in [(0,b''),(23,b''),(2,bytes(15)),(1,b'X'),(9,uid+b'\2')]:
            with self.assertRaises(ProtocolError):stac.decode_request(opcode,data)

    def test_consumed_response_regions_retain_trailing_bytes(self):
        for opcode,size,field in [(13,60,'challenge'),(18,48,'nonce')]:
            raw=bytes(range(size))+b'PAD'
            fields=stac.decode_response(opcode,raw)
            self.assertEqual(fields,{field:bytes(range(size)),'trailing':b'PAD'})
            self.assertEqual(stac.encode_response(opcode,**fields),raw)
            with self.assertRaises(ProtocolError):stac.decode_response(opcode,raw[:size-1])
        self.assertEqual(stac.decode_response(2,b'\1\0PAD'),dict(flag0=1,flag1=0,trailing=b'PAD'))
        with self.assertRaises(ProtocolError):stac.decode_response(10,bytes(16))

    def test_pair_begin_orders_static_then_generated_accessory_keys(self):
        raw=bytes(range(146))
        self.assertEqual(stac.encode_pair_begin(raw[:16],raw[16:81],raw[81:]),raw)
        self.assertEqual(stac.decode_pair_begin(raw),dict(uid=raw[:16],static_key=raw[16:81],pairing_key=raw[81:]))
        with self.assertRaises(ProtocolError):stac.decode_pair_begin(raw[:-1])

    def test_attestation_identity_response_reserves_129_bytes(self):
        raw=stac.encode_attestation_identity(b'ABC')
        self.assertEqual(len(raw),133)
        self.assertEqual(raw[:7].hex(),'03000000414243')
        result=stac.decode_attestation_identity(raw)
        self.assertEqual(result,dict(identity=b'ABC',padding=bytes(126),trailing=b''))
        self.assertEqual(stac.encode_attestation_identity(**result),raw)
        for data in [raw[:-1],bytes.fromhex('82000000')+raw[4:]]:
            with self.assertRaises(ProtocolError):stac.decode_attestation_identity(data)

    def test_authorization_wrapper_matches_stac_offsets(self):
        raw=stac.encode_authorization(3,b'U'*16,b'AB',b'XYZ')
        self.assertEqual(raw[:24],bytes.fromhex('03000000')+b'U'*16+bytes.fromhex('02000000'))
        self.assertEqual(raw[24:56],b'AB'+bytes(30))
        self.assertEqual(raw[56:],bytes.fromhex('03000000')+b'XYZ')
        fields=stac.decode_authorization(raw)
        self.assertEqual(fields['authorization'],b'AB')
        self.assertEqual(stac.encode_authorization(**fields),raw)
        with self.assertRaises(ProtocolError):stac.decode_authorization(raw[:-1])

    def test_session_begin_is_uid_followed_by_accessory_key(self):
        raw=bytes(range(81))
        self.assertEqual(stac.encode_session_begin(raw[:16],raw[16:]),raw)
        self.assertEqual(stac.decode_session_begin(raw),dict(uid=raw[:16],key=raw[16:]))

    def test_session_material_length_at_unaligned_offset_65(self):
        raw=bytes(range(65))+bytes.fromhex('03000000')+b'ABC'+b'PAD'
        self.assertEqual(stac.decode_session_material(raw),dict(key=bytes(range(65)),challenge=b'ABC',trailing=b'PAD'))
        self.assertEqual(stac.encode_session_material(bytes(range(65)),b'ABC',trailing=b'PAD'),raw)
        with self.assertRaises(ProtocolError):stac.decode_session_material(raw[:71])

    def test_session_completion_has_fixed_1536_byte_region(self):
        raw=stac.encode_session_completion(bytes(range(16)),b'ABC')
        self.assertEqual(len(raw),1556)
        self.assertEqual(raw[:23],bytes(range(16))+bytes.fromhex('03000000')+b'ABC')
        self.assertEqual(raw[23:],bytes(1533))
        result=stac.decode_session_completion(raw)
        self.assertEqual(result,dict(uid=bytes(range(16)),blob=b'ABC',padding=bytes(1533)))
        self.assertEqual(stac.encode_session_completion(**result),raw)

    def test_completion_bounds_and_reserved_bytes(self):
        for n in [0,1537]:
            with self.assertRaises(ProtocolError):stac.encode_session_completion(bytes(16),bytes(n))
        raw=stac.encode_session_completion(bytes(16),b'X',padding=b'P'*1535)
        self.assertEqual(stac.decode_session_completion(raw)['padding'],b'P'*1535)
        for data in [raw[:-1],raw+b'X',raw[:16]+bytes.fromhex('01060000')+raw[20:]]:
            with self.assertRaises(ProtocolError):stac.decode_session_completion(data)

    def test_challenge_validation_request_is_uid_and_sixty_bytes(self):
        raw=bytes(range(76))
        self.assertEqual(stac.encode_challenge_validation(raw[:16],raw[16:]),raw)
        self.assertEqual(stac.decode_challenge_validation(raw),dict(uid=raw[:16],challenge=raw[16:]))

    def test_all_fixed_inputs_reject_wrong_sizes(self):
        for fn,size in [(stac.decode_session_begin,81),(stac.decode_challenge_validation,76)]:
            for n in [size-1,size+1]:
                with self.assertRaises(ProtocolError):fn(bytes(n))
