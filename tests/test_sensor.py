import unittest

from touchid_lab.codec import ProtocolError
from touchid_lab.sensor import (decode_sensor_report, decode_metadata,
    encode_capture_buffer, decode_capture_buffer, encode_capture_identity,
    decode_capture_identity, encode_sensor_report, encode_calibration_info,
    decode_calibration_info, decode_feature_finger_state, command_mode_report_id)


class SensorTests(unittest.TestCase):
    def test_image_info_record_types_and_unaligned_offsets(self):
        import struct
        from touchid_lab import sensor as s
        raw=bytearray(306)
        struct.pack_into('<QQ',raw,0,0x1234,0x5678)
        raw[16:21]=bytes([10,11,12,13,1])
        struct.pack_into('<HBBH',raw,21,0x1234,0xaa,0xbb,0xccdd)
        raw[27:30]=bytes([1,2,3])
        struct.pack_into('<4I',raw,30,0x3f800000,0x80000000,0x7fc12345,0xdeadbeef)
        struct.pack_into('<4Q',raw,46,1,2,3,4)
        fields=s.decode_image_info_metadata(bytes(raw))
        self.assertEqual(fields['header_words'],(0x1234,0x5678))
        self.assertEqual(fields['header_bytes'],bytes([10,11,12,13,1]))
        record=fields['records'][0]
        self.assertEqual(record['word0'],0x1234)
        self.assertEqual(record['bytes6'],bytes([1,2,3]))
        self.assertEqual(record['float_bits'],(0x3f800000,0x80000000,0x7fc12345))
        self.assertEqual(record['word21'],0xdeadbeef)
        self.assertEqual(record['words25'],(1,2,3,4))
        self.assertEqual(s.encode_image_info_metadata(**fields),bytes(raw))
        self.assertEqual(len(s.active_image_info_records(bytes(raw))),1)

    def test_metadata_count_and_fixed_sensor_info_bounds(self):
        from touchid_lab import sensor as s
        raw=bytearray(306);raw[20]=6
        self.assertEqual(s.decode_image_info_metadata(bytes(raw))['header_bytes'][4],6)
        with self.assertRaises(ProtocolError):s.active_image_info_records(bytes(raw))
        self.assertEqual(s.decode_device_info(bytes(range(91))),dict(opaque=bytes(range(91))))
        self.assertEqual(s.encode_device_info(bytes(range(91))),bytes(range(91)))
        for data in [bytes(90),bytes(92)]:
            with self.assertRaises(ProtocolError):s.decode_device_info(data)
        for data in [bytes(305),bytes(307)]:
            with self.assertRaises(ProtocolError):s.decode_image_info_metadata(data)

    def test_error_requires_six_bytes_despite_only_reading_four(self):
        with self.assertRaises(ProtocolError):
            decode_sensor_report(bytes.fromhex('b478563412'))
        result = decode_sensor_report(bytes.fromhex('b478563412abff'))
        self.assertEqual(result['code'], 0x12345678)
        self.assertEqual(result['reserved'], b'\xab')
        self.assertEqual(result['trailing'], b'\xff')

    def test_finger_state_preserves_unknown_eight_byte_field(self):
        raw = b'\xb5\x03' + bytes(range(8)) + b'X'
        result = decode_sensor_report(raw)
        self.assertEqual(result['state'], 3)
        self.assertEqual(result['opaque8'], bytes(range(8)))
        self.assertEqual(result['trailing'], b'X')

    def test_image_regions_match_independent_offsets(self):
        raw = bytearray(0x2a42)
        raw[0] = 0xb6
        raw[1] = 0x11
        raw[0x2a00] = 0x22
        raw[0x2a01:0x2a12] = bytes(range(17))
        raw[0x2a12:] = bytes(range(48))
        result = decode_sensor_report(bytes(raw))
        self.assertEqual(len(result['image_blob']), 10752)
        self.assertEqual(result['image_blob'][0], 0x11)
        self.assertEqual(result['image_blob'][-1], 0x22)
        self.assertEqual(result['opaque17'], bytes(range(17)))
        self.assertEqual(result['opaque48'], bytes(range(48)))

    def test_image_info_keeps_metadata_opaque(self):
        raw = b'\xb7\xff' + bytes(range(256)) + bytes(range(50))
        result = decode_sensor_report(raw)
        self.assertTrue(result['metadata_valid'])
        self.assertEqual(result['metadata'], raw[2:])
        self.assertFalse(decode_sensor_report(b'\xb7\x01' + bytes(306))['metadata_valid'])

    def test_all_report_minimum_lengths_and_unknown_ids(self):
        for report_id, size in [(0xb4,6),(0xb5,10),(0xb6,10818),(0xb7,308)]:
            with self.subTest(report_id=report_id), self.assertRaises(ProtocolError):
                decode_sensor_report(bytes([report_id]) + bytes(size-2))
        for data in [b'', b'\x00' + bytes(400)]:
            with self.assertRaises(ProtocolError):
                decode_sensor_report(data)

    def test_metadata_getters_follow_native_bit_mapping(self):
        for flags, state in [(0,1),(1,3),(2,4),(3,2)]:
            raw = bytes([flags | 8,0]) + bytes(range(8)) + b'\x99\x05ABCDE'
            result = decode_metadata(raw)
            self.assertEqual(result['button_state'], state)
            self.assertEqual(result['wake_on_menu_pin_used'], 8)
            self.assertEqual(result['capture_counter'], 4)
            self.assertEqual(result['opaque8'], bytes(range(8)))
        self.assertEqual(decode_metadata(bytes(17))['capture_counter'], 0)

    def test_capture_header_order_and_offsets(self):
        data = encode_capture_buffer(b'ABC',bytes(range(17)),b'XY')
        self.assertEqual(data[:12].hex(), '030000001100000002000000')
        self.assertEqual(data[12:15],b'ABC')
        self.assertEqual(data[15:32],bytes(range(17)))
        self.assertEqual(data[32:],b'XY')
        self.assertEqual(decode_capture_buffer(data),dict(image_blob=b'ABC',metadata=bytes(range(17)),extra=b'XY'))

    def test_capture_decoder_rejects_inconsistent_lengths(self):
        raw = bytes.fromhex('030000001100000002000000') + b'ABC' + bytes(17) + b'XY'
        for data in [raw[:-1],raw+b'X',raw[:4]+b'\x10\0\0\0'+raw[8:],b'\xff'*12]:
            with self.subTest(data=data[:12]), self.assertRaises(ProtocolError):
                decode_capture_buffer(data)
        with self.assertRaises(ProtocolError):encode_capture_buffer(b'',bytes(16),b'')

    def test_capture_identity_is_uid_then_metadata(self):
        raw = bytes(range(33))
        self.assertEqual(encode_capture_identity(raw[:16],raw[16:]),raw)
        self.assertEqual(decode_capture_identity(raw),dict(uid=raw[:16],metadata=raw[16:]))
        for data in [raw[:-1],raw+b'X']:
            with self.assertRaises(ProtocolError):decode_capture_identity(data)

    def test_sensor_encoder_reproduces_fixed_regions(self):
        raw=bytes.fromhex('b478563412abff')
        self.assertEqual(encode_sensor_report(0xb4,code=0x12345678,reserved=b'\xab',trailing=b'\xff'),raw)
        self.assertEqual(encode_sensor_report(0xb5,state=2,opaque8=bytes(range(8))),b'\xb5\x02'+bytes(range(8)))
        self.assertEqual(encode_sensor_report(0xb6,image_blob=b'A'*10752,opaque17=b'B'*17,opaque48=b'C'*48),b'\xb6'+b'A'*10752+b'B'*17+b'C'*48)
        self.assertEqual(encode_sensor_report(0xb7,marker=0xff,metadata=b'D'*306),b'\xb7\xff'+b'D'*306)
        with self.assertRaises(ProtocolError):encode_sensor_report(0xb6,image_blob=b'X',opaque17=bytes(17),opaque48=bytes(48))

    def test_calibration_info_is_two_words_without_report_id(self):
        raw=bytes.fromhex('7856341204030201')
        self.assertEqual(encode_calibration_info(0x12345678,0x01020304),raw)
        self.assertEqual(decode_calibration_info(raw),dict(status=0x12345678,total_length=0x01020304))
        for data in [raw[:-1],raw+b'X']:
            with self.assertRaises(ProtocolError):decode_calibration_info(data)

    def test_feature_finger_state_and_mode_id(self):
        for value in [0,1,255]:
            self.assertEqual(decode_feature_finger_state(bytes([value])),dict(raw_state=value,finger_present=value!=0))
        for mode in range(5):self.assertEqual(command_mode_report_id(mode),0x78+mode)
        for mode in [-1,5,256]:
            with self.assertRaises(ProtocolError):command_mode_report_id(mode)
        for data in [b'',bytes(2)]:
            with self.assertRaises(ProtocolError):decode_feature_finger_state(data)
