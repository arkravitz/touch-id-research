import unittest
from touchid_lab import intent
from touchid_lab.codec import HostCommand, ProtocolError


class IntentTests(unittest.TestCase):
    def test_start_operation_offsets_and_padding(self):
        raw=intent.encode_start_command(operation_type=3,context=b'ABC',flag40=255)
        self.assertEqual(raw[:16].hex(),'54410100010000000300000003000000')
        self.assertEqual(raw[16:48],b'ABC'+bytes(29))
        self.assertEqual(raw[48:],b'\xff')
        result=intent.decode_operation(1,raw)
        self.assertEqual(result['fields']['flag40'],255)
        self.assertEqual(result['fields']['context'],b'ABC')

    def test_stac_start_zeros_unused_context_and_excludes_flag(self):
        host=intent.encode_start_command(operation_type=7,context=b'ABC',padding=b'P'*29,flag40=1)
        decoded=intent.decode_operation(1,host)['fields']
        stac=intent.encode_start_context(decoded['operation_type'],decoded['context'])
        self.assertEqual(stac,bytes.fromhex('0700000003000000')+b'ABC'+bytes(29))
        self.assertEqual(len(stac),40)
        self.assertEqual(intent.decode_start_context(stac)['context'],b'ABC')

    def test_cancel_selector_does_not_restrict_header_command(self):
        for command in [0,1,65535]:
            raw=intent.encode_cancel_command(command,payload=b'XYZ')
            self.assertEqual(intent.decode_operation(2,raw),dict(selector=2,command=command,in_value=0,payload=b'XYZ'))
        for selector,data in [(0,bytes(8)),(1,HostCommand(2,1,0,bytes(41)).encode()),(2,HostCommand(1,2,0).encode())]:
            with self.assertRaises(ProtocolError):intent.decode_operation(selector,data)

    def test_context_bounds_and_truncated_operation(self):
        for n in [0,32]:
            self.assertEqual(len(intent.encode_start_command(operation_type=0,context=bytes(n))),49)
        with self.assertRaises(ProtocolError):intent.encode_start_command(operation_type=0,context=bytes(33))
        for payload in [bytes(40),bytes(4)+bytes.fromhex('21000000')+bytes(33)]:
            with self.assertRaises(ProtocolError):intent.decode_operation(1,HostCommand(1,1,0,payload).encode())

    def test_detected_intent_wrapper_is_uid_and_opaque48(self):
        raw=bytes(range(64))
        self.assertEqual(intent.encode_detected_intent(raw[:16],raw[16:]),raw)
        self.assertEqual(intent.decode_detected_intent(raw),dict(uid=raw[:16],intent=raw[16:]))
        with self.assertRaises(ProtocolError):intent.decode_detected_intent(raw[:-1])

    def test_notification_bodies_preserve_unknown_status_tail(self):
        raw=bytes.fromhex('04000000')+b'P'*12
        self.assertEqual(intent.decode_notification_body(1,raw),dict(status=4,reserved=b'P'*12))
        self.assertEqual(intent.encode_notification_body(1,status=4,reserved=b'P'*12),raw)
        uid=bytes(range(16))
        self.assertEqual(intent.decode_notification_body(2,uid),dict(uid=uid))
        self.assertEqual(intent.encode_notification_body(2,uid=uid),uid)
        for notification_id,data in [(1,raw[:-1]),(2,uid+b'X'),(3,uid)]:
            with self.assertRaises(ProtocolError):intent.decode_notification_body(notification_id,data)
