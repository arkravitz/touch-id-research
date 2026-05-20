import unittest
from touchid_lab.simulator import Exchange, ScriptedPeer, run_demo, TrustUnavailable
from touchid_lab.codec import ProtocolError


class SimulatorTests(unittest.TestCase):
    def test_unpair_feature_fixture_requires_and_validates_status(self):
        from touchid_lab.simulator import Exchange, ScriptedPeer
        from touchid_lab import codec as c
        peer=ScriptedPeer([Exchange('unpair',b'',c.encode_reply('unpair',status=0))])
        self.assertEqual(peer.exchange('unpair',b''),bytes(4))
        self.assertTrue(peer.complete)
        for reply in [None,c.encode_reply('unpair',status=1)]:
            peer=ScriptedPeer([Exchange('unpair',b'',reply)])
            with self.assertRaises(c.ProtocolError):peer.exchange('unpair',b'')
            self.assertEqual(peer.position,0)

    def test_literal_exchange_and_native_trust_stays_unavailable(self):
        peer=ScriptedPeer([Exchange('generate_key',bytes.fromhex('0100000002000000'),
              bytes.fromhex('470100000000000000')+b'K'*65)])
        reply=peer.exchange('generate_key',bytes.fromhex('0100000002000000'))
        self.assertEqual(reply[9:],b'K'*65)
        self.assertTrue(peer.complete)
        self.assertFalse(peer.native_compatible)
        with self.assertRaises(TrustUnavailable):peer.require_native_trust()
        with self.assertRaises(ProtocolError):peer.exchange('generate_key',bytes.fromhex('0100000002000000'))

    def test_wrong_request_does_not_consume_script(self):
        peer=ScriptedPeer([Exchange('generate_key',bytes.fromhex('0100000002000000'),
              bytes.fromhex('470100000000000000')+b'K'*65)])
        with self.assertRaises(ProtocolError):peer.exchange('public_key',bytes.fromhex('01000000'))
        self.assertEqual(peer.position,0)
        with self.assertRaises(ProtocolError):peer.exchange('generate_key',bytes.fromhex('0200000002000000'))
        self.assertEqual(peer.position,0)

    def test_stale_wrong_report_and_rejection_cannot_advance(self):
        req=bytes.fromhex('0100000002000000')
        for header in ['470000000000000000','400100000000000000','470100000001000000']:
            peer=ScriptedPeer([Exchange('generate_key',req,bytes.fromhex(header)+b'K'*65)])
            with self.subTest(header=header),self.assertRaises(ProtocolError):peer.exchange('generate_key',req)
            self.assertEqual(peer.position,0)

    def test_demo_covers_recovered_phases_but_is_not_attestation(self):
        result=run_demo('all')
        self.assertFalse(result['native_compatible'])
        self.assertEqual(result['provenance'],'synthetic fixtures')
        operations={row['operation'] for row in result['exchanges']}
        self.assertTrue({'protocol_info','select_protocol','uid','public_key','query_pairing',
            'generate_key','transfer','pair_prepare','pair','manifest','compute_session',
            'issue_challenge','verify_challenge','start_intent','secure_intent_nonce','cancel'}<=operations)
        self.assertEqual(result['trust_gate'],'unavailable: enclave attestation is not implemented')
        self.assertTrue(all(row['validated'] for row in result['exchanges']))
