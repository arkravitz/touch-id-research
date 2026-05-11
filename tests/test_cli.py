import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]


class CLITests(unittest.TestCase):
    def call(self,*args):
        return subprocess.run([sys.executable,'-m','touchid_lab',*args],cwd=ROOT,capture_output=True,text=True)

    def test_typed_image_metadata_and_device_info(self):
        raw='00'*306
        p=self.call('decode','sensor','image_info',raw)
        self.assertEqual(p.returncode,0,p.stderr)
        fields=json.loads(p.stdout)
        self.assertEqual(len(fields['records']),5)
        self.assertEqual(fields['records'][0]['float_bits'],[0,0,0])
        p=self.call('encode','sensor','image_info',json.dumps(fields))
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['hex'],raw)
        p=self.call('encode','sensor','device_info',json.dumps({'opaque':'ab'*91}))
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['hex'],'ab'*91)
        p=self.call('decode','sensor','device_info','ab'*90)
        self.assertEqual(p.returncode,2)

    def test_encode_and_decode_literal_request(self):
        p=self.call('encode','request','generate_key','{"counter":1,"key_type":2}')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['hex'],'0100000002000000')
        p=self.call('decode','reply','query_pairing','4201000000010005')
        self.assertEqual(json.loads(p.stdout)['slots'],5)

    def test_invalid_input_returns_error_without_traceback(self):
        for args in [('decode','reply','pair','zz'),('encode','request','generate_key','{}')]:
            p=self.call(*args)
            self.assertEqual(p.returncode,2)
            self.assertNotIn('Traceback',p.stderr)

    def test_demo_reports_scope(self):
        p=self.call('demo','--scenario','all')
        self.assertEqual(p.returncode,0,p.stderr)
        result=json.loads(p.stdout)
        self.assertFalse(result['native_compatible'])
        self.assertGreater(len(result['exchanges']),15)

    def test_sensor_report_and_capture_commands(self):
        p=self.call('decode','sensor','report','b5020001020304050607')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['opaque8'],'0001020304050607')
        p=self.call('encode','sensor','capture','{"image_blob":"414243","metadata":"0000000000000000000000000000000000","extra":"5859"}')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['hex'],'030000001100000002000000414243'+'00'*17+'5859')
        p=self.call('encode','sensor','report','{"report_id":181,"state":1,"opaque8":"0001020304050607"}')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['hex'],'b5010001020304050607')

    def test_manager_and_stac_wrappers_are_accessible_offline(self):
        p=self.call('encode','manager','find_accessories','{"records":[{"property":7,"data":"414243"}]}')
        self.assertEqual(p.returncode,0,p.stderr)
        raw=json.loads(p.stdout)['hex']
        self.assertEqual(raw[:16],'5441090001000000')
        p=self.call('decode','manager','command',raw)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['fields']['records'][0]['data'],'414243')
        p=self.call('encode','sep','session_begin','{"uid":"'+'00'*16+'","key":"'+'11'*65+'"}')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['length'],81)

    def test_intent_operations_and_notification_bodies(self):
        p=self.call('encode','operation','start','{"operation_type":3,"context":"414243","flag40":1}')
        self.assertEqual(p.returncode,0,p.stderr)
        raw=json.loads(p.stdout)['hex']
        self.assertEqual(len(raw),98)
        p=self.call('decode','operation','start',raw)
        self.assertEqual(json.loads(p.stdout)['fields']['context'],'414243')
        p=self.call('decode','notification','1','04000000'+'00'*12)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['status'],4)
        p=self.call('encode','manager_result','find_accessories','{"uids":["'+'11'*16+'"]}')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['hex'],'01000000'+'11'*16)

    def test_stac_numeric_namespace_keeps_opcode_outside_buffer(self):
        p=self.call('encode','stac_request','0x13','{"uid":"'+'11'*16+'","intent":"'+'22'*48+'"}')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['hex'],'11'*16+'22'*48)
        p=self.call('decode','stac_response','0x2','0100')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['flag0'],1)
