"""Command-line offline packet encoder, decoder, and transcript simulator."""
import argparse
import json
import sys
from . import codec as c
from . import sensor as s
from . import stac
from . import manager
from . import intent
from .simulator import run_demo

BYTE_FIELDS={'payload','identity','key','challenge','nonce','uid','manifest','blob_a','blob_b',
             'chunk','padding','padding_a','padding_b','trailing','image_blob',
             'metadata','extra','opaque8','opaque17','opaque48','reserved','blob',
             'opaque36','authorization','data','context','intent','flags',
             'opaque','header_bytes','bytes6'}

SEP_ENCODERS={'manifest':c.encode_sep_manifest,'pair_completion':c.encode_sep_pair_completion,
              'pair_begin':stac.encode_pair_begin,'pair_material':stac.encode_session_material,
              'attestation_identity':stac.encode_attestation_identity,'authorization':stac.encode_authorization,
              'session_begin':stac.encode_session_begin,'session_material':stac.encode_session_material,
              'session_completion':stac.encode_session_completion,
              'challenge_validation':stac.encode_challenge_validation,
              'intent_start':intent.encode_start_context,'intent_detected':intent.encode_detected_intent}
SEP_DECODERS={'manifest':c.decode_sep_manifest,'pair_completion':c.decode_sep_pair_completion,
              'pair_begin':stac.decode_pair_begin,'pair_material':stac.decode_session_material,
              'attestation_identity':stac.decode_attestation_identity,'authorization':stac.decode_authorization,
              'session_begin':stac.decode_session_begin,'session_material':stac.decode_session_material,
              'session_completion':stac.decode_session_completion,
              'challenge_validation':stac.decode_challenge_validation,
              'intent_start':intent.decode_start_context,'intent_detected':intent.decode_detected_intent}


def byte_fields(value):
    if isinstance(value,list):return [byte_fields(v) for v in value]
    if isinstance(value,dict):
        return {k:bytes.fromhex(v) if k in BYTE_FIELDS else
                [bytes.fromhex(item) for item in v] if k=='uids' else byte_fields(v)
                for k,v in value.items()}
    return value


def json_ready(value):
    if isinstance(value,bytes):return value.hex()
    if isinstance(value,dict):return {k:json_ready(v) for k,v in value.items()}
    if isinstance(value,(list,tuple)):return [json_ready(v) for v in value]
    return value


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='command',required=True)
    for verb in ('encode','decode'):
        q=sub.add_parser(verb)
        q.add_argument('layer',choices=['host','request','reply','sep','sensor','manager',
                                     'operation','notification','manager_result','stac_request','stac_response'])
        q.add_argument('operation',help='operation name; sensor: report, metadata (decode only), capture, capture_identity')
        q.add_argument('value',help='JSON object for encode (byte fields are hex); hexadecimal bytes for decode')
    q=sub.add_parser('demo');q.add_argument('--scenario',choices=['all','pairing','session','intent'],default='all')
    a=p.parse_args(argv)
    try:
        if a.command=='demo':result=run_demo(a.scenario)
        elif a.command=='encode':
            fields=json.loads(a.value)
            if not isinstance(fields,dict):raise c.ProtocolError('encode expects a JSON object')
            fields=byte_fields(fields)
            if a.layer=='host':
                buffer_size=fields.pop('buffer_size',None)
                data=c.HostCommand(**fields).encode(buffer_size=buffer_size)
            elif a.layer=='request':data=c.encode_request(a.operation,**fields)
            elif a.layer=='reply':data=c.encode_reply(a.operation,**fields)
            elif a.layer=='manager':data=manager.encode_command(a.operation,**fields)
            elif a.layer=='manager_result':data=manager.encode_result(a.operation,**fields)
            elif a.layer=='stac_request':data=stac.encode_request(int(a.operation,0),**fields)
            elif a.layer=='stac_response':data=stac.encode_response(int(a.operation,0),**fields)
            elif a.layer=='notification':data=intent.encode_notification_body(int(a.operation),**fields)
            elif a.layer=='operation':
                if a.operation=='start':data=intent.encode_start_command(**fields)
                elif a.operation=='cancel':data=intent.encode_cancel_command(**fields)
                else:raise c.ProtocolError('operation must be start or cancel')
            elif a.layer=='sensor':
                encoders={'report':s.encode_sensor_report,'capture':s.encode_capture_buffer,
                          'capture_identity':s.encode_capture_identity,
                          'calibration_info':s.encode_calibration_info,
                          'device_info':s.encode_device_info,
                          'image_info':s.encode_image_info_metadata}
                if a.operation not in encoders:raise c.ProtocolError('unknown sensor encoder')
                data=encoders[a.operation](**fields)
            elif a.operation in SEP_ENCODERS:data=SEP_ENCODERS[a.operation](**fields)
            else:raise c.ProtocolError('unknown SEP wrapper')
            result={'hex':data.hex(),'length':len(data),'scope':'driver buffer; Bluetooth encapsulation unverified'}
        else:
            data=bytes.fromhex(a.value)
            if a.layer=='host':result=vars(c.HostCommand.decode(data))
            elif a.layer=='request':result=c.decode_request(a.operation,data)
            elif a.layer=='reply':result=c.decode_reply(a.operation,data)
            elif a.layer=='manager':result=manager.decode_command(data)
            elif a.layer=='manager_result':result=manager.decode_result(a.operation,data)
            elif a.layer=='stac_request':result=stac.decode_request(int(a.operation,0),data)
            elif a.layer=='stac_response':result=stac.decode_response(int(a.operation,0),data)
            elif a.layer=='notification':result=intent.decode_notification_body(int(a.operation),data)
            elif a.layer=='operation':
                if a.operation not in ('start','cancel'):raise c.ProtocolError('operation must be start or cancel')
                result=intent.decode_operation(1 if a.operation=='start' else 2,data)
            elif a.layer=='sensor':
                decoders={'report':s.decode_sensor_report,'metadata':s.decode_metadata,
                          'capture':s.decode_capture_buffer,'capture_identity':s.decode_capture_identity}
                decoders.update(calibration_info=s.decode_calibration_info,
                                feature_finger_state=s.decode_feature_finger_state,
                                device_info=s.decode_device_info,
                                image_info=s.decode_image_info_metadata)
                if a.operation not in decoders:raise c.ProtocolError('unknown sensor decoder')
                result=decoders[a.operation](data)
            elif a.operation in SEP_DECODERS:result=SEP_DECODERS[a.operation](data)
            else:raise c.ProtocolError('unknown SEP wrapper')
        print(json.dumps(json_ready(result),indent=2));return 0
    except (ValueError,TypeError,KeyError) as exc:
        print(f'error: {exc}',file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
