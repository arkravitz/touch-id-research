"""Recovered stac session wrappers, with cryptographic contents left opaque.

Evidence: AppleTrustedAccessoryManager::establishSessionWithAccessory and
testSecureSessionWithAccessory. These routines never contact an enclave.
"""
from .codec import ProtocolError, _bytes, _fixed, _size, _u32, _read32, _bounded, _pad
from . import codec, intent


def encode_pair_begin(uid, static_key, pairing_key):
    """Transaction 3: UID16, static accessory key65, generated pairing key65."""
    return _fixed(uid,16)+_fixed(static_key,65)+_fixed(pairing_key,65)


def decode_pair_begin(data):
    data=_fixed(data,146)
    return dict(uid=data[:16],static_key=data[16:81],pairing_key=data[81:])


def encode_attestation_identity(identity, padding=None, trailing=b''):
    """Transaction 1 response's fixed identity region; contents stay opaque."""
    identity=_bounded(identity,129)
    return _u32(len(identity))+_pad(identity,129,padding)+_bytes(trailing)


def decode_attestation_identity(data):
    data=_bytes(data);_size(data,133,False);n=_read32(data)
    if n>129:raise ProtocolError('identity exceeds the modeled 129-byte region')
    return dict(identity=data[4:4+n],padding=data[4+n:133],trailing=data[133:])


def encode_authorization(authorization_type, uid, authorization, extra=b'', padding=None):
    """Transaction 0x14: same field offsets as extended host authorization."""
    authorization=_bounded(authorization,32);extra=_bounded(extra,0xffffffff)
    return (_u32(authorization_type)+_fixed(uid,16)+_u32(len(authorization))
            +_pad(authorization,32,padding)+_u32(len(extra))+extra)


def decode_authorization(data):
    data=_bytes(data);_size(data,60,False)
    n=_read32(data,20);extra_len=_read32(data,56)
    if n>32:raise ProtocolError('authorization exceeds reserved region')
    _size(data,60+extra_len)
    return dict(authorization_type=_read32(data),uid=data[4:20],authorization=data[24:24+n],
                padding=data[24+n:56],extra=data[60:])


def encode_session_begin(uid, key):
    """Transaction 6: UID16 + accessory session public-key-shaped bytes65."""
    return _fixed(uid,16)+_fixed(key,65)


def decode_session_begin(data):
    data=_fixed(data,81)
    return dict(uid=data[:16],key=data[16:])


def encode_session_material(key, challenge, trailing=b''):
    """Transaction 6 result: key65 + length32 + opaque variable challenge.

    This wrapper does not enforce computeSessionKey's later 1..256 bound.
    """
    challenge=_bounded(challenge,0xffffffff)
    return _fixed(key,65)+_u32(len(challenge))+challenge+_bytes(trailing)


def decode_session_material(data):
    data=_bytes(data);_size(data,69,False)
    n=_read32(data,65);_size(data,69+n,False)
    return dict(key=data[:65],challenge=data[69:69+n],trailing=data[69+n:])


def encode_session_completion(uid, blob, padding=None):
    """Transaction 7: UID16 + length32 + reserved opaque region1536."""
    blob=_bounded(blob,1536,1)
    return _fixed(uid,16)+_u32(len(blob))+_pad(blob,1536,padding,1)


def decode_session_completion(data):
    data=_fixed(data,1556)
    n=_read32(data,16)
    # Reuse the independent region bound rather than trusting a length field.
    blob=_bounded(data[20:20+n],1536,1)
    _size(blob,n)
    return dict(uid=data[:16],blob=blob,padding=data[20+n:])


def encode_challenge_validation(uid, challenge):
    """Transaction 0x0e: UID16 + opaque crypto_challenge_t60."""
    return _fixed(uid,16)+_fixed(challenge,60)


def decode_challenge_validation(data):
    data=_fixed(data,76)
    return dict(uid=data[:16],challenge=data[16:])


REQUEST_SHAPES={1:'empty',2:'uid',3:'pair_begin',4:'uid',5:'manifest',6:'session_begin',
                7:'session_completion',8:'uid',9:'presence',10:'empty',11:'empty',
                12:'empty',13:'uid',14:'challenge_validation',15:'word',16:'intent_start',
                17:'empty',18:'uid',19:'intent_detected',20:'authorization',21:'pair_completion',22:'uid'}


def _request_codecs():
    return {'pair_begin':(encode_pair_begin,decode_pair_begin),
            'manifest':(codec.encode_sep_manifest,codec.decode_sep_manifest),
            'session_begin':(encode_session_begin,decode_session_begin),
            'session_completion':(encode_session_completion,decode_session_completion),
            'challenge_validation':(encode_challenge_validation,decode_challenge_validation),
            'intent_start':(intent.encode_start_context,intent.decode_start_context),
            'intent_detected':(intent.encode_detected_intent,intent.decode_detected_intent),
            'authorization':(encode_authorization,decode_authorization),
            'pair_completion':(codec.encode_sep_pair_completion,codec.decode_sep_pair_completion)}


def encode_request(opcode, **fields):
    """Route the 22 statically observed stac inputs. Opcode stays external."""
    shape=REQUEST_SHAPES.get(opcode)
    if shape is None:raise ProtocolError('unknown stac request opcode')
    if shape=='empty':return b''
    if shape=='uid':return _fixed(fields['uid'],16)
    if shape=='word':return _u32(fields['value'])
    if shape=='presence':
        if not isinstance(fields['present'],bool):raise ProtocolError('present must be boolean')
        return _fixed(fields['uid'],16)+bytes([fields['present']])
    return _request_codecs()[shape][0](**fields)


def decode_request(opcode, data):
    shape=REQUEST_SHAPES.get(opcode)
    if shape is None:raise ProtocolError('unknown stac request opcode')
    data=_bytes(data)
    if shape=='empty':
        _size(data,0);return {}
    if shape=='uid':return dict(uid=_fixed(data,16))
    if shape=='word':return dict(value=_read32(_fixed(data,4)))
    if shape=='presence':
        data=_fixed(data,17)
        if data[16]>1:raise ProtocolError('noncanonical presence boolean')
        return dict(uid=data[:16],present=bool(data[16]))
    return _request_codecs()[shape][1](data)


def encode_response(opcode, **fields):
    """Only recovered output structures, never fabricated enclave status codes."""
    if opcode==1:return encode_attestation_identity(**fields)
    if opcode in (3,6):return encode_session_material(**fields)
    if opcode==2:
        return bytes([codec._uint(fields['flag0'],8),codec._uint(fields['flag1'],8)])+_bytes(fields.get('trailing',b''))
    if opcode in (13,18):
        key,size=('challenge',60) if opcode==13 else ('nonce',48)
        return _fixed(fields[key],size)+_bytes(fields.get('trailing',b''))
    raise ProtocolError('stac response layout is opaque or has no returned buffer')


def decode_response(opcode, data):
    data=_bytes(data)
    if opcode==1:return decode_attestation_identity(data)
    if opcode in (3,6):return decode_session_material(data)
    if opcode==2:
        _size(data,2,False)
        return dict(flag0=data[0],flag1=data[1],trailing=data[2:])
    if opcode in (13,18):
        key,size=('challenge',60) if opcode==13 else ('nonce',48)
        _size(data,size,False)
        return {key:data[:size],'trailing':data[size:]}
    raise ProtocolError('stac response layout is opaque or has no returned buffer')
