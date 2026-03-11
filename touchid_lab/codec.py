"""Recovered driver buffers; these are not Bluetooth wire packets.

Cryptographic fields are opaque. Encoders zero unused regions by default;
real driver scratch buffers may have different unused bytes. See PROTOCOL.md.
"""
from dataclasses import dataclass
import struct


class ProtocolError(ValueError):
    pass


class UnsupportedVersion(ProtocolError):
    pass


def _uint(n, bits=32):
    if not isinstance(n, int) or not 0 <= n < 1 << bits:
        raise ProtocolError(f'expected unsigned {bits}-bit integer, got {n!r}')
    return n


def _bytes(value):
    if not isinstance(value, (bytes, bytearray)):
        raise ProtocolError('expected bytes')
    return bytes(value)


def _size(data, n, exact=True):
    if len(data) < n or (exact and len(data) != n):
        raise ProtocolError(f'expected {"exactly" if exact else "at least"} {n} bytes, got {len(data)}')


def _fixed(data, n):
    data = _bytes(data)
    _size(data, n)
    return data


def _bounded(data, maximum, minimum=0):
    data = _bytes(data)
    if not minimum <= len(data) <= maximum:
        raise ProtocolError(f'length must be {minimum}..{maximum}, got {len(data)}')
    return data


def _pad(data, maximum, padding=None, minimum=0):
    data = _bounded(data, maximum, minimum)
    return data + (bytes(maximum-len(data)) if padding is None else _fixed(padding, maximum-len(data)))


def _u32(n):
    return struct.pack('<I', _uint(n))


def _read32(data, offset=0):
    _size(data, offset+4, False)
    return struct.unpack_from('<I', data, offset)[0]


def _region(data, length_offset, start, capacity, minimum=0):
    n = _read32(data, length_offset)
    if not minimum <= n <= capacity:
        raise ProtocolError(f'invalid region length {n}; expected {minimum}..{capacity}')
    _size(data, start+n, False)
    return data[start:start+n]


@dataclass(frozen=True)
class HostCommand:
    command: int
    version: int
    in_value: int
    payload: bytes = b''

    def encode(self, buffer_size=None):
        data = struct.pack('<4H', 0x4154, _uint(self.command,16), _uint(self.version,16),
                           _uint(self.in_value,16)) + _bytes(self.payload)
        if buffer_size is None:return data
        _uint(buffer_size,64)
        if buffer_size < len(data):raise ProtocolError('command exceeds buffer size')
        return data + bytes(buffer_size-len(data))

    @classmethod
    def decode(cls, data, payload_length=None):
        data = _bytes(data); _size(data,8,False)
        magic, command, version, value = struct.unpack_from('<4H',data)
        if magic != 0x4154:
            raise ProtocolError('invalid TA host command magic')
        if payload_length is None:payload_length=len(data)-8
        _uint(payload_length,64);_size(data,8+payload_length,False)
        return cls(command,version,value,data[8:8+payload_length])


# A feature GetReport returns a raw driver buffer, without the interrupt header.
GET_SIZES = {'protocol_info':8, 'uid':16, 'nonce':16, 'issue_challenge':60, 'unpair':4}
REQUEST_IDS = {'query_pairing':0x60, 'pair':0x61, 'compute_session':0x62,
               'verify_challenge':0x63, 'start_intent':0x64, 'cancel':0x64,
               'secure_intent_nonce':0x65, 'generate_key':0x66, 'public_key':0x67,
               'select_protocol':0x68, 'transfer':0x6a, 'pair_prepare':0x6b}
REPLY_IDS = {'public_key':0x40, 'query_pairing':0x42, 'pair':0x43,
             'compute_session':0x46, 'generate_key':0x47,
             'verify_challenge':0x49,'pair_prepare':0x49,'start_intent':0x49,'cancel':0x49}


def negotiate_version(data):
    # The observed driver checks nonzero advertisement, then unconditionally selects 1.
    decode_reply('protocol_info', data)
    return encode_request('select_protocol', version=1)


def encode_request(name, counter=None, **f):
    if name in GET_SIZES or name in ('manifest','unpair'):
        raise ProtocolError('GetReport has no recovered request body; use its report ID separately')
    if name == 'select_protocol':
        return b'TACP' + _u32(f.get('version',1))
    if name == 'secure_intent_nonce':
        return _fixed(f['nonce'],48)
    if name not in REQUEST_IDS:
        raise ProtocolError(f'unknown operation {name!r}')
    header = _u32(counter)
    if name == 'public_key':return header
    if name == 'generate_key':return header + _u32(f['key_type'])
    if name in ('query_pairing','pair_prepare','pair'):
        identity = _bounded(f['identity'],129,1)
        data = header + _u32(len(identity)) + _pad(identity,129,f.get('padding'))
        return data + (_fixed(f['key'],65) if name=='pair' else b'')
    if name == 'compute_session':
        challenge = _bounded(f['challenge'],256,1)
        return header+_fixed(f['key'],65)+_u32(len(challenge))+_pad(challenge,256,f.get('padding'),1)
    if name == 'verify_challenge':return header+_fixed(f['challenge'],60)
    if name in ('start_intent','cancel'):
        return header+_u32(1 if name=='start_intent' else 0)+_u32(1 if name=='start_intent' else 0)
    if name == 'transfer':
        kind = _uint(f['kind']); total = _uint(f['total']); offset = _uint(f['offset'])
        if kind not in (1,2):raise ProtocolError('observed transfer type must be 1 or 2')
        chunk = _bounded(f['chunk'],512,1)
        if total==0 or offset+len(chunk)>total:raise ProtocolError('chunk exceeds transfer')
        return header+_u32(kind)+_u32(total)+_u32(offset)+_u32(len(chunk))+_pad(chunk,512,f.get('padding'),1)
    raise ProtocolError(f'unmodeled request {name}')


def decode_request(name,data):
    data = _bytes(data)
    if name=='select_protocol':return decode_reply('protocol_info',data)
    if name=='secure_intent_nonce':return {'nonce':_fixed(data,48)}
    if name not in REQUEST_IDS:raise ProtocolError(f'unknown request {name}')
    sizes={'public_key':4,'generate_key':8,'query_pairing':137,'pair_prepare':137,'pair':202,
           'compute_session':329,'verify_challenge':64,'start_intent':12,'cancel':12,'transfer':532}
    _size(data,sizes[name]);out={'counter':_read32(data)}
    if name=='generate_key':out['key_type']=_read32(data,4)
    elif name in ('query_pairing','pair_prepare','pair'):
        identity=_region(data,4,8,129,1)
        out.update(identity=identity,padding=data[8+len(identity):137])
        if name=='pair':out['key']=data[137:202]
    elif name=='compute_session':
        ch=_region(data,69,73,256,1)
        out.update(key=data[4:69],challenge=ch,padding=data[73+len(ch):])
    elif name=='verify_challenge':out['challenge']=data[4:]
    elif name in ('start_intent','cancel'):
        if data[4:] != (b'\1\0\0\0' if name=='start_intent' else bytes(4))+(b'\1\0\0\0' if name=='start_intent' else bytes(4)):
            raise ProtocolError('unexpected secure-intent control fields')
    elif name=='transfer':
        kind,total,offset,n=struct.unpack_from('<4I',data,4)
        if kind not in (1,2) or not 1<=n<=512 or total==0 or offset+n>total:
            raise ProtocolError('invalid transfer chunk')
        out.update(kind=kind,total=total,offset=offset,chunk=data[20:20+n],padding=data[20+n:])
    return out


def encode_reply(name, counter=None, status=0, **f):
    if name=='unpair':return _u32(status)
    if name=='protocol_info':return b'TACP'+_u32(f['version'])
    if name in GET_SIZES:
        key={'uid':'uid','nonce':'nonce','issue_challenge':'challenge'}[name]
        return _fixed(f[key],GET_SIZES[name])
    if name=='manifest':
        data=_bounded(f['manifest'],2560)
        return _u32(len(data))+data+_bytes(f.get('padding',b''))
    if name not in REPLY_IDS:raise ProtocolError(f'unknown reply {name}')
    report_id=REPLY_IDS[name]
    if 'report_id' in f and f['report_id']!=report_id:raise ProtocolError('wrong reply report ID')
    header=struct.pack('<BI',report_id,_uint(counter))
    if name=='query_pairing':
        return header+bytes(_uint(f[k],8) for k in ('flag5','flag6','slots'))
    data=header+_u32(status)
    if name in ('public_key','generate_key'):return data+_fixed(f['key'],65)
    if name in ('pair','compute_session'):
        blob=_bounded(f['blob_a'],1536,0 if status else 1)
        data+=_u32(len(blob))+_pad(blob,1536,f.get('padding_a'))
        if name=='pair':
            other=_bounded(f['blob_b'],2048)
            data+=_u32(len(other))+_pad(other,2048,f.get('padding_b'))
    return data+_bytes(f.get('trailing',b''))


def decode_reply(name,data):
    data=_bytes(data)
    if name=='unpair':
        _size(data,4)
        return {'status':_read32(data)}
    if name=='protocol_info':
        _size(data,8)
        if data[:4]!=b'TACP' or _read32(data,4)==0:raise ProtocolError('invalid communication protocol descriptor')
        return {'version':_read32(data,4)}
    if name in GET_SIZES:
        key={'uid':'uid','nonce':'nonce','issue_challenge':'challenge'}[name]
        return {key:_fixed(data,GET_SIZES[name])}
    if name=='manifest':
        blob=_region(data,0,4,2560)
        return {'manifest':blob,'padding':data[4+len(blob):]} if len(data)>4+len(blob) else {'manifest':blob}
    if name not in REPLY_IDS:raise ProtocolError(f'unknown reply {name}')
    size=8 if name=='query_pairing' else 74 if name in ('public_key','generate_key') else 0xe11 if name=='pair' else 0x60d if name=='compute_session' else 9
    _size(data,size,name=='pair')
    if data[0]!=REPLY_IDS[name]:raise ProtocolError(f'wrong report ID for {name}: {data[0]:#x}')
    out={'report_id':data[0],'counter':_read32(data,1)}
    if name=='query_pairing':out.update(flag5=data[5],flag6=data[6],slots=data[7])
    else:
        out['status']=_read32(data,5)
        if name in ('public_key','generate_key'):out['key']=data[9:74]
        elif name in ('pair','compute_session'):
            blob=_region(data,9,13,1536,0 if out['status'] else 1)
            out.update(blob_a=blob,padding_a=data[13+len(blob):0x60d])
            if name=='pair':
                other=_region(data,0x60d,0x611,2048)
                out.update(blob_b=other,padding_b=data[0x611+len(other):0xe11])
    if len(data)>size:out['trailing']=data[size:]
    return out


def transfer_chunks(counter,kind,data):
    data=_bounded(data,0xffffffff,1)
    return [encode_request('transfer',counter,kind=kind,total=len(data),offset=i,chunk=data[i:i+512])
            for i in range(0,len(data),512)]


def reassemble_transfer(chunks):
    if not chunks:raise ProtocolError('empty transfer')
    output=bytearray();identity=None
    for raw in chunks:
        d=decode_request('transfer',raw);key=(d['counter'],d['kind'],d['total'])
        if identity is None:identity=key
        if key!=identity or d['offset']!=len(output):raise ProtocolError('mixed, duplicate, or out-of-order chunk')
        output.extend(d['chunk'])
    if len(output)!=identity[2]:raise ProtocolError('incomplete transfer')
    return bytes(output)


def encode_sep_manifest(uid,flag,manifest):
    if not isinstance(flag,bool):raise ProtocolError('manifest flag must be boolean')
    manifest=_bounded(manifest,2560)
    return _fixed(uid,16)+bytes([flag])+_u32(len(manifest))+manifest


def decode_sep_manifest(data):
    data=_bytes(data);_size(data,21,False)
    blob=_region(data,17,21,2560)
    _size(data,21+len(blob))
    if data[16]>1:raise ProtocolError('invalid boolean flag')
    return {'uid':data[:16],'flag':bool(data[16]),'manifest':blob}


def encode_sep_pair_completion(uid,key,blob_a,blob_b):
    blob_a=_bounded(blob_a,1536,1);blob_b=_bounded(blob_b,2048)
    return _fixed(uid,16)+_fixed(key,65)+_u32(len(blob_a))+_pad(blob_a,1536)+_u32(len(blob_b))+blob_b


def decode_sep_pair_completion(data):
    data=_bytes(data);_size(data,0x659,False)
    a=_region(data,0x51,0x55,1536,1);b=_region(data,0x655,0x659,2048)
    _size(data,0x659+len(b))
    return {'uid':data[:16],'key':data[16:81],'blob_a':a,'blob_b':b}
