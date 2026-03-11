"""Offline manager payloads from performCommand's commands 2..15.

No methods here connect to IOKit. Names with numbers retain unresolved meaning.
Decoders retain surplus bytes, including the native serializer's allocation
padding, rather than treating them as additional semantic payload.
"""
from .codec import (HostCommand, ProtocolError, _bytes, _fixed, _bounded,
                    _pad, _size, _u32, _read32)

COMMANDS={'enclave_0b':2,'enclave_0a':3,'pair':4,'unpair':5,'unpair_all':6,
          'is_connected':7,'query_pairing':8,'find_accessories':9,'test_session':10,
          'authorize':11,'get_property':12,'inject_input':13,'command_14':14,
          'enclave_16':15}
UID_ONLY={'unpair','is_connected','query_pairing','test_session','enclave_16'}
NO_FIELDS={'enclave_0b','enclave_0a','unpair_all','command_14'}


def encode_payload(name, *, trailing=b'', **f):
    if name not in COMMANDS:
        raise ProtocolError('unknown manager command')
    if name in NO_FIELDS:
        data=b''
    elif name in UID_ONLY:
        data=_fixed(f['uid'],16)
    elif name in ('get_property','inject_input'):
        field='property' if name=='get_property' else 'input_type'
        data=_fixed(f['uid'],16)+_u32(f[field])
    elif name=='pair':
        blob=_bounded(f['blob'],0xffffffff)
        data=_fixed(f['uid'],16)+_fixed(f['opaque36'],36)+_u32(len(blob))+blob
    elif name=='authorize':
        authorization=_bounded(f['authorization'],32)
        extra=_bounded(f.get('extra',b''),0xffffffff)
        data=(_u32(f['authorization_type'])+_fixed(f['uid'],16)
              +_u32(len(authorization))+_pad(authorization,32,f.get('padding')))
        # Native accepts the old 56-byte form without the optional field.
        if f.get('extended',True):
            data+=_u32(len(extra))+extra
        elif extra:
            raise ProtocolError('extra bytes require extended authorization form')
    else:
        records=f['records'];data=_u32(len(records))
        parts=[data]
        for record in records:
            item=_bounded(record['data'],64)
            parts.append(_u32(record['property'])+_u32(len(item))+_pad(item,64,record.get('padding')))
        data=b''.join(parts)
    return data+_bytes(trailing)


def decode_payload(name, data):
    data=_bytes(data)
    if name not in COMMANDS:
        raise ProtocolError('unknown manager command')
    out={};used=0
    if name in UID_ONLY or name in ('get_property','inject_input','pair'):
        _size(data,16,False);out['uid']=data[:16];used=16
        if name in ('get_property','inject_input'):
            field='property' if name=='get_property' else 'input_type'
            out[field]=_read32(data,16);used=20
        elif name=='pair':
            _size(data,56,False);n=_read32(data,52);_size(data,56+n,False)
            out.update(opaque36=data[16:52],blob=data[56:56+n]);used=56+n
    elif name=='authorize':
        _size(data,56,False);n=_read32(data,20)
        if n>32:raise ProtocolError('authorization exceeds reserved region')
        out.update(authorization_type=_read32(data),uid=data[4:20],
                   authorization=data[24:24+n],padding=data[24+n:56],extra=b'',extended=len(data)>=60)
        used=56
        if out['extended']:
            extra_len=_read32(data,56);_size(data,60+extra_len,False)
            out['extra']=data[60:60+extra_len];used=60+extra_len
    elif name=='find_accessories':
        n=_read32(data);_size(data,4+72*n,False);out['records']=[]
        for offset in range(4,4+72*n,72):
            length=_read32(data,offset+4)
            if length>64:raise ProtocolError('filter data exceeds reserved region')
            out['records'].append(dict(property=_read32(data,offset),data=data[offset+8:offset+8+length],
                                       padding=data[offset+8+length:offset+72]))
        used=4+72*n
    out['trailing']=data[used:]
    return out


def encode_command(name, *, version=1, in_value=0, **fields):
    if version!=1:raise ProtocolError('observed manager commands require version 1')
    if name not in COMMANDS:raise ProtocolError('unknown manager command')
    return HostCommand(COMMANDS[name],version,in_value,encode_payload(name,**fields)).encode()


def decode_command(data):
    command=HostCommand.decode(data)
    names={value:key for key,value in COMMANDS.items()}
    if command.version!=1 or command.command not in names:
        raise ProtocolError('unsupported manager command or version')
    name=names[command.command]
    return dict(operation=name,in_value=command.in_value,fields=decode_payload(name,command.payload))


def encode_result(name, **fields):
    """Recovered successful command outputs, without a host command header."""
    if name=='is_connected':
        if not isinstance(fields['connected'],bool):raise ProtocolError('connected must be boolean')
        return bytes([fields['connected']])
    if name=='query_pairing':return _fixed(fields['flags'],5)
    if name=='get_property':
        data=_bounded(fields['data'],64)
        return _u32(fields['property'])+_u32(len(data))+_pad(data,64,fields.get('padding'))
    if name=='find_accessories':
        uids=fields['uids']
        return _u32(len(uids))+b''.join(_fixed(uid,16) for uid in uids)
    raise ProtocolError('manager result layout is not modeled')


def decode_result(name, data):
    data=_bytes(data)
    if name=='is_connected':
        data=_fixed(data,1)
        if data[0]>1:raise ProtocolError('noncanonical connected boolean')
        return dict(connected=bool(data[0]))
    if name=='query_pairing':return dict(flags=_fixed(data,5))
    if name=='get_property':
        data=_fixed(data,72);n=_read32(data,4)
        if n>64:raise ProtocolError('property result length exceeds reserved region')
        return dict(property=_read32(data),data=data[8:8+n],padding=data[8+n:])
    if name=='find_accessories':
        n=_read32(data);_size(data,4+16*n)
        return dict(uids=[data[i:i+16] for i in range(4,len(data),16)])
    raise ProtocolError('manager result layout is not modeled')
