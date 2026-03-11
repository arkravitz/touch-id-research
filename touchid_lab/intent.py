"""Secure-intent structures recovered at the host, stac, and client boundaries.

No transport, notification port, system authentication change, or cryptography.
Names operation_type/context/flag40 reflect structure, not established semantics.
"""
from .codec import (HostCommand, ProtocolError, _bytes, _fixed, _bounded,
                    _pad, _size, _u32, _read32, _uint)


def encode_start_context(operation_type, context, padding=None):
    """stac 0x10 input. The native manager zeroes unused context bytes."""
    context=_bounded(context,32)
    return _u32(operation_type)+_u32(len(context))+_pad(context,32,padding)


def decode_start_context(data):
    data=_fixed(data,40);n=_read32(data,4)
    if n>32:raise ProtocolError('context exceeds reserved region')
    return dict(operation_type=_read32(data),context=data[8:8+n],padding=data[8+n:40])


def encode_start_command(*, operation_type, context, flag40=0, padding=None,
                         trailing=b'', in_value=0):
    payload=encode_start_context(operation_type,context,padding)+bytes([_uint(flag40,8)])+_bytes(trailing)
    return HostCommand(1,1,in_value,payload).encode()


def encode_cancel_command(command, *, version=1, in_value=0, payload=b''):
    if version!=1:raise ProtocolError('operation requires version 1')
    return HostCommand(command,version,in_value,_bytes(payload)).encode()


def decode_operation(selector, data):
    if selector not in (1,2):raise ProtocolError('operation selector must be 1 or 2')
    command=HostCommand.decode(data)
    if command.version!=1:raise ProtocolError('operation requires version 1')
    result=dict(selector=selector,command=command.command,in_value=command.in_value)
    if selector==1:
        if command.command!=1:raise ProtocolError('start operation requires command 1')
        _size(command.payload,41,False)
        fields=decode_start_context(command.payload[:40])
        fields.update(flag40=command.payload[40],trailing=command.payload[41:])
        result['fields']=fields
    else:
        # The native cancel branch checks version, not header.command or body.
        result['payload']=command.payload
    return result


def encode_detected_intent(uid, intent):
    """stac 0x13 input: UID16 + accessory secure_intent_t48."""
    return _fixed(uid,16)+_fixed(intent,48)


def decode_detected_intent(data):
    data=_fixed(data,64)
    return dict(uid=data[:16],intent=data[16:])


def encode_notification_body(notification_id, **fields):
    """16-byte builder body only; Mach headers/ports are outside this codec.

    Status notifications write only the first four bytes in the observed
    builder. The remaining twelve bytes are explicit opaque reserved data.
    """
    if notification_id==1:
        return _u32(fields['status'])+_fixed(fields.get('reserved',bytes(12)),12)
    if notification_id==2:return _fixed(fields['uid'],16)
    raise ProtocolError('unknown notification ID')


def decode_notification_body(notification_id, data):
    data=_fixed(data,16)
    if notification_id==1:return dict(status=_read32(data),reserved=data[4:])
    if notification_id==2:return dict(uid=data)
    raise ProtocolError('unknown notification ID')
