"""Static driver-visible sensor report layouts; no transport or decryption.

Source: AppleMesaSEPDriver's MesaAccessoryIntReport* init and block functions.
Opaque field names deliberately avoid inferring plaintext pixels or timestamps.
"""
import struct

from .codec import ProtocolError


MINIMUM_LENGTHS = {0xb4: 6, 0xb5: 10, 0xb6: 0x2a42, 0xb7: 0x134}
IMAGE_INFO_RECORD = struct.Struct('<HBBH3s4I4Q')


def _fixed(value, length, name):
    if not isinstance(value, bytes) or len(value) != length:
        raise ProtocolError(f'{name} requires {length} bytes')
    return value


def _uint(value, bits, name):
    if not isinstance(value, int) or not 0 <= value < 1 << bits:
        raise ProtocolError(f'{name} must be an unsigned {bits}-bit integer')
    return value


def decode_metadata(data: bytes) -> dict:
    """Reproduce named native getters; retain unexplained fields as opaque."""
    _fixed(data, 17, 'metadata')
    flags = struct.unpack_from('<H', data)[0]
    return dict(flags=flags, button_state=(1, 3, 4, 2)[flags & 3],
                wake_on_menu_pin_used=flags & 8, opaque8=data[2:10],
                opaque_byte10=data[10], capture_count=data[11],
                capture_counter=max(data[11]-1, 0), opaque5=data[12:17])


def encode_capture_buffer(image_blob: bytes, metadata: bytes, extra: bytes) -> bytes:
    """IOMesaCaptureDataAccessory packed OSData, consumed by SBIO 0x74."""
    _fixed(metadata, 17, 'metadata')
    for name, data in [('image_blob', image_blob), ('extra', extra)]:
        if not isinstance(data, bytes):
            raise ProtocolError(f'{name} must be bytes')
        _uint(len(data), 32, name+' length')
    _uint(29+len(image_blob)+len(extra), 32, 'total length')
    return struct.pack('<III', len(image_blob), 17, len(extra)) + image_blob + metadata + extra


def decode_capture_buffer(data: bytes) -> dict:
    if len(data) < 12:
        raise ProtocolError('capture buffer requires a 12-byte header')
    image_len, metadata_len, extra_len = struct.unpack_from('<III', data)
    if metadata_len != 17 or len(data) != 12+image_len+metadata_len+extra_len:
        raise ProtocolError('inconsistent capture buffer lengths')
    end_image = 12+image_len
    return dict(image_blob=data[12:end_image], metadata=data[end_image:end_image+17],
                extra=data[end_image+17:])


def encode_capture_identity(uid: bytes, metadata: bytes) -> bytes:
    """SBIO 0x75's input: UID followed by the same 17-byte metadata."""
    return _fixed(uid, 16, 'uid') + _fixed(metadata, 17, 'metadata')


def decode_capture_identity(data: bytes) -> dict:
    _fixed(data, 33, 'capture identity')
    return dict(uid=data[:16], metadata=data[16:])


def command_mode_report_id(mode: int) -> int:
    """Only the report ID is established; the one-byte body is uncharacterized."""
    _uint(mode, 32, 'mode')
    if mode >= 5:
        raise ProtocolError('observed command modes range from 0 to 4')
    return 0x78 | mode


def decode_feature_finger_state(data: bytes) -> dict:
    """GetReport 0xa1 returns one byte interpreted as nonzero = present."""
    _fixed(data, 1, 'feature finger state')
    return dict(raw_state=data[0], finger_present=data[0] != 0)


def encode_calibration_info(status: int, total_length: int) -> bytes:
    """GetReport 0xab's eight-byte status/length response."""
    return struct.pack('<II', _uint(status,32,'status'), _uint(total_length,32,'total_length'))


def decode_calibration_info(data: bytes) -> dict:
    _fixed(data, 8, 'calibration info')
    status, total_length = struct.unpack('<II', data)
    return dict(status=status, total_length=total_length)


def encode_device_info(opaque: bytes) -> bytes:
    """GetReport 0xa0's forwarded 91-byte buffer; field meanings unresolved."""
    return _fixed(opaque,91,'device info')


def decode_device_info(data: bytes) -> dict:
    return dict(opaque=_fixed(data,91,'device info'))


def _words(values, count, bits, name):
    if len(values)!=count:raise ProtocolError(f'{name} requires {count} values')
    return tuple(_uint(value,bits,name) for value in values)


def encode_image_info_metadata(header_words, header_bytes, records) -> bytes:
    """Packed 306-byte region. Float fields use raw bits to preserve NaNs.

    Types derive from biometrickitd's accessoryImageInfo: method encoding and
    are cross-checked against the driver's 57-byte record stride and copies.
    Field names indicate offsets, not inferred physical meanings.
    """
    head=struct.pack('<QQ',*_words(header_words,2,64,'header_words'))+_fixed(header_bytes,5,'header_bytes')
    if len(records)!=5:raise ProtocolError('image info reserves exactly five records')
    parts=[head]
    for record in records:
        parts.append(IMAGE_INFO_RECORD.pack(
            _uint(record['word0'],16,'word0'),_uint(record['byte2'],8,'byte2'),
            _uint(record['byte3'],8,'byte3'),_uint(record['word4'],16,'word4'),
            _fixed(record['bytes6'],3,'bytes6'),*_words(record['float_bits'],3,32,'float_bits'),
            _uint(record['word21'],32,'word21'),*_words(record['words25'],4,64,'words25')))
    return b''.join(parts)


def decode_image_info_metadata(data: bytes) -> dict:
    data=_fixed(data,306,'image info metadata')
    records=[]
    for offset in range(21,306,57):
        fields=IMAGE_INFO_RECORD.unpack_from(data,offset)
        records.append(dict(word0=fields[0],byte2=fields[1],byte3=fields[2],word4=fields[3],
                            bytes6=fields[4],float_bits=fields[5:8],word21=fields[8],words25=fields[9:13]))
    return dict(header_words=struct.unpack_from('<QQ',data),header_bytes=data[16:21],records=records)


def active_image_info_records(data: bytes) -> list:
    """Conservatively bound count before selecting records; no native OOB reads."""
    result=decode_image_info_metadata(data);count=result['header_bytes'][4]
    if count>5:raise ProtocolError('record count exceeds five-record capacity')
    return result['records'][:count]


def encode_sensor_report(report_id: int, *, trailing=b'', **fields) -> bytes:
    """Build recovered report structures without claiming cryptographic validity."""
    if report_id == 0xb4:
        body = struct.pack('<I', _uint(fields['code'],32,'code')) + _fixed(fields.get('reserved',b'\0'),1,'reserved')
    elif report_id == 0xb5:
        body = bytes([_uint(fields['state'],8,'state')]) + _fixed(fields['opaque8'],8,'opaque8')
    elif report_id == 0xb6:
        body = (_fixed(fields['image_blob'],10752,'image_blob')
                + _fixed(fields['opaque17'],17,'opaque17') + _fixed(fields['opaque48'],48,'opaque48'))
    elif report_id == 0xb7:
        body = bytes([_uint(fields['marker'],8,'marker')]) + _fixed(fields['metadata'],306,'metadata')
    else:
        raise ProtocolError('unknown sensor report ID')
    if not isinstance(trailing, bytes):
        raise ProtocolError('trailing must be bytes')
    return bytes([report_id]) + body + trailing


def decode_sensor_report(data: bytes) -> dict:
    """Decode copied fields, retaining bytes the observed parser does not read.

    Like processReportMD, accept trailing bytes. ImageInfo stays opaque rather
    than reproducing the native parser's count-dependent metadata dereferences.
    This is a structural model, not a cryptographic acceptance check.
    """
    if not data or data[0] not in MINIMUM_LENGTHS:
        raise ProtocolError('unknown or missing sensor report ID')
    report_id = data[0]
    minimum = MINIMUM_LENGTHS[report_id]
    if len(data) < minimum:
        raise ProtocolError(f'sensor report {report_id:#x} requires at least {minimum} bytes')
    result = dict(report_id=report_id, trailing=data[minimum:])
    if report_id == 0xb4:
        result.update(kind='error', code=struct.unpack_from('<I', data, 1)[0], reserved=data[5:6])
    elif report_id == 0xb5:
        result.update(kind='finger_state', state=data[1], opaque8=data[2:10])
    elif report_id == 0xb6:
        result.update(kind='image', image_blob=data[1:0x2a01],
                      opaque17=data[0x2a01:0x2a12], opaque48=data[0x2a12:0x2a42])
    else:
        result.update(kind='image_info', marker=data[1],
                      metadata_valid=data[1] == 0xff, metadata=data[2:0x134])
    return result
