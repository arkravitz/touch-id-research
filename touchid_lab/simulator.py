"""A scripted transport laboratory, never a cryptographic or macOS authenticator."""
from dataclasses import dataclass
from . import codec as c


class TrustUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class Exchange:
    operation: str
    request: bytes
    reply: bytes | None
    stage: str = 'fixture'


class ScriptedPeer:
    """Strict ordered byte fixtures. Rejected exchanges leave position unchanged."""
    def __init__(self, exchanges):
        self._exchanges = tuple(exchanges)
        self.position = 0

    @property
    def complete(self):return self.position == len(self._exchanges)

    @property
    def native_compatible(self):return False

    def require_native_trust(self):
        raise TrustUnavailable('enclave attestation is not implemented')

    def exchange(self, operation, request):
        if self.complete:raise c.ProtocolError('script complete; duplicate or unexpected request')
        step=self._exchanges[self.position]
        if operation != step.operation or request != step.request:
            raise c.ProtocolError(f'out-of-order or altered request at step {self.position}: expected {step.operation}')
        if operation in c.GET_SIZES or operation=='manifest':
            if request:raise c.ProtocolError('GetReport request body must be empty')
            decoded={}
        else:
            decoded=c.decode_request(operation,request)
        if step.reply is not None:
            response=c.decode_reply(operation,step.reply)
            if 'counter' in response and response['counter']!=decoded.get('counter'):
                raise c.ProtocolError('reply counter does not match request')
            if response.get('status',0)!=0:
                raise c.ProtocolError(f'accessory returned status {response["status"]:#x}')
        elif operation in c.REPLY_IDS or operation in c.GET_SIZES or operation=='manifest':
            raise c.ProtocolError('missing required fixture response')
        self.position+=1
        return step.reply


def demo_script(scenario='all'):
    if scenario not in ('all','pairing','session','intent'):raise c.ProtocolError('unknown scenario')
    # Every key/blob below is synthetic opaque data, not a genuine cryptographic value.
    steps=[];counter=0;key=b'K'*65;identity=b'SYNTHETIC-HOST-IDENTITY';challenge=b'C'*60
    def get(name,stage,**reply):
        steps.append(Exchange(name,b'',c.encode_reply(name,**reply),stage))
    def send(name,stage,*,reply=None,**fields):
        nonlocal counter
        counted=name not in ('select_protocol','secure_intent_nonce')
        if counted:counter=(counter+1)&0xffffffff
        request=c.encode_request(name,counter if counted else None,**fields)
        response=c.encode_reply(name,counter=counter,**reply) if reply is not None else None
        steps.append(Exchange(name,request,response,stage))
    get('protocol_info','discovery',version=1)
    send('select_protocol','discovery',version=1)
    get('uid','discovery',uid=bytes(range(16)))
    send('public_key','discovery',reply={'key':key})
    if scenario in ('all','pairing'):
        send('query_pairing','pairing',identity=identity,reply={'flag5':0,'flag6':0,'slots':5})
        send('generate_key','pairing',key_type=1,reply={'key':key})
        for transfer_type,blob,following in [(1,b'OPAQUE-ATTESTATION-FIXTURE','pair_prepare'),(2,b'OPAQUE-CHALLENGE-FIXTURE','pair')]:
            counter+=1
            steps.extend(Exchange('transfer',chunk,None,'pairing') for chunk in c.transfer_chunks(counter,transfer_type,blob))
            if following=='pair_prepare':send('pair_prepare','pairing',identity=identity,reply={})
            else:send('pair','pairing',identity=identity,key=key,reply={'blob_a':b'OPAQUE-PAIR-A','blob_b':b'OPAQUE-PAIR-B'})
        get('manifest','manifest',manifest=b'OPAQUE-MANIFEST-FIXTURE')
    if scenario in ('all','session'):
        send('generate_key','session',key_type=2,reply={'key':key})
        send('compute_session','session',key=key,challenge=b'OPAQUE-SEP-CHALLENGE',reply={'blob_a':b'OPAQUE-SESSION-REPLY'})
        get('issue_challenge','session',challenge=challenge)
        send('verify_challenge','session',challenge=challenge,reply={})
    if scenario in ('all','intent'):
        send('start_intent','intent',reply={})
        send('secure_intent_nonce','intent',nonce=b'N'*48)
        send('cancel','intent',reply={})
    return steps


def run_demo(scenario='all'):
    steps=demo_script(scenario);peer=ScriptedPeer(steps);rows=[]
    for step in steps:
        reply=peer.exchange(step.operation,step.request)
        rows.append({'stage':step.stage,'operation':step.operation,
                     'request_hex':step.request.hex(),'reply_hex':None if reply is None else reply.hex(),
                     'request_length':len(step.request),'reply_length':None if reply is None else len(reply),
                     'validated':True,'provenance':'synthetic fixtures'})
    try:peer.require_native_trust()
    except TrustUnavailable as exc:gate='unavailable: '+str(exc)
    return {'provenance':'synthetic fixtures','scenario':scenario,'native_compatible':False,
            'script_complete':peer.complete,'trust_gate':gate,'exchanges':rows}
