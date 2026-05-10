from ipv8.community import Community, CommunitySettings
from dataclasses import dataclass
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.lazy_community import lazy_wrapper
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8_service import IPv8
import asyncio
import time
 
 
# ----------------- communicate with server -----------------
 
# @dataclass
# class RegisterPayload(DataClassPayload[1]):
#     format_list = ["varlenH", "varlenH", "varlenH"]
#     member1_key: bytes
#     member2_key: bytes
#     member3_key: bytes
 
 
# @dataclass
# class RegisterResponsePayload(DataClassPayload[2]):
#     format_list = ["?", "varlenHutf8", "varlenHutf8"]
#     success: bool
#     group_id: str
#     message: str
 
 
@dataclass
class ChallengeRequestPayload(DataClassPayload[3]):
    format_list = ["varlenHutf8"]
    group_id: str
 
 
@dataclass
class ChallengeResponsePayload(DataClassPayload[4]):
    format_list = ["varlenH", "q", "d"]
    nonce: bytes
    round_number: int
    deadline: float
 
 
@dataclass
class SignatureBundlePayload(DataClassPayload[5]):
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]
    group_id: str
    round_number: int
    sig1: bytes
    sig2: bytes
    sig3: bytes
 
 
@dataclass
class RoundResultPayload(DataClassPayload[6]):
    format_list = ["?", "q", "q", "varlenHutf8"]
    success: bool
    round_number: int
    rounds_completed: int
    message: str
 
 
# ----------------- communicate between us -----------------
 
@dataclass
class ReadyPayload(DataClassPayload[7]):
    format_list = ["varlenHutf8"]
    note: str 
 
 
@dataclass
class NonceAnnouncePayload(DataClassPayload[8]):
    format_list = ["q", "varlenH"]
    round_number: int
    nonce: bytes
 
 
@dataclass
class SignatureSharePayload(DataClassPayload[9]):
    format_list = ["q", "varlenH"]
    round_number: int
    signature: bytes
 
 
@dataclass
class RoundDonePayload(DataClassPayload[10]):
    format_list = ["q"]
    round_number: int

class Lab2Settings(CommunitySettings):
    member1_key: bytes = b"4c69624e61434c504b3ac117a8cfc7b28b662c9707255b962f1848c0fe7dc1938af68f116884760ea26f6e4901c5dce1ee2bfd23cbc537a9f888308cb343cd67746516a24b54a8d45e3c"
    member2_key: bytes = b"4c69624e61434c504b3a2203abd94c9a33c8d18f9fc76093fe83629cafa13b83f568e0519d0d16e2e6322d1413efce2211605e4ab47aff0f9880f36227b691cf20022feeeb4d73d9da64"
    member3_key: bytes = b"4c69624e61434c504b3a92170169432c64a01d2462ddcfd589ef83c6fb39c4892b248adb834f702a321c1050fd59c0b5510aac9e282a4b3e0416083901551b90d524df4629479eebe5d1"
    group_id: str = "5a69b03f8adf9b9e"

class Lab2Community(Community):
    community_id = bytes.fromhex("4c61623247726f75705369676e696e6732303236")
    settings_class = Lab2Settings
    def __init__(self, settings: Lab2Settings):
        super().__init__(settings)
        self.members = [settings.member1_key, settings.member2_key, settings.member3_key]
        self.group_id = settings.group_id
        self.server_pk = bytes.fromhex("4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96")

        self.server_peer = None

        # state for the timed run
        self.my_index = None  # member number (need to set later)
        self.ready_from = set()  # keys of who sent ready so far
        self.current_round = 0
        self.current_nonce = None
        self.collected_sigs = {}  # round_number -> {member_index: signature}
        self.all_done = False
        self.t0 = None  # local clock alex might remove not sure if i need it?

        # handlers for all possible received messages
        self.add_message_handler(ChallengeResponsePayload, self.on_challenge_response)
        self.add_message_handler(RoundResultPayload, self.on_round_result)
        self.add_message_handler(ReadyPayload, self.on_ready)
        self.add_message_handler(NonceAnnouncePayload, self.on_nonce_announce)
        self.add_message_handler(SignatureSharePayload, self.on_signature_received)
        self.add_message_handler(RoundDonePayload, self.on_round_done)
    
# ----- helpers -----
 
    def my_pubkey(self):
        return self.my_peer.public_key.key_to_bin()
 
    # return peer from pub key so i can send stuff
    def _find_peer(self, pubkey_bin):
        for p in self.get_peers():
            if p.public_key.key_to_bin() == pubkey_bin:
                return p
        return None
 
    def sign(self, data: bytes) -> bytes:
        return self.my_peer.key.signature(data)


    # make sure everyone is ready
    def broadcast_ready(self):
        for key in self.members:
            if key == self.my_pubkey():
                continue
            peer = self._find_peer(key)
            if peer is not None:
                self.ez_send(peer, ReadyPayload(note="ready"))
 
    @lazy_wrapper(ReadyPayload)
    def on_ready(self, peer, payload):
        pk = peer.public_key.key_to_bin()
        if pk in self.members and pk != self.my_pubkey():
            self.ready_from.add(pk)
            print(f"[ready] from member{self.members.index(pk)+1}")
 
    def everyone_ready(self):
        teammates = []
        for k in self.members:
            if k != self.my_pubkey():
                teammates.append(k)
        
        all_seen = True
        for k in teammates:
            if self._find_peer(k) is None:
                all_seen = False
                break
        
        all_acked = True
        for k in teammates:
            if k not in self.ready_from:
                all_acked = False
                break
        
        if all_seen and all_acked:
            return True
        return False


    # round starts
    def request_challenge(self):
        print(f"[round {self.current_round + 1}] requesting challenge")
        self.ez_send(self.server_peer, ChallengeRequestPayload(group_id=self.group_id))

    @lazy_wrapper(ChallengeResponsePayload)
    def on_challenge_response(self, peer, payload):
        if peer.public_key.key_to_bin() != self.server_pk:
            return
        round_nr = payload.round_number
        nonce = payload.nonce


        self.current_round = round_nr
        self.current_nonce = nonce
        if round_nr not in self.collected_sigs:
            self.collected_sigs[round_nr] = {}

        for key in self.members:
            if key == self.my_pubkey():
                continue
            team_peer = self._find_peer(key)
            if team_peer is not None:
                self.ez_send(team_peer, NonceAnnouncePayload(round_number=round_nr, nonce=nonce))

        my_sig = self.sign(nonce)
        self.collected_sigs[round_nr][self.my_index] = my_sig

    @lazy_wrapper(NonceAnnouncePayload)
    def on_nonce_announce(self, peer, payload):
        pk = peer.public_key.key_to_bin()
        if pk not in self.members:
            return

        round_nr = payload.round_number
        nonce = payload.nonce
        sig = self.sign(nonce)
        print(f"[round {round_nr}] signing for member{self.members.index(pk)+1}")
        
        self.ez_send(peer, SignatureSharePayload(round_number=round_nr, signature=sig))


    @lazy_wrapper(SignatureSharePayload)
    def on_signature_received(self, peer, payload):
        pk = peer.public_key.key_to_bin()
        if pk not in self.members:
            return
        sender_index = self.members.index(pk)
        round_nr = payload.round_number

        if round_nr not in self.collected_sigs:
            self.collected_sigs[round_nr] = {}
        self.collected_sigs[round_nr][sender_index] = payload.signature

        print(f"[round {round_nr}] got sig from member{sender_index+1}")
        self._maybe_submit_bundle(round_nr)

    # TODO alex: daca nu am toate 3 signatures sau nu sunt eu submitter skip(pt asta fa un if cu  my_index == rnd-1 si membrul ala da submit)
    # dupa creezi SignatureBundlePayload si dai la server cu ez send
    def _maybe_submit_bundle(self, rnd):
        pass


    # TODO alex: handle respunsul de la server, print daca e succes pt log, daca e fail return
    # daca rounds_completed e 3 return plus set all_done la true, else trimite round doen payload to rest ca sa inceapa urmatorul submitter runda urm
    # also daca cumva eu sunt urm submitter sa incep eu runda(nu stiu ce e asta e edge case care aparea la claude in plan)
    @lazy_wrapper(RoundResultPayload)
    def on_round_result(self, peer, payload):
        pass


    # TODO alex: am primit un round done de la cnv prin func da mai sus, intai verific ca acel cnv sa fie in din grup
    # calculez next_round = payload.round_number + 1(return daca >3), si daca: my_index == next_round - 1 =>  self.current_round = next_round si self.request_challenge()
    @lazy_wrapper(RoundDonePayload)
    def on_round_done(self, peer, payload):
        pass

# main
# TODO alex: combini tot ce e mai sus, am dat eu copy paste la fluff tu tb sa faci combinarea functiilor. good luck! :)))
async def main():
    MY_KEY_FILE = "my_key.pem"
    MEMBER1 = bytes.fromhex("4c69624e61434c504b3ac117a8cfc7b28b662c9707255b962f1848c0fe7dc1938af68f116884760ea26f6e4901c5dce1ee2bfd23cbc537a9f888308cb343cd67746516a24b54a8d45e3c")
    MEMBER2 = bytes.fromhex("4c69624e61434c504b3a2203abd94c9a33c8d18f9fc76093fe83629cafa13b83f568e0519d0d16e2e6322d1413efce2211605e4ab47aff0f9880f36227b691cf20022feeeb4d73d9da64")
    MEMBER3 = bytes.fromhex("4c69624e61434c504b3a92170169432c64a01d2462ddcfd589ef83c6fb39c4892b248adb834f702a321c1050fd59c0b5510aac9e282a4b3e0416083901551b90d524df4629479eebe5d1")
    GROUP_ID = "5a69b03f8adf9b9e"

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my key", "curve25519", MY_KEY_FILE)
    builder.add_overlay(
        "Lab2Community", "my key",
        [WalkerDefinition(Strategy.RandomWalk, 50, {"timeout": 1.0})],
        default_bootstrap_defs,
        {
            "member1_key": MEMBER1,
            "member2_key": MEMBER2,
            "member3_key": MEMBER3,
            "group_id": GROUP_ID,
        },
        [],
    )
    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab2Community": Lab2Community})
    await ipv8.start()
    community = ipv8.get_overlay(Lab2Community)


    my_pk = community.my_pubkey()
    print("My pubkey:", my_pk.hex())
    if my_pk not in community.members:
        await ipv8.stop()
        return
    community.my_index = community.members.index(my_pk)
    print(f"I am member{community.my_index + 1}")



if __name__ == "__main__":
    asyncio.run(main())
