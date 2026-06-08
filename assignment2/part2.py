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
 
 
from ipv8.messaging.payload_dataclass import convert_to_payload

@dataclass
class ChallengeRequestPayload:
    group_id: str

@dataclass
class ChallengeResponsePayload:
    nonce: bytes
    round_number: int
    deadline: float

@dataclass
class SignatureBundlePayload:
    group_id: str
    round_number: int
    sig1: bytes
    sig2: bytes
    sig3: bytes

@dataclass
class RoundResultPayload:
    success: bool
    round_number: int
    rounds_completed: int
    message: str

@dataclass
class ReadyPayload:
    note: str

@dataclass
class NonceAnnouncePayload:
    round_number: int
    nonce: bytes

@dataclass
class SignatureSharePayload:
    round_number: int
    signature: bytes

@dataclass
class RoundDonePayload:
    round_number: int

convert_to_payload(ChallengeRequestPayload, msg_id=3)
convert_to_payload(ChallengeResponsePayload, msg_id=4)
convert_to_payload(SignatureBundlePayload, msg_id=5)
convert_to_payload(RoundResultPayload, msg_id=6)
convert_to_payload(ReadyPayload, msg_id=7)
convert_to_payload(NonceAnnouncePayload, msg_id=8)
convert_to_payload(SignatureSharePayload, msg_id=9)
convert_to_payload(RoundDonePayload, msg_id=10)

class Lab2Settings(CommunitySettings):
    member1_key: bytes = b"4c69624e61434c504b3ac117a8cfc7b28b662c9707255b962f1848c0fe7dc1938af68f116884760ea26f6e4901c5dce1ee2bfd23cbc537a9f888308cb343cd67746516a24b54a8d45e3c"
    member2_key: bytes = b"4c69624e61434c504b3a2203abd94c9a33c8d18f9fc76093fe83629cafa13b83f568e0519d0d16e2e6322d1413efce2211605e4ab47aff0f9880f36227b691cf20022feeeb4d73d9da64"
    member3_key: bytes = b"4c69624e61434c504b3a92170169432c64a01d2462ddcfd589ef83c6fb39c4892b248adb834f702a321c1050fd59c0b5510aac9e282a4b3e0416083901551b90d524df4629479eebe5d1"
    group_id: str = "65db51e2655da2e3"

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
        self.acked_rounds = set()  # rounds the server confirmed success for
        self.activate_retransmission = True # debug if retransmission doesn't work
        self.retransmit_interval = 0.5
        self.t0 = None  # local clock, might remove not sure if i need it?

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
        # send a ready ping to each teammate (skip myself)
        for key in self.members:
            if key == self.my_pubkey():
                continue
            peer = self._find_peer(key)
            if peer is not None:
                self.ez_send(peer, ReadyPayload(note="ready"))
 
    @lazy_wrapper(ReadyPayload)
    def on_ready(self, peer, payload):
        # mark this teammate as ready (filter out anyone not in the group)
        pk = peer.public_key.key_to_bin()
        if pk in self.members and pk != self.my_pubkey():
            self.ready_from.add(pk)
            print(f"[ready] from member{self.members.index(pk)+1}")
 
    def everyone_ready(self):
        # ready when I can see both teammates AND both have pinged me back
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

    # round starts : ask the server for the next challenge
    def request_challenge(self):
        print(f"[round {self.current_round + 1}] requesting challenge")
        self.ez_send(self.server_peer, ChallengeRequestPayload(group_id=self.group_id))

    @lazy_wrapper(ChallengeResponsePayload)
    def on_challenge_response(self, peer, payload):
        if peer.public_key.key_to_bin() != self.server_pk:
            return
        round_nr = payload.round_number
        nonce = payload.nonce


        # got the nonce, store the round
        self.current_round = round_nr
        self.current_nonce = nonce
        if round_nr not in self.collected_sigs:
            self.collected_sigs[round_nr] = {}

        # send the nonce to teammates so they can sign too
        for key in self.members:
            if key == self.my_pubkey():
                continue
            team_peer = self._find_peer(key)
            if team_peer is not None:
                self.ez_send(team_peer, NonceAnnouncePayload(round_number=round_nr, nonce=nonce))

        # sign it myself
        my_sig = self.sign(nonce)
        self.collected_sigs[round_nr][self.my_index] = my_sig
        # resend if someone didn't get the nonce
        if self.activate_retransmission:
            asyncio.create_task(self._retransmit_nonce(round_nr))

    @lazy_wrapper(NonceAnnouncePayload)
    def on_nonce_announce(self, peer, payload):
        # teammate sent me a nonce, sign it and send my signature back
        pk = peer.public_key.key_to_bin()
        if pk not in self.members:
            return

        # mark internally a new round began
        round_nr = payload.round_number
        nonce = payload.nonce
        if round_nr > self.current_round:
            self.current_round = round_nr
        sig = self.sign(nonce)
        print(f"[round {round_nr}] signing for member{self.members.index(pk)+1}")

        self.ez_send(peer, SignatureSharePayload(round_number=round_nr, signature=sig))

    @lazy_wrapper(SignatureSharePayload)
    def on_signature_received(self, peer, payload):
        # got a signature from a peer so i store it if its new
        pk = peer.public_key.key_to_bin()
        if pk not in self.members:
            return
        sender_index = self.members.index(pk)
        round_nr = payload.round_number

        if round_nr not in self.collected_sigs:
            self.collected_sigs[round_nr] = {}
        self.collected_sigs[round_nr][sender_index] = payload.signature

        print(f"[round {round_nr}] got sig from member{sender_index+1}")
        # maybe we now have all 3, check and submit if so
        self._maybe_submit_bundle(round_nr)

    def _maybe_submit_bundle(self, rnd):
        # if I am not a submitter, skip
        if self.my_index != rnd-1:
            return
        # if not all signatures have been collected, skip
        sigs = self.collected_sigs.get(rnd, {})
        if len(sigs) != 3:  
            return
        #assemble bundle in correct order
        sig_bundle_payload = SignatureBundlePayload(
            group_id = self.group_id,
            round_number = rnd,
            sig1 = sigs[0],
            sig2 = sigs[1],
            sig3 = sigs[2]
        )
        print(f"[round {rnd}] submitting bundle")
        self.ez_send(self.server_peer, sig_bundle_payload)
        # in case the server doesn't get the bundle, keep resending
        if self.activate_retransmission:
            asyncio.create_task(self._retransmit_bundle(rnd, sig_bundle_payload))

    @lazy_wrapper(RoundResultPayload)
    def on_round_result(self, peer, payload):
        # got the server's reply to our submission
        if peer.public_key.key_to_bin() != self.server_pk:
            return
        if not payload.success:
            print(f"[round {payload.round_number}] failed")
            return
        print(f"[round {payload.round_number}] success")
        print(payload.message)
        self.acked_rounds.add(payload.round_number)

         # if all 3 rounds done, we're finished
        if payload.rounds_completed >= 3:
            self.all_done = True
        
        # tell teammates this round is done so the next submitter takes their turn
        for key in self.members:
            if key == self.my_pubkey():
                continue
            team_peer = self._find_peer(key)
            if team_peer is not None:
                self.ez_send(team_peer, RoundDonePayload(round_number=payload.round_number))
        
        # in case a teammate doesn't get the round done msg, keep resending
        if self.activate_retransmission:
            asyncio.create_task(self._retransmit_round_done(payload.round_number))

    @lazy_wrapper(RoundDonePayload)
    def on_round_done(self, peer, payload):
        # some peer finished their round, see if I'm up next
        pk = peer.public_key.key_to_bin()
        if pk not in self.members:
            return
        next_round = payload.round_number + 1
        if next_round > 3:
            self.all_done = True
            return
        # if I'm the submitter for the next round, start it
        if self.my_index == next_round - 1:
            self.current_round = next_round
            self.request_challenge()

    # ----- retransmit for packet-loss recovery -----

    async def _retransmit_nonce(self, rnd):
        # submitter rebroadcasts the nonce to teammates that haven't replied yet
        while not self.all_done:
            await asyncio.sleep(self.retransmit_interval)
            if rnd in self.acked_rounds or self.current_round > rnd:
                return
            sigs = self.collected_sigs.get(rnd, {})
            if len(sigs) >= 3:
                return
            for key in self.members:
                if key == self.my_pubkey():
                    continue
                idx = self.members.index(key)
                if idx in sigs:
                    continue
                team_peer = self._find_peer(key)
                if team_peer is not None:
                    self.ez_send(team_peer, NonceAnnouncePayload(round_number=rnd, nonce=self.current_nonce))

    async def _retransmit_bundle(self, rnd, payload):
        # submitter resends the bundle until the server acks this round
        while not self.all_done:
            await asyncio.sleep(self.retransmit_interval)
            if rnd in self.acked_rounds:
                return
            if self.server_peer is not None:
                self.ez_send(self.server_peer, payload)

    async def _retransmit_round_done(self, rnd):
        # previous submitter nudges the next submitter until round rnd+1 starts
        while not self.all_done:
            await asyncio.sleep(self.retransmit_interval)
            if self.current_round > rnd or self.all_done:
                return
            for key in self.members:
                if key == self.my_pubkey():
                    continue
                team_peer = self._find_peer(key)
                if team_peer is not None:
                    self.ez_send(team_peer, RoundDonePayload(round_number=rnd))

# main
async def main():
    #TODO: Fill your key file
    MY_KEY_FILE = "my_key.pem"
    MEMBER1 = bytes.fromhex("4c69624e61434c504b3ac117a8cfc7b28b662c9707255b962f1848c0fe7dc1938af68f116884760ea26f6e4901c5dce1ee2bfd23cbc537a9f888308cb343cd67746516a24b54a8d45e3c")
    MEMBER2 = bytes.fromhex("4c69624e61434c504b3a2203abd94c9a33c8d18f9fc76093fe83629cafa13b83f568e0519d0d16e2e6322d1413efce2211605e4ab47aff0f9880f36227b691cf20022feeeb4d73d9da64")
    MEMBER3 = bytes.fromhex("4c69624e61434c504b3a92170169432c64a01d2462ddcfd589ef83c6fb39c4892b248adb834f702a321c1050fd59c0b5510aac9e282a4b3e0416083901551b90d524df4629479eebe5d1")
    GROUP_ID = "65db51e2655da2e3"

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

    # wait until I see the server and both teammates as peers
    while True:
        community.server_peer = community._find_peer(community.server_pk)
        teammates_seen = True
        for k in community.members:
            if k == my_pk:
                continue
            if community._find_peer(k) is None:
                teammates_seen = False
                break
        if community.server_peer is not None and teammates_seen:
            break
        await asyncio.sleep(0.5)
    print("found server and teammates")
    
    # send ready + start the rounds. only member1 fires round 1, the rest chain after via RoundDone msgs
    done = False
    while not community.all_done:
        community.broadcast_ready()
        await asyncio.sleep(0.5)
        if community.everyone_ready() and not done:
            if community.my_index == 0:
                done = True
                community.request_challenge()
        await asyncio.sleep(0.2)
    print("everyone ready")
    print("all rounds done")
    await ipv8.stop()

if __name__ == "__main__":
    asyncio.run(main())