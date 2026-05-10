# PART ONE
import logging
from asyncio import run
from dataclasses import dataclass
from ipv8.messaging.payload_dataclass import convert_to_payload

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.util import run_forever
from ipv8_service import IPv8
from ipv8.peer import Peer

member1_key = "4c69624e61434c504b3ac117a8cfc7b28b662c9707255b962f1848c0fe7dc1938af68f116884760ea26f6e4901c5dce1ee2bfd23cbc537a9f888308cb343cd67746516a24b54a8d45e3c"
member2_key = "4c69624e61434c504b3a2203abd94c9a33c8d18f9fc76093fe83629cafa13b83f568e0519d0d16e2e6322d1413efce2211605e4ab47aff0f9880f36227b691cf20022feeeb4d73d9da64"
member3_key = "4c69624e61434c504b3a92170169432c64a01d2462ddcfd589ef83c6fb39c4892b248adb834f702a321c1050fd59c0b5510aac9e282a4b3e0416083901551b90d524df4629479eebe5d1"
COMMUNITY_ID = "4c61623247726f75705369676e696e6732303236"
SERVER_PUBLIC_KEY = "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"

@dataclass
class SubmissionMessage:
    member1_key: bytes
    member2_key: bytes
    member3_key: bytes

@dataclass
class ResponseMessage:
    success: bool
    group_id: str
    message: str

convert_to_payload(SubmissionMessage, msg_id=1)
convert_to_payload(ResponseMessage, msg_id=2)


class MyCommunity(Community):
    community_id = bytes.fromhex(COMMUNITY_ID)

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.add_message_handler(ResponseMessage, self.on_response)
        self._submitted = False
        self.register_task("find_server", self.find_server, interval = 3.0, delay = 3.0)

    async def find_server(self) -> None:
        if self._submitted:
            return
        server = next((p for p in self.get_peers() if p.public_key.key_to_bin() == bytes.fromhex(SERVER_PUBLIC_KEY)), None)
        if server is None:
            logging.info("Server not found.")
            return
        self._submitted = True
        logging.info("Server found! Registering group.")
        self.ez_send(server, SubmissionMessage(bytes.fromhex(member1_key), bytes.fromhex(member2_key), bytes.fromhex(member3_key)))

    @lazy_wrapper(ResponseMessage)
    def on_response(self, peer: Peer, payload: ResponseMessage) -> None:
        logging.info("Response: success=%s, group_id=%s, message=%s", payload.success, payload.group_id, payload.message)

async def start_communities() -> None:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "curve25519", "ec1.pem")
    builder.add_overlay("MyCommunity", "my peer", 
                        [WalkerDefinition(Strategy.RandomWalk,
                                              10, {"timeout": 30.0})],
                            default_bootstrap_defs, {}, [])
    await IPv8(builder.finalize(), extra_communities={"MyCommunity": MyCommunity}).start()
    await run_forever()


run(start_communities())

