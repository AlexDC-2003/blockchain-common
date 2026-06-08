# PART ONE - Lab 3 blockchain registration
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
import asyncio

logging.basicConfig(level=logging.INFO, format="%(message)s")

# Registration community (the server's community where we send the registration)
REGISTRATION_COMMUNITY_ID = "4c616233426c6f636b636861696e323032365057"
SERVER_PUBLIC_KEY = "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6"

# Get group id from assign 2
GROUP_ID = "65db51e2655da2e3"

# Our self-chosen blockchain community ID (must match the one in community.py)
BLOCKCHAIN_COMMUNITY_ID = "09726633cb789f8bfa556fadea366c1954ff91ed"

# TODO: fill your own .pem file name here
MY_KEY_FILE = "my_key.pem"

# communication with the server
@dataclass
class RegisterBlockchain:
    group_id: str
    community_id: bytes
 
 
@dataclass
class RegisterResponse:
    success: bool
    message: str
 
 
convert_to_payload(RegisterBlockchain, msg_id=1)
convert_to_payload(RegisterResponse, msg_id=2)
 
 
class RegistrationCommunity(Community):
    community_id = bytes.fromhex(REGISTRATION_COMMUNITY_ID)
 
    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.add_message_handler(RegisterResponse, self.on_response)
        self._submitted = False
        # try to find the server every 3s until we register
        self.register_task("find_server", self.find_server, interval=3.0, delay=3.0)
 
    async def find_server(self) -> None:
        if self._submitted:
            return
        # look through peers for the server's pubkey
        server = next(
            (p for p in self.get_peers()
             if p.public_key.key_to_bin() == bytes.fromhex(SERVER_PUBLIC_KEY)),
            None,
        )
        if server is None:
            logging.info("Server not found.")
            return
        self._submitted = True
        logging.info("Server found! Registering blockchain.")
        self.ez_send(
            server,
            RegisterBlockchain(
                group_id=GROUP_ID,
                community_id=bytes.fromhex(BLOCKCHAIN_COMMUNITY_ID),
            ),
        )
 
    @lazy_wrapper(RegisterResponse)
    def on_response(self, peer: Peer, payload: RegisterResponse) -> None:
        if peer.public_key.key_to_bin() != bytes.fromhex(SERVER_PUBLIC_KEY):
            logging.info("Ignored response from non-server peer")
            return
        logging.info("Response: success=%s, message=%s", payload.success, payload.message)
 
 
async def main() -> None:
    # set up IPv8 with my key and the registration overlay
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "curve25519", MY_KEY_FILE)
    builder.add_overlay(
        "RegistrationCommunity", "my peer",
        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 30.0})],
        default_bootstrap_defs, {}, [],
    )
    await IPv8(
        builder.finalize(),
        extra_communities={"RegistrationCommunity": RegistrationCommunity},
    ).start()
    # keep running so we can receive the response
    await run_forever()
 
 
if __name__ == "__main__":
    asyncio.run(main())