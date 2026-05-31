from ipv8.community import Community, CommunitySettings
from dataclasses import dataclass
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.lazy_community import lazy_wrapper
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8_service import IPv8
from ipv8.messaging.payload_dataclass import convert_to_payload
from ipv8.keyvault.crypto import default_eccrypto
import asyncio
import struct
import time

from chain import Block, Transaction
from node import BlockChain

COMMUNITY_ID = bytes.fromhex("04c2aa6ce092029eeb113660172c1da47b7ab028")
SERVER_PUBLIC_KEY = bytes.fromhex("4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6")
MINING_DIFFICULTY = 20  # we have to pick this
MEMBER1 = bytes.fromhex("4c69624e61434c504b3ac117a8cfc7b28b662c9707255b962f1848c0fe7dc1938af68f116884760ea26f6e4901c5dce1ee2bfd23cbc537a9f888308cb343cd67746516a24b54a8d45e3c")
MEMBER2 = bytes.fromhex("4c69624e61434c504b3a2203abd94c9a33c8d18f9fc76093fe83629cafa13b83f568e0519d0d16e2e6322d1413efce2211605e4ab47aff0f9880f36227b691cf20022feeeb4d73d9da64")
MEMBER3 = bytes.fromhex("4c69624e61434c504b3a92170169432c64a01d2462ddcfd589ef83c6fb39c4892b248adb834f702a321c1050fd59c0b5510aac9e282a4b3e0416083901551b90d524df4629479eebe5d1")

@dataclass
class SubmitTransaction:
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes

@dataclass
class SubmitTxResponse:
    success: bool
    tx_hash: bytes
    message: str

@dataclass
class GetChainHeight:
    request_id: int

@dataclass
class ChainHeightResponse:
    request_id: int
    height: int
    tip_hash: bytes

@dataclass
class GetBlock:
    height: int

@dataclass
class BlockResponse:
    height: int
    prev_hash: bytes
    txs_hash: bytes 
    timestamp: int
    difficulty: int
    nonce: int
    block_hash: bytes
    tx_hashes: bytes
    # txs_blob: bytes   # TODO: added the transaction (ask team)

@dataclass
class BlockPropagate:
    height: int
    prev_hash: bytes
    txs_hash: bytes 
    timestamp: int
    difficulty: int
    nonce: int
    block_hash: bytes
    tx_hashes: bytes
    # txs_blob: bytes   # TODO: added the transaction (ask team)

convert_to_payload(SubmitTransaction, msg_id=1)
convert_to_payload(SubmitTxResponse, msg_id=2)
convert_to_payload(GetChainHeight, msg_id=3)
convert_to_payload(ChainHeightResponse, msg_id=4)
convert_to_payload(GetBlock, msg_id=5)
convert_to_payload(BlockResponse, msg_id=6)
convert_to_payload(BlockPropagate, msg_id=7)

class BlockchainSettings(CommunitySettings):
    member1_key: bytes = MEMBER1
    member2_key: bytes = MEMBER2
    member3_key: bytes = MEMBER3
    group_id: str = "65db51e2655da2e3"

class BlockchainCommunity(Community):
    settings_class = BlockchainSettings
    community_id = COMMUNITY_ID
    def __init__(self, settings: BlockchainSettings):
        super().__init__(settings)
        self.members = [settings.member1_key, settings.member2_key, settings.member3_key]
        self.group_id = settings.group_id
        self.server_public_key = SERVER_PUBLIC_KEY
        self.blockchain = BlockChain()
        self.server_peer = None
        self._mining_task = None
        self._chain_updated = False
        self._pending_block_requests: dict[int, asyncio.Future] = {}
        self._fork_switch_lock = asyncio.Lock()

        self.add_message_handler(BlockPropagate, self.on_block_propagate)
        self.add_message_handler(GetBlock, self.on_get_block)
        self.add_message_handler(BlockResponse, self.on_block_response)
        	
        self.add_message_handler(SubmitTransaction, self.on_submit_transaction)
        self.add_message_handler(GetChainHeight, self.on_get_chain_height)
    
    def my_pubkey(self):
        return self.my_peer.public_key.key_to_bin()
 
    def _find_peer(self, pubkey_bin):
        for p in self.get_peers():
            if p.public_key.key_to_bin() == pubkey_bin:
                return p
        return None
    
    # helper to propagate a block to peers
    def propagate_block(self, block):
        msg = BlockPropagate(
            height=self.blockchain.height,
            prev_hash=block.prev_hash,
            txs_hash=block.txs_hash,
            timestamp=block.timestamp,
            difficulty=block.difficulty,
            nonce=block.nonce,
            block_hash=block.hash,
            tx_hashes=b"".join(tx.tx_hash() for tx in block.transactions),
            #txs_blob=serialize_txs(block.transactions),   # TODO
        )
        for k in self.members:
            if k == self.my_pubkey():
                continue
            peer = self._find_peer(k)
            if peer is not None:
                self.ez_send(peer, msg)
    
    # helper to start mining the next block
    def start_mining(self):
        if self._mining_task and not self._mining_task.done():
            self._mining_task.cancel()
        self._mining_task = asyncio.create_task(self._mine_loop())

    # mines the next block in a loop, tries to append it to the chain and propagate it if successful
    async def _mine_loop(self):
        while True:
          self._chain_updated = False
          block = await asyncio.get_event_loop().run_in_executor(None, self.blockchain.prepare_next, MINING_DIFFICULTY)
          if self._chain_updated:
              print("Chain updated while mining, discarding block")
              continue
          result = self.blockchain.try_append(block)
          if result.ok:
              print(f"Mined new block at height {self.blockchain.height}")
              self.propagate_block(block)
          await asyncio.sleep(0)
    
    # try to fetch a block at a given height from a peer
    async def fetch_block(self, peer, height) -> Block | None:
        future = asyncio.get_event_loop().create_future()
        self._pending_block_requests[height] = future
        self.ez_send(peer, GetBlock(height=height))
        try:
            block = await asyncio.wait_for(future, timeout=5.0)
            return block
        except asyncio.TimeoutError:
            print(f"Timeout while waiting for block at height {height} from peer {peer.public_key.key_to_bin().hex()}")
            return None
        finally:
            self._pending_block_requests.pop(height, None)
            
    # handler for receiving a propagated block, validates and tries to append it or do a fork switch
    @lazy_wrapper(BlockPropagate)
    def on_block_propagate(self, peer, msg):
        if peer.public_key.key_to_bin() not in self.members:
            print(f"Received block propagate from non-member peer {peer.public_key.key_to_bin().hex()}, ignoring")
            return
        if msg.height <= self.blockchain.height:
            print(f"Received block propagate for height {msg.height} which is not above current height {self.blockchain.height}, ignoring")
            return
        if msg.height == self.blockchain.height + 1:
            block = Block(
                prev_hash=msg.prev_hash,
                txs_hash=msg.txs_hash,
                timestamp=msg.timestamp,
                difficulty=msg.difficulty,
                nonce=msg.nonce,
                transactions=[]
                #transactions=deserialize_txs(msg.txs_blob),   # TODO: changed from empty bc there might be others?

            )
            result = self.blockchain.validate_extension(block)
            if result.ok:
                print(f"Received valid block at height {msg.height} from peer {peer.public_key.key_to_bin().hex()}")
                self.blockchain.try_append(block)
                self.propagate_block(block)
                self._chain_updated = True
            else:
                print(f"Received invalid block from peer {peer.public_key.key_to_bin().hex()}: {result.reason}")
        else:
            print(f"Received block propagate for height {msg.height}, more than current height {self.blockchain.height}")
            tip_block = Block(
                prev_hash=msg.prev_hash,
                txs_hash=msg.txs_hash,
                timestamp=msg.timestamp,
                difficulty=msg.difficulty,
                nonce=msg.nonce,
                transactions=[]
            )
            asyncio.create_task(self._try_fork_switch(peer, msg.height, tip_block))

    # try to do a fork switch, go backwards from the new tip until finding a common ancestor block
    async def _try_fork_switch(self, peer, tip_height, tip_block):
        # try to prevent multiple concurrent fork switches
        async with self._fork_switch_lock:
          if tip_height <= self.blockchain.height:
            print("Chain already caught up, skipping fork switch")
            return
          new_blocks = [tip_block]
          current_height = tip_height - 1
          while current_height > 0:
              earliest_block = new_blocks[0]
              if current_height < len(self.blockchain.blocks) and earliest_block.prev_hash == self.blockchain.blocks[current_height].hash:
                  break
              block = await self.fetch_block(peer, current_height)
              if block is None:
                  print(f"Failed to fetch block at height {current_height} for fork switch, aborting")
                  return
              if not block.is_valid_pow():
                  print(f"Received block at height {current_height} for fork switch does not meet PoW, aborting")
                  return
              new_blocks.insert(0, block)
              current_height -= 1
          fork_point = current_height
          for i in range(1, len(new_blocks)):
              if new_blocks[i].prev_hash != new_blocks[i-1].hash:
                  print("Blockchain incorrect, not switching")
                  return
          print(f"Switching to new fork")
          self.blockchain.fork_switch(fork_point, new_blocks)
          self.propagate_block(self.blockchain.tip)
          self._chain_updated = True

            
    # handler for receiving a get block message, sends a block corresponding to the requested height
    @lazy_wrapper(GetBlock)
    def on_get_block(self, peer, msg):
        allowed = {*self.members, self.server_public_key}
        if peer.public_key.key_to_bin() not in allowed:
            print(f"Received get block from non-member peer {peer.public_key.key_to_bin().hex()}, ignoring")
            return
        if msg.height > self.blockchain.height:
            print(f"Received get block for height {msg.height} which is above current height {self.blockchain.height}")
            return
        block = self.blockchain.blocks[msg.height]
        response = BlockResponse(
            height=msg.height,
            prev_hash=block.prev_hash,
            txs_hash=block.txs_hash,
            timestamp=block.timestamp,
            difficulty=block.difficulty,
            nonce=block.nonce,
            block_hash=block.hash,
            tx_hashes=b"".join(tx.tx_hash() for tx in block.transactions),
            #txs_blob=serialize_txs(block.transactions),   # TODO

        )
        self.ez_send(peer, response)

    # handler for reaceiving a block response message, checks if waiting for this block and stores it in the corresponding future
    @lazy_wrapper(BlockResponse)
    def on_block_response(self, peer, msg):
        if peer.public_key.key_to_bin() not in self.members:
            print(f"Received block response from non-member peer {peer.public_key.key_to_bin().hex()}, ignoring")
            return
        future = self._pending_block_requests.get(msg.height)
        if future is None:
            print(f"Received unexpected block response for height {msg.height} from peer {peer.public_key.key_to_bin().hex()}, ignoring")
            return
        block = Block(
            prev_hash=msg.prev_hash,
            txs_hash=msg.txs_hash,
            timestamp=msg.timestamp,
            difficulty=msg.difficulty,
            nonce=msg.nonce,
            transactions=[]
            #transactions=deserialize_txs(msg.txs_blob),   # TODO: changed from empty bc there might be others?

        )
        self._pending_block_requests[msg.height].set_result(block)

    @lazy_wrapper(SubmitTransaction)
    def on_submit_transaction(self, peer, msg):
        # Only accept submissions from the server
        if peer.public_key.key_to_bin() != self.server_public_key:
            print(f"Received submit transaction from non-server peer {peer.public_key.key_to_bin().hex()}, ignoring")
            return
        tx = Transaction(
            sender_key=msg.sender_key,
            data=msg.data,
            timestamp=msg.timestamp,
            signature=msg.signature,
        )
        tx_hash = tx.tx_hash()
        # Verify the signature over sender_key + data + timestamp_8byte_be
        signed_data = msg.sender_key + msg.data + struct.pack(">q", msg.timestamp)
        try:
            sender_pk = default_eccrypto.key_from_public_bin(msg.sender_key)
            valid = default_eccrypto.is_valid_signature(sender_pk, signed_data, msg.signature)
        except Exception as e:
            print(f"Could not verify signature: {e}")
            valid = False
        if not valid:
            print(f"Rejected transaction: invalid signature")
            self.ez_send(peer, SubmitTxResponse(
                success=False,
                tx_hash=tx_hash,
                message="Invalid signature",
            ))
            return
        added = self.blockchain.add_transaction(tx)
        if added:
            print(f"Accepted transaction {tx_hash.hex()[:16]}... into mempool")
            self.ez_send(peer, SubmitTxResponse(
                success=True,
                tx_hash=tx_hash,
                message="Accepted into mempool",
            ))
        else:
            print(f"Transaction {tx_hash.hex()[:16]}... already known")
            self.ez_send(peer, SubmitTxResponse(
                success=True,
                tx_hash=tx_hash,
                message="Already known",
            ))
    @lazy_wrapper(GetChainHeight)
    def on_get_chain_height(self, peer, msg):
        # Allow server and team members to query height
        allowed = {*self.members, self.server_public_key}
        if peer.public_key.key_to_bin() not in allowed:
            print(f"Received get chain height from non-allowed peer {peer.public_key.key_to_bin().hex()}, ignoring")
            return
        response = ChainHeightResponse(
            request_id=msg.request_id,
            height=self.blockchain.height,
            tip_hash=self.blockchain.tip.hash,
        )
        self.ez_send(peer, response)

async def main():
    MY_KEY_FILE = "INSERT KEY FILE PATH HERE"
    GROUP_ID = "65db51e2655da2e3"
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my key", "curve25519", MY_KEY_FILE)
    builder.add_overlay(
        "BlockchainCommunity", "my key",
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
    ipv8 = IPv8(builder.finalize(), extra_communities={"BlockchainCommunity": BlockchainCommunity})
    await ipv8.start()
    community = ipv8.get_overlay(BlockchainCommunity)
    my_pk = community.my_pubkey()
    print("My pubkey:", my_pk.hex())
    if my_pk not in community.members:
        await ipv8.stop()
        return
    while True:
        community.server_peer = community._find_peer(community.server_public_key)
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
    community.start_mining()
    try:
        await asyncio.sleep(float("inf"))
    except asyncio.CancelledError:
        pass
    finally:
        await ipv8.stop()

if __name__ == "__main__":
    asyncio.run(main())
        
  


