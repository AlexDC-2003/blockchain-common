from __future__ import annotations
import hashlib
import struct
from dataclasses import dataclass, field

HASH_SIZE = 32
HEADER_SIZE = 84    # prev_hash(32) + txs_hash(32) + timestamp(8) + difficulty(4) + nonce(8)
EMPTY_TXS_HASH = hashlib.sha256(b"").digest()   # empty hash used by blocks with no transactions

@dataclass
class Transaction:
    sender_key: bytes   # public key of the sender (also identifies who signed)
    data: bytes         # payload carried by the transaction
    timestamp: int      # creation time
    signature: bytes    # sender's signature over the transaction

    def tx_hash(self):
        # identity of a transaction, hashing over all fields
        return hashlib.sha256(self.sender_key + self.data + struct.pack(">q", self.timestamp) + self.signature).digest()

def compute_txs_hash(txs):
    # the block's body, hash over the concatenated per-tx hashes
    # order matters: a different tx ordering produces a different commitment
    if not txs:
        return EMPTY_TXS_HASH  # empty body collapses to a fixed sentinel hash
    return hashlib.sha256(b"".join(tx.tx_hash() for tx in txs)).digest()

def pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce):
    # serialize the 84-byte block header in a fixed big-endian layout
    assert len(prev_hash) == HASH_SIZE, f"prev_hash must have a size of {HASH_SIZE} bytes"
    assert len(txs_hash) == HASH_SIZE, f"txs_hash must have a size of {HASH_SIZE} bytes"
    return prev_hash + txs_hash + struct.pack(">QIQ", timestamp, difficulty, nonce)

def block_hash(prev_hash, txs_hash, timestamp, difficulty, nonce):
    # a block's hash is the hash of its serialized header
    return hashlib.sha256(pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce)).digest()

# check whether nonce meets the difficulty requirement of having 'bits' leading zeroes
def meets_difficulty(digest, bits):
    if bits <= 0:
        return True 
    full, rem = divmod(bits, 8)
    if any(digest[i] != 0 for i in range(full)):
        return False
    if rem == 0:
        return True
    return digest[full] < (1 << (8 - rem))

def mine(prev_hash, txs_hash, timestamp, difficulty, start_nonce = 0):
    # brute-force search for a nonce whose block hash meets the difficulty target
    nonce = start_nonce
    limit = 1 << 64
    while nonce < limit:
        hash = block_hash(prev_hash, txs_hash, timestamp, difficulty, nonce)
        if meets_difficulty(hash, difficulty):
            return nonce, hash  # found a winning nonce
        nonce += 1
    raise RuntimeError("nonce space exhausted")

@dataclass
class Block:
    prev_hash: bytes    # hash of the previous block, links the chain together
    txs_hash: bytes     # commitment to the body
    timestamp: int      # when the block was mined
    difficulty: int     # number of leading zero bits required of the block hash
    nonce: int          # value found by mining so the hash meets the difficulty
    transactions: list[Transaction] = field(default_factory=list)  # the block body
    
    # block helper functions
    @property
    def hash(self):
        # returns the block hash
        return block_hash(self.prev_hash, self.txs_hash, self.timestamp, self.difficulty, self.nonce)

    def header_bytes(self):
        # returns the block header
        return pack_header(self.prev_hash, self.txs_hash, self.timestamp, self.difficulty, self.nonce)

    def is_valid_pow(self):
        # checks the difficulty
        return meets_difficulty(self.hash, self.difficulty)

    def is_body_consistent(self):
        # checks whether the block's body's hash is equal to the commitment to the body
        return compute_txs_hash(self.transactions) == self.txs_hash

def genesis_block():
    # fixed, deterministic first block shared by every chain instance
    return Block(prev_hash=b"\x00" * HASH_SIZE, txs_hash=EMPTY_TXS_HASH, timestamp=0, difficulty=0, nonce=0, transactions=[])


def serialize_txs(txs):
    # wire format for a list of transactions (all integers big-endian)
    # 4bytes for nr of txs, then for each 2bytes for sender key len then key, 4bytes for data then actual data, 8bytes timestamp,
    # 2 bytes for signature then the actual siganture.
    out = struct.pack(">I", len(txs))
    for tx in txs:
        out += struct.pack(">H", len(tx.sender_key)) + tx.sender_key
        out += struct.pack(">I", len(tx.data)) + tx.data
        out += struct.pack(">q", tx.timestamp)
        out += struct.pack(">H", len(tx.signature)) + tx.signature
    return out


def deserialize_txs(blob):
    # unpack the function above
    txs = []
    offset = 0
    num_txs, = struct.unpack_from(">I", blob, offset)
    offset += 4

    for _ in range(num_txs):
        sk_len, = struct.unpack_from(">H", blob, offset)
        offset += 2
        sender_key = blob[offset:offset + sk_len]
        offset += sk_len

        data_len, = struct.unpack_from(">I", blob, offset)
        offset += 4
        data = blob[offset:offset + data_len]
        offset += data_len

        timestamp, = struct.unpack_from(">q", blob, offset)
        offset += 8

        sig_len, = struct.unpack_from(">H", blob, offset)
        offset += 2
        signature = blob[offset:offset + sig_len]
        offset += sig_len

        txs.append(Transaction(
            sender_key=sender_key,
            data=data,
            timestamp=timestamp,
            signature=signature,
        ))
    
    return txs