from __future__ import annotations
import hashlib
import struct
from dataclasses import dataclass, field

HASH_SIZE = 32
HEADER_SIZE = 84
EMPTY_TXS_HASH = hashlib.sha256(b"").digest()

@dataclass
class Transaction:
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes

    def tx_hash(self):
        return hashlib.sha256(self.sender_key + self.data + struct.pack(">q", self.timestamp) + self.signature).digest()

def compute_txs_hash(txs):
    if not txs:
        return EMPTY_TXS_HASH
    return hashlib.sha256(b"".join(tx.tx_hash() for tx in txs)).digest()

def pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce):
    assert len(prev_hash) == HASH_SIZE, f"prev_hash must have a size of {HASH_SIZE} bytes"
    assert len(txs_hash) == HASH_SIZE, f"txs_hash must have a size of {HASH_SIZE} bytes"
    return prev_hash + txs_hash + struct.pack(">QIQ", timestamp, difficulty, nonce)

def block_hash(prev_hash, txs_hash, timestamp, difficulty, nonce):
    return hashlib.sha256(pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce)).digest()

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
    nonce = start_nonce
    limit = 1 << 64
    while nonce < limit:
        hash = block_hash(prev_hash, txs_hash, timestamp, difficulty, nonce)
        if meets_difficulty(hash, difficulty):
            return nonce, hash
        nonce += 1
    raise RuntimeError("nonce space exhausted")

@dataclass
class Block:
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    transactions: list[Transaction] = field(default_factory=list)

    @property
    def hash(self):
        return block_hash(self.prev_hash, self.txs_hash, self.timestamp, self.difficulty, self.nonce)

    def header_bytes(self):
        return pack_header(self.prev_hash, self.txs_hash, self.timestamp, self.difficulty, self.nonce)
        
    def is_valid_pow(self):
        return meets_difficulty(self.hash, self.difficulty)

    def is_body_consistent(self):
        return compute_txs_hash(self.transactions) == self.txs_hash

def genesis_block():
    return Block(prev_hash=b"\x00" * HASH_SIZE, txs_hash=EMPTY_TXS_HASH, timestamp=0, difficulty=0, nonce=0, transactions=[])


def serialize_txs(txs):
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