from __future__ import annotations
import time
from dataclasses import dataclass
from chain import Block, Transaction, compute_txs_hash, genesis_block, mine

@dataclass
class ValidationResult:
    ok: bool
    reason: str = ""

class BlockChain:
    def __init__(self):
        self.blocks: list[Block] = [genesis_block()]
        self.mempool: list[Transaction] = []
        self._mempool_hashes: set[bytes] = set()
        self._confirmed_tx_hashes: set[bytes] = set()

    @property
    def tip(self):
        return self.blocks[-1]

    @property
    def height(self):
        return len(self.blocks) - 1

    def add_transaction(self, tx):
        h = tx.tx_hash()
        if h in self._mempool_hashes or h in self._confirmed_tx_hashes:
            return False
        self.mempool.append(tx)
        self._mempool_hashes.add(h)
        return True

    def mine_next(self, difficulty, timestamp = None, max_txs = None):
        if timestamp is not None:
            ts = timestamp
        else:
            ts = int(time.time())
        if max_txs is None:
            txs = list(self.mempool)
        else:
            txs = list(self.mempool[:max_txs])
        commitment = compute_txs_hash(txs)
        prev = self.tip.hash
        nonce, _ = mine(prev, commitment, ts, difficulty)
        block = Block(prev, commitment, ts, difficulty, nonce, txs)
        self._append(block)
        return block

    def validate_extension(self, block):
        if block.prev_hash != self.tip.hash:
            return ValidationResult(False, "prev_hash does not link to tip")
        if not block.is_valid_pow():
            return ValidationResult(False, "PoW does not meet declared difficulty")
        if not block.is_body_consistent():
            return ValidationResult(False, "txs_hash does not match body")
        return ValidationResult(True)

    def try_append(self, block):
        result = self.validate_extension(block)
        if result.ok:
            self._append(block)
        return result

    def _append(self, block):
        self.blocks.append(block)
        included = set()
        for tx in block.transactions:
            included.add(tx.tx_hash())
        self._confirmed_tx_hashes = self._confirmed_tx_hashes | included
        self._mempool_hashes = self._mempool_hashes - included
        new_mempool = []
        for tx in self.mempool:
            if tx.tx_hash() not in included:
                new_mempool.append(tx)
        self.mempool = new_mempool
