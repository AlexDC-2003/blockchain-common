from __future__ import annotations
import time
from dataclasses import dataclass
from chain import Block, Transaction, compute_txs_hash, genesis_block, mine

@dataclass
class ValidationResult:
    # outcome of checking a candidate block. Reason is populated only on failure
    ok: bool
    reason: str = ""

class BlockChain:
    # in-memory blockchain: the ordered block list plus a mempool of pending txs.
    # the two hash sets are caches that let add_transaction reject duplicates in O(1).
    def __init__(self):
        self.blocks: list[Block] = [genesis_block()]    # canonical chain, genesis at index 0
        self.mempool: list[Transaction] = []            # pending txs not yet in a block
        self._mempool_hashes: set[bytes] = set()        # tx hashes currently in the mempool (fast dedupe)
        self._confirmed_tx_hashes: set[bytes] = set()   # tx hashes already in a confirmed block

    @property
    def tip(self):
        # the most recent block
        return self.blocks[-1]

    @property
    def height(self):
        # number of blocks after genesis block
        return len(self.blocks) - 1

    def add_transaction(self, tx):
        # add to the mempool unless we've already seen this tx (pending or confirmed)
        h = tx.tx_hash()
        if h in self._mempool_hashes or h in self._confirmed_tx_hashes:
            return False
        self.mempool.append(tx)
        self._mempool_hashes.add(h)
        return True

    def mine_next(self, difficulty, timestamp = None, max_txs = None):
        # mine a block on top of the tip and append it to the chain
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
        nonce, _ = mine(prev, commitment, ts, difficulty)  # do the proof-of-work
        block = Block(prev, commitment, ts, difficulty, nonce, txs)
        self._append(block)
        return block

    def validate_extension(self, block):
        # check a block is a valid extension of the current tip (does not mutate state)
        if block.prev_hash != self.tip.hash:
            return ValidationResult(False, "prev_hash does not link to tip")
        if not block.is_valid_pow():
            return ValidationResult(False, "PoW does not meet declared difficulty")
        if not block.is_body_consistent():
            return ValidationResult(False, "txs_hash does not match body")
        return ValidationResult(True)

    def try_append(self, block):
        # validate then append a block. Chain is only mutated when validation passes
        result = self.validate_extension(block)
        if result.ok:
            self._append(block)
        return result

    def _append(self, block):
        # append a (presumed valid) block and reconcile the mempool with its txs
        self.blocks.append(block)
        included = set()
        for tx in block.transactions:
            included.add(tx.tx_hash())
        self._confirmed_tx_hashes = self._confirmed_tx_hashes | included
        self._mempool_hashes = self._mempool_hashes - included
        # drop any newly-confirmed txs from the pending pool
        new_mempool = []
        for tx in self.mempool:
            if tx.tx_hash() not in included:
                new_mempool.append(tx)
        self.mempool = new_mempool

    # switches to a different fork, from a given fork point and a list of new blocks to add on top of it
    def fork_switch(self, fork_point, new_blocks):
        discarded_txs = []
        for block in self.blocks[fork_point + 1:]:
            discarded_txs.extend(block.transactions)
        self.blocks = self.blocks[:fork_point + 1]
        self._confirmed_tx_hashes = set()
        for block in self.blocks:
            for tx in block.transactions:
                self._confirmed_tx_hashes.add(tx.tx_hash())
        for block in new_blocks:
            self._append(block)
        for tx in discarded_txs:
            self.add_transaction(tx)

    # the same as mine_next, but does not append the block to the chain, so we can check it is a valid extension beforehand
    def prepare_next(self, difficulty, timestamp = None, max_txs = None):
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
        return block
