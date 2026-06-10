import unittest

from chain import EMPTY_TXS_HASH, Block, Transaction, block_hash, compute_txs_hash, genesis_block, mine
from node import BlockChain

DIFF = 6  # low difficulty so tests mine quickly

class TestInitialState(unittest.TestCase):
    def test_starts_at_genesis(self):
        c = BlockChain()
        self.assertEqual(c.height, 0)
        self.assertEqual(c.tip.hash, genesis_block().hash)
        self.assertEqual(c.mempool, [])

# test mempool admission and de-duplication rules
class TestMempool(unittest.TestCase):
    def test_add_unique_tx(self):
        # A new tx is accepted into the mempool
        c = BlockChain()
        tx = Transaction(b"k", b"d", 1, b"s")
        self.assertTrue(c.add_transaction(tx))
        self.assertEqual(c.mempool, [tx])

    def test_reject_duplicate_in_mempool(self):
        # Re-adding a pending tx is rejected
        c = BlockChain()
        tx = Transaction(b"k", b"d", 1, b"s")
        c.add_transaction(tx)
        self.assertFalse(c.add_transaction(tx))
        self.assertEqual(len(c.mempool), 1)

    def test_reject_already_confirmed(self):
        # A tx already mined into a block can't re-enter the mempool
        c = BlockChain()
        tx = Transaction(b"k", b"d", 1, b"s")
        c.add_transaction(tx)
        c.mine_next(difficulty=DIFF, timestamp=1)
        self.assertFalse(c.add_transaction(tx))


# Mining onto the chain: extension, mempool draining, and limits
class TestMining(unittest.TestCase):
    def test_mine_empty_block_extends_chain(self):
        # Mining with no pending txs still advances the tip by one valid block
        c = BlockChain()
        parent_hash = c.tip.hash
        b = c.mine_next(difficulty=DIFF, timestamp=1)
        self.assertEqual(c.height, 1)
        self.assertEqual(c.tip, b)
        self.assertEqual(b.prev_hash, parent_hash)
        self.assertEqual(b.txs_hash, EMPTY_TXS_HASH)
        self.assertTrue(b.is_valid_pow())
        self.assertTrue(b.is_body_consistent())

    def test_mine_includes_mempool_and_drains(self):
        # Pending txs go into the block and are removed from the mempool
        c = BlockChain()
        tx1 = Transaction(b"k1", b"d1", 1, b"s1")
        tx2 = Transaction(b"k2", b"d2", 2, b"s2")
        c.add_transaction(tx1)
        c.add_transaction(tx2)
        b = c.mine_next(difficulty=DIFF, timestamp=10)
        self.assertEqual(b.transactions, [tx1, tx2])
        self.assertEqual(b.txs_hash, compute_txs_hash([tx1, tx2]))
        self.assertEqual(c.mempool, [])

    def test_mine_respects_max_txs(self):
        # max_txs caps inclusion, the leftover tx stays pending
        c = BlockChain()
        txs = [Transaction(f"k{i}".encode(), b"d", i, b"s") for i in range(3)]
        for tx in txs:
            c.add_transaction(tx)
        b = c.mine_next(difficulty=DIFF, timestamp=10, max_txs=2)
        self.assertEqual(b.transactions, txs[:2])
        self.assertEqual(c.mempool, [txs[2]])

    def test_chain_grows_correctly(self):
        # Successive blocks link tip-to-tip and the block list stays in order
        c = BlockChain()
        b1 = c.mine_next(difficulty=DIFF, timestamp=1)
        b2 = c.mine_next(difficulty=DIFF, timestamp=2)
        self.assertEqual(c.height, 2)
        self.assertEqual(b2.prev_hash, b1.hash)
        self.assertEqual(c.blocks, [genesis_block(), b1, b2])


# try_append / validate_extension acceptance and rejection paths
class TestValidation(unittest.TestCase):
    # Helper function for tests, mine a valid block building directly on `parent`
    def _mine_on(self, parent: Block, txs=None, difficulty=DIFF, timestamp=1):
        txs = txs or []
        commitment = compute_txs_hash(txs)
        nonce, _ = mine(parent.hash, commitment, timestamp, difficulty)
        return Block(parent.hash, commitment, timestamp, difficulty, nonce, txs)

    def test_accepts_well_formed_block(self):
        # A valid extension is appended and becomes the new tip
        c = BlockChain()
        block = self._mine_on(c.tip)
        result = c.try_append(block)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(c.tip, block)

    def test_rejects_wrong_prev_hash(self):
        # A block not linking to the tip is rejected and the chain is unchanged
        c = BlockChain()
        bogus_parent = Block(b"\xaa" * 32, EMPTY_TXS_HASH, 0, 0, 0)
        block = self._mine_on(bogus_parent)
        result = c.try_append(block)
        self.assertFalse(result.ok)
        self.assertIn("prev_hash", result.reason)
        self.assertEqual(c.height, 0)

    def test_rejects_invalid_pow(self):
        c = BlockChain()
        # Hand-roll a block whose hash almost certainly does not meet difficulty.
        bad = Block(c.tip.hash, EMPTY_TXS_HASH, 1, 32, 0)
        result = c.try_append(bad)
        self.assertFalse(result.ok)
        self.assertIn("PoW", result.reason)
        self.assertEqual(c.height, 0)

    def test_rejects_body_mismatch(self):
        # A valid-PoW block whose commitment doesn't match its body is rejected
        c = BlockChain()
        tx = Transaction(b"k", b"d", 1, b"s")
        wrong_commitment = b"\xff" * 32
        nonce, _ = mine(c.tip.hash, wrong_commitment, 1, DIFF)
        block = Block(c.tip.hash, wrong_commitment, 1, DIFF, nonce, [tx])
        result = c.try_append(block)
        self.assertFalse(result.ok)
        self.assertIn("txs_hash", result.reason)
        self.assertEqual(c.height, 0)

    def test_validate_does_not_mutate(self):
        # validate_extension is read-only, it never changes the chain
        c = BlockChain()
        good = self._mine_on(c.tip)
        before = list(c.blocks)
        c.validate_extension(good)
        self.assertEqual(c.blocks, before)


# A block mined on one chain validates and appends on another fresh chain
class TestMineThenValidateInterop(unittest.TestCase):
    def test_block_mined_on_one_chain_validates_on_a_fresh_chain(self):
        producer = BlockChain()
        producer.add_transaction(Transaction(b"k", b"d", 1, b"s"))
        b = producer.mine_next(difficulty=DIFF, timestamp=5)

        consumer = BlockChain()
        result = consumer.try_append(b)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(consumer.tip.hash, b.hash)
        self.assertEqual(consumer.height, 1)


if __name__ == "__main__":
    unittest.main()
