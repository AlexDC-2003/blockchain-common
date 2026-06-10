import hashlib
import struct
import unittest
from chain import EMPTY_TXS_HASH, HASH_SIZE, HEADER_SIZE, Block, Transaction, block_hash, compute_txs_hash, genesis_block, meets_difficulty, mine, pack_header

# Header serialization: fixed size and exact byte layout
class TestHeader(unittest.TestCase):
    def test_size_is_84(self):
        h = pack_header(b"\x00" * 32, b"\x11" * 32, 1234, 5, 6789)
        self.assertEqual(len(h), 84)
        self.assertEqual(HEADER_SIZE, 84)

    def test_layout_and_byte_order(self):
        # Each field lands at its expected offset, encoded big-endian
        prev = bytes(range(32))
        txs = bytes(range(32, 64))
        ts, diff, nonce = 0x0102030405060708, 0x0A0B0C0D, 0xFEEDFACECAFEBABE
        h = pack_header(prev, txs, ts, diff, nonce)
        self.assertEqual(h[:32], prev)
        self.assertEqual(h[32:64], txs)
        self.assertEqual(h[64:72], struct.pack(">Q", ts))
        self.assertEqual(h[72:76], struct.pack(">I", diff))
        self.assertEqual(h[76:84], struct.pack(">Q", nonce))

    def test_rejects_wrong_hash_size(self):
        # prev_hash / txs_hash must be exactly 32 bytes
        with self.assertRaises(AssertionError):
            pack_header(b"\x00" * 31, b"\x00" * 32, 0, 0, 0)
        with self.assertRaises(AssertionError):
            pack_header(b"\x00" * 32, b"\x00" * 33, 0, 0, 0)

    def test_block_hash_is_sha256_of_header(self):
        # block_hash is exactly hash of the packed header
        prev, txs, ts, diff, nonce = b"\x00" * 32, b"\x11" * 32, 1, 2, 3
        expected = hashlib.sha256(pack_header(prev, txs, ts, diff, nonce)).digest()
        self.assertEqual(block_hash(prev, txs, ts, diff, nonce), expected)
        self.assertEqual(len(expected), HASH_SIZE)


# Transaction hashing: exact formula and sensitivity to every field
class TestTxHash(unittest.TestCase):
    def test_tx_hash_formula(self):
        tx = Transaction(sender_key=b"sender", data=b"hello", timestamp=42, signature=b"sig")
        expected = hashlib.sha256(b"sender" + b"hello" + struct.pack(">q", 42) + b"sig").digest()
        self.assertEqual(tx.tx_hash(), expected)

    def test_tx_hash_changes_on_field_change(self):
        # Changing any single field must change the hash
        base = Transaction(b"k", b"d", 1, b"s")
        self.assertNotEqual(base.tx_hash(), Transaction(b"k2", b"d", 1, b"s").tx_hash())
        self.assertNotEqual(base.tx_hash(), Transaction(b"k", b"d2", 1, b"s").tx_hash())
        self.assertNotEqual(base.tx_hash(), Transaction(b"k", b"d", 2, b"s").tx_hash())
        self.assertNotEqual(base.tx_hash(), Transaction(b"k", b"d", 1, b"s2").tx_hash())


# Body commitment: empty-block sentinel and order-dependent concatenation
class TestTxsCommitment(unittest.TestCase):
    def test_empty_block_uses_sha256_of_empty(self):
        self.assertEqual(compute_txs_hash([]), hashlib.sha256(b"").digest())
        self.assertEqual(EMPTY_TXS_HASH, hashlib.sha256(b"").digest())
        self.assertNotEqual(EMPTY_TXS_HASH, b"\x00" * 32)

    def test_concatenation_order(self):
        # Commitment depends on tx order, so swapping txs yields a different hash
        t1 = Transaction(b"k1", b"d1", 1, b"s1")
        t2 = Transaction(b"k2", b"d2", 2, b"s2")
        expected = hashlib.sha256(t1.tx_hash() + t2.tx_hash()).digest()
        self.assertEqual(compute_txs_hash([t1, t2]), expected)
        self.assertNotEqual(compute_txs_hash([t1, t2]), compute_txs_hash([t2, t1]))


# Difficulty target: leading-zero-bit checks at and across byte boundaries
class TestDifficulty(unittest.TestCase):
    def test_zero_bits_always_satisfied(self):
        # Zero difficulty accepts any digest
        self.assertTrue(meets_difficulty(b"\xff" * 32, 0))

    def test_byte_boundary(self):
        # One zero byte satisfies 8 bits but not 9
        d = b"\x00\xff" + b"\x00" * 30
        self.assertTrue(meets_difficulty(d, 8))
        self.assertFalse(meets_difficulty(d, 9))

    def test_within_byte(self):
        # Partial-byte difficulty checks the top bits of the next byte
        good = b"\x00\x0f" + b"\x00" * 30
        bad = b"\x00\x10" + b"\x00" * 30
        self.assertTrue(meets_difficulty(good, 12))
        self.assertFalse(meets_difficulty(bad, 12))

    def test_full_zero_digest(self):
        # All-zero digest meets the maximum bit difficulty
        self.assertTrue(meets_difficulty(b"\x00" * 32, 256))


# Mining: the returned nonce actually produces a hash meeting the target
class TestMining(unittest.TestCase):
    def test_mined_hash_meets_difficulty(self):
        prev = b"\x00" * 32
        txs = EMPTY_TXS_HASH
        nonce, h = mine(prev, txs, timestamp=1700000000, difficulty=10)
        self.assertTrue(meets_difficulty(h, 10))
        self.assertEqual(h, block_hash(prev, txs, 1700000000, 10, nonce))


# Block self-validation: PoW validity and body/commitment consistency
class TestBlock(unittest.TestCase):
    def test_valid_block_with_txs(self):
        # A properly mined block with a matching commitment passes both checks
        prev = b"\x00" * 32
        txs = [Transaction(b"k", b"d", 1, b"s")]
        commitment = compute_txs_hash(txs)
        nonce, _ = mine(prev, commitment, timestamp=1, difficulty=6)
        b = Block(prev, commitment, 1, 6, nonce, txs)
        self.assertTrue(b.is_valid_pow())
        self.assertTrue(b.is_body_consistent())

    def test_body_mismatch_detected(self):
        # txs_hash that doesn't match the body is caught
        prev = b"\x00" * 32
        txs = [Transaction(b"k", b"d", 1, b"s")]
        b = Block(prev, b"\xff" * 32, 1, 0, 0, txs)
        self.assertFalse(b.is_body_consistent())

    def test_bad_pow_detected(self):
        # nonce=0 against high difficulty fails PoW
        prev = b"\x00" * 32
        b = Block(prev, EMPTY_TXS_HASH, 1, 32, 0)
        self.assertFalse(b.is_valid_pow())


# Genesis block: deterministic and well-formed
class TestGenesis(unittest.TestCase):
    def test_genesis_is_deterministic(self):
        # Same genesis every time
        self.assertEqual(genesis_block().hash, genesis_block().hash)

    def test_genesis_shape(self):
        # Fixed fields, empty body, and a valid 84-byte header
        g = genesis_block()
        self.assertEqual(g.prev_hash, b"\x00" * 32)
        self.assertEqual(g.txs_hash, EMPTY_TXS_HASH)
        self.assertEqual(g.transactions, [])
        self.assertTrue(g.is_valid_pow())
        self.assertTrue(g.is_body_consistent())
        self.assertEqual(len(g.header_bytes()), 84)


if __name__ == "__main__":
    unittest.main()
