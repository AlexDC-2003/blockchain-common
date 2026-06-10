# Blockchain 2026 — Labs

Course code for the IPv8 labs.

## Setup

```bash
pip install -r requirements.txt
```

Each lab uses an IPv8 `.pem` key file. Labs 2 and 3 reuse the key each member registered in Lab 1.

## Lab 2 — Coordinated Group Signing over IPv8

3-person group signs 3 challenge nonces from the server within a 10-second wall-clock budget. Each round must be submitted by a different member.

### Files
- `assignment2/part1.py` — one-time group registration. Sends the 3 member pubkeys (in canonical order) to the server and prints the returned `group_id`.
- `assignment2/part2.py` — the timed signing client. Round-robin: member 1 submits round 1, member 2 round 2, member 3 round 3. Each member runs the same script with their own `.pem`.

### Running

**Part 1 (one person):**

```bash
cd assignment2
python part1.py
```

Wait for `Response: success=True, group_id=...`. Save the `group_id`, then Ctrl+C.

**Part 2 (all 3 teammates):**

Each teammate fills in their own `MY_KEY_FILE` and pastes the shared `GROUP_ID` + 3 member pubkeys, then runs:

```bash
cd assignment2
python part2.py
```

Each script discovers the other 2 + the server, does a Ready handshake, then member 1 fires round 1. The chain auto-progresses through all 3 rounds via `RoundDone` messages.

### Notes
- Uses the same `.pem` from Lab 1.
- Intra-team messages have retransmission tasks to handle UDP packet loss within the 10s budget.
- All 3 members must hardcode the 3 pubkeys in the same canonical order; this order also determines which round each member submits.


## Lab 3 — PoW Blockchain over IPv8

3-node Proof-of-Work blockchain. Each member runs one node; nodes mine, propagate, and converge on a single chain. After registration, the server joins the blockchain community, submits a test transaction, and verifies the chain across all 3 nodes.

### Files
- `assignment3/part1.py` — one-time registration. Sends the `group_id` + the self-chosen blockchain community ID to the server so it knows which community to join.
- `assignment3/chain.py` — chain primitives: block header packing (84 bytes), `block_hash`, `tx_hash`, `txs_hash` body commitment, PoW search, genesis block, and `serialize_txs`/`deserialize_txs` for sending transactions.
- `assignment3/node.py` — `BlockChain` class. Owns the blocks list, mempool, mining (`prepare_next`), validation, append, and fork-switch logic.
- `assignment3/community.py` — the IPv8 node. Server-facing handlers, block propagation between teammates, and the mining loop.

### Running

**Part 1 (one person):**

```bash
cd assignment3
python part1.py
```

Wait for `Response: success=True, message=...`. Then Ctrl+C.

**Part 2 (all 3 teammates):**

Each teammate fills in their own `MY_KEY_FILE`, then runs:

```bash
cd assignment3
python community.py
```

Each node joins the blockchain community, discovers the others, and starts mining. The server queries the nodes in the background; pass confirmation can be seen when running `part1.py` again after a good-looking run.

### Tests

Unit tests for the chain primitives and single-node mining + validation live in `assignment3/tests/`. Run them with `pytest` from a virtualenv:

```bash
cd assignment3
python3 -m venv .venv          # needs python3-venv (sudo apt install python3-venv)
source .venv/bin/activate
pip install pytest
pytest tests/
```

`tests/conftest.py` puts `assignment3/` on `sys.path` so the tests import `chain`/`node` the same way the rest of the code does. Always run via `pytest` (not `python3 tests/test_chain.py` directly), otherwise the import path isn't set up.

### Notes
- Uses the same `.pem` from Lab 1.
- Mining difficulty is set high enough (`MINING_DIFFICULTY = 24`) + a 3s sleep between blocks to keep propagation ahead of new blocks and prevent the 3 chains from diverging.
- Re-run `part1.py` to reset the server's retry counter (or if the blockchain community ID changes).
- All 3 members must hardcode the 3 pubkeys in the same canonical order.