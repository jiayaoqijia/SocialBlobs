"""test.py

End-to-end integration test using an in-memory eth_tester chain.

Deploys the BAM Core contract (ERC-8180), blob decoder (IERC_BAM_Decoder),
BLS signature registry (IERC_BAM_SignatureRegistry), and message exposer
(IERC_BAM_Exposer); signs messages with BLS keys; constructs and registers
a blob; then verifies decoding, aggregate signature verification, and
message exposure on-chain.
"""

from pathlib import Path
from typing import List, Tuple

from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
from vyper import compile_code

from data_signer import Signer, aggregate_signatures
from blob_encoder import encode_blob


# ---------------------------------------------------------------------------
# Compile helpers
# ---------------------------------------------------------------------------

def compile_vyper(source: str) -> dict:
    """Compile a Vyper source string; return {"abi": ..., "bytecode": ...}."""
    return compile_code(source, output_formats=["abi", "bytecode"])


def deploy(w3: Web3, compiled: dict, deployer: str, *args):
    """Deploy a compiled contract and return the bound contract instance."""
    factory = w3.eth.contract(abi=compiled["abi"], bytecode=compiled["bytecode"])
    receipt = w3.eth.wait_for_transaction_receipt(
        factory.constructor(*args).transact({"from": deployer})
    )
    return w3.eth.contract(address=receipt.contractAddress, abi=compiled["abi"])


# ---------------------------------------------------------------------------
# Chain setup
# ---------------------------------------------------------------------------

w3 = Web3(EthereumTesterProvider())
# eth_tester provides 10 pre-funded accounts.
# accounts[0] is the deployer; accounts[1..N] are the per-signer Ethereum accounts
# so each BLS key can be registered under a distinct address.
accounts = w3.eth.accounts
deployer = accounts[0]
w3.eth.default_account = deployer

# ---------------------------------------------------------------------------
# Deploy contracts
# ---------------------------------------------------------------------------

core     = deploy(w3, compile_vyper(Path("bam_core.vy").read_text()),            deployer)
decoder  = deploy(w3, compile_vyper(Path("decoder.vy").read_text()),             deployer)
registry = deploy(w3, compile_vyper(Path("signature_registry.vy").read_text()),  deployer)
exposer  = deploy(w3, compile_vyper(Path("exposer.vy").read_text()),             deployer,
                  core.address, registry.address)

print(f"BAM Core:    {core.address}")
print(f"Decoder:     {decoder.address}")
print(f"Registry:    {registry.address}")
print(f"Exposer:     {exposer.address}")

# ---------------------------------------------------------------------------
# BLS signing
# ---------------------------------------------------------------------------

msg_contents = [b"hello world", b"test message", b"data blobs rock"]
n = len(msg_contents)

signers   = [Signer.generate() for _ in range(n)]
sigs      = [s.sign(m) for s, m in zip(signers, msg_contents)]
agg_sig   = aggregate_signatures(sigs)

# Each BLS signer uses a distinct Ethereum account so their public keys are
# stored at different addresses in the registry mapping.
signer_accounts = accounts[1:n + 1]
nonces: List[int] = list(range(n))
message_tuples: List[Tuple[str, int, bytes]] = list(
    zip(signer_accounts, nonces, msg_contents)
)
blob = encode_blob(message_tuples, sigs)

# ---------------------------------------------------------------------------
# Register BLS keys (one per Ethereum account)
# ---------------------------------------------------------------------------

for i, (signer, eth_acct) in enumerate(zip(signers, signer_accounts)):
    registry.functions.register(signer.public_bytes(), signer.make_pop()).transact(
        {"from": eth_acct}
    )
    print(f"PoP {i} registered for {eth_acct}")

print("Key registration complete")

# ---------------------------------------------------------------------------
# Register blob on-chain via BAM Core and verify the event
# ---------------------------------------------------------------------------

receipt = w3.eth.wait_for_transaction_receipt(
    core.functions.registerCalldataBatch(blob, decoder.address, registry.address)
        .transact({"from": deployer})
)

logs = core.events.CalldataBatchRegistered().process_receipt(receipt)
assert logs,                                         "No CalldataBatchRegistered event"
assert logs[0].args.submitter == deployer,           "Wrong submitter"
content_hash = logs[0].args.contentHash
assert content_hash == Web3.keccak(blob),            "Wrong content hash"
assert logs[0].args.decoder == decoder.address,      "Wrong decoder address"
assert logs[0].args.signatureRegistry == registry.address, "Wrong registry address"
print("✅ BAM Core registration passed (CalldataBatchRegistered event verified)")

# ---------------------------------------------------------------------------
# Decode the blob and verify its contents
# ---------------------------------------------------------------------------

decoded_messages, decoded_sig = decoder.functions.decode(blob).call()

assert decoded_messages == message_tuples, "Decoded messages do not match"
assert decoded_sig == agg_sig,             "Decoded signature does not match"
print("✅ Decoder test passed")

# ---------------------------------------------------------------------------
# Verify aggregate BLS signature on-chain
# ---------------------------------------------------------------------------

owners   = list(signer_accounts)
messages = list(msg_contents)

assert registry.functions.verifyAggregated(owners, messages, agg_sig).call(), \
    "verifyAggregated rejected a valid aggregate signature"
print("✅ Aggregate signature verified on-chain")

# Negative check: bit-flipped signature must be rejected (may revert or return False).
bad_sig = bytes([agg_sig[0] ^ 0xFF]) + agg_sig[1:]
try:
    bad_result = registry.functions.verifyAggregated(owners, messages, bad_sig).call()
except Exception:
    bad_result = False
assert not bad_result, "verifyAggregated accepted a tampered signature"
print("✅ Tampered signature correctly rejected")

# Negative check: wrong message must be rejected.
wrong_messages = [b"wrong message"] + messages[1:]
try:
    wrong_result = registry.functions.verifyAggregated(owners, wrong_messages, agg_sig).call()
except Exception:
    wrong_result = False
assert not wrong_result, "verifyAggregated accepted wrong messages"
print("✅ Wrong message correctly rejected")

# ---------------------------------------------------------------------------
# Test IERC_BAM_Exposer — message exposure (ERC-8180)
# ---------------------------------------------------------------------------

# Register the batch in the exposer so messages can be exposed.
exposer.functions.registerBatch(content_hash).transact({"from": deployer})

# Expose the first message.
author_0  = signer_accounts[0]
nonce_0   = 0
content_0 = msg_contents[0]

# Verify message ID computation matches the ERC-8180 formula:
#   messageId = keccak256(author || nonce || contentHash)
computed_id = exposer.functions.computeMessageId(author_0, nonce_0, content_hash).call()
expected_id = Web3.keccak(
    Web3.to_bytes(hexstr=author_0) + nonce_0.to_bytes(8, "big") + content_hash
)
assert computed_id == expected_id, "Message ID mismatch"
print("✅ Message ID computation matches ERC-8180 formula")

# Message should not be exposed yet.
assert not exposer.functions.isExposed(computed_id).call(), "Message should not be exposed yet"

# Expose the message.
receipt = w3.eth.wait_for_transaction_receipt(
    exposer.functions.exposeMessage(content_hash, author_0, nonce_0, content_0)
        .transact({"from": deployer})
)

# Verify the MessageExposed event.
logs = exposer.events.MessageExposed().process_receipt(receipt)
assert logs,                                     "No MessageExposed event"
assert logs[0].args.contentHash == content_hash, "Wrong contentHash in event"
assert logs[0].args.messageId == computed_id,    "Wrong messageId in event"
assert logs[0].args.author == author_0,          "Wrong author in event"
assert logs[0].args.exposer == deployer,         "Wrong exposer in event"
print("✅ Message exposed on-chain (MessageExposed event verified)")

# Message should now be exposed.
assert exposer.functions.isExposed(computed_id).call(), "Message should be exposed"

# Double-exposure must fail.
try:
    exposer.functions.exposeMessage(content_hash, author_0, nonce_0, content_0) \
        .transact({"from": deployer})
    assert False, "Double exposure should have reverted"
except Exception:
    pass
print("✅ Double exposure correctly rejected")

# Expose a second message to verify independence.
author_1  = signer_accounts[1]
nonce_1   = 1
content_1 = msg_contents[1]
id_1 = exposer.functions.computeMessageId(author_1, nonce_1, content_hash).call()
assert not exposer.functions.isExposed(id_1).call(), "Message 1 should not be exposed yet"
exposer.functions.exposeMessage(content_hash, author_1, nonce_1, content_1) \
    .transact({"from": deployer})
assert exposer.functions.isExposed(id_1).call(), "Message 1 should now be exposed"
print("✅ Second message exposed independently")

# Unregistered batch must fail.
fake_hash = Web3.keccak(b"fake batch")
try:
    exposer.functions.exposeMessage(fake_hash, author_0, 99, b"fake") \
        .transact({"from": deployer})
    assert False, "Unregistered batch should have reverted"
except Exception:
    pass
print("✅ Unregistered batch correctly rejected")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print()
print(f"  Blob (hex)     : 0x{blob.hex()}")
print(f"  Aggregate sig  : 0x{agg_sig.hex()}")
print(f"  Content hash   : 0x{content_hash.hex()}")
print(f"  Message ID #0  : 0x{computed_id.hex()}")
print("✅ All tests passed")
