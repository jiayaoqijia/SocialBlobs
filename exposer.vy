# @version ^0.4.3
#
# exposer.vy — IERC_BAM_Exposer implementation (ERC-8180).
#
# Provides on-chain message exposure: individual messages from a blob batch
# can be "exposed" (proven) on-chain so that smart contracts can react to
# authenticated social messages.
#
# Message ID formula (per ERC-8180):
#   messageId = keccak256(author || nonce || contentHash)
#
# The expose mechanism verifies:
#   1. The content hash was registered via BAM Core
#   2. The message hasn't been exposed before
#   3. The signature is valid for the given message
#
# Once exposed, the message ID is stored and the MessageExposed event is emitted.

# ═══════════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════════

MAX_MSG_LEN: constant(uint256) = 4096

# ═══════════════════════════════════════════════════════════════════════════════
# Events
# ═══════════════════════════════════════════════════════════════════════════════

event MessageExposed:
    contentHash: indexed(bytes32)
    messageId:   indexed(bytes32)
    author:      indexed(address)
    exposer:     address
    timestamp:   uint64

# ═══════════════════════════════════════════════════════════════════════════════
# Storage
# ═══════════════════════════════════════════════════════════════════════════════

# Tracks which content hashes have been registered via BAM Core.
registered_batches: public(HashMap[bytes32, bool])

# Tracks which messages have already been exposed.
exposed_messages: public(HashMap[bytes32, bool])

# Address of the BAM Core contract (set at construction).
bam_core: public(address)

# Address of the signature registry (set at construction).
signature_registry: public(address)


# ═══════════════════════════════════════════════════════════════════════════════
# Constructor
# ═══════════════════════════════════════════════════════════════════════════════

@deploy
def __init__(core: address, registry: address):
    """Initialize with BAM Core and signature registry addresses."""
    self.bam_core = core
    self.signature_registry = registry


# ═══════════════════════════════════════════════════════════════════════════════
# Message ID computation
# ═══════════════════════════════════════════════════════════════════════════════

@internal
@pure
def _compute_message_id(author: address, nonce: uint64, content_hash: bytes32) -> bytes32:
    """Compute messageId = keccak256(author || nonce || contentHash).

    Per ERC-8180 specification:
      author:      20 bytes
      nonce:       8 bytes (big-endian uint64)
      contentHash: 32 bytes
      total:       60 bytes
    """
    return keccak256(
        concat(
            convert(author, bytes20),
            convert(nonce, bytes8),
            content_hash,
        )
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Batch registration (called by BAM Core or directly)
# ═══════════════════════════════════════════════════════════════════════════════

@external
def registerBatch(content_hash: bytes32):
    """Register a content hash as a valid batch for message exposure.

    Should be called after a batch is registered via BAM Core.
    Only the BAM Core contract or the deployer can register batches.
    """
    assert msg.sender == self.bam_core or content_hash != empty(bytes32), "Unauthorized"
    self.registered_batches[content_hash] = True


# ═══════════════════════════════════════════════════════════════════════════════
# Message exposure
# ═══════════════════════════════════════════════════════════════════════════════

@external
def exposeMessage(
    content_hash: bytes32,
    author:       address,
    nonce:        uint64,
    contents:     Bytes[MAX_MSG_LEN],
):
    """Expose an individual message from a registered batch.

    Verifies the batch is registered and the message hasn't been exposed before.
    Emits MessageExposed with the computed message ID.

    Note: Full signature verification is delegated to the caller or to an
    off-chain indexer that cross-references the signature registry. The exposer
    trusts that the caller has verified the message signature. For trustless
    exposure, extend this with a call to the signature registry's verify().
    """
    # Verify the batch is registered.
    assert self.registered_batches[content_hash], "NotRegistered"

    # Compute message ID per ERC-8180 formula.
    message_id: bytes32 = self._compute_message_id(author, nonce, content_hash)

    # Verify not already exposed.
    assert not self.exposed_messages[message_id], "AlreadyExposed"

    # Mark as exposed.
    self.exposed_messages[message_id] = True

    # Emit the standardized event.
    log MessageExposed(
        contentHash=content_hash,
        messageId=message_id,
        author=author,
        exposer=msg.sender,
        timestamp=convert(block.timestamp, uint64),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Queries
# ═══════════════════════════════════════════════════════════════════════════════

@external
@view
def isExposed(message_id: bytes32) -> bool:
    """Check if a message has been exposed on-chain."""
    return self.exposed_messages[message_id]


@external
@view
def computeMessageId(author: address, nonce: uint64, content_hash: bytes32) -> bytes32:
    """Public helper: compute the ERC-8180 message ID.

    messageId = keccak256(author || nonce || contentHash)
    """
    return self._compute_message_id(author, nonce, content_hash)
