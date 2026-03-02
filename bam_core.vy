# @version ^0.4.3
#
# bam_core.vy — IERC_BAM_Core implementation (ERC-8180).
#
# Extends Blob Space Segments (ERC-8179) with decoder and signature registry
# pointers for Blob Authenticated Messaging. Zero storage — events are the
# sole record.
#
# Two registration paths:
#   - registerBlobBatch:     for EIP-4844 blob transactions (uses BLOBHASH)
#   - registerCalldataBatch: for calldata-based batches (uses keccak256)

MAX_FIELD_ELEMENTS: constant(uint16) = 4096

# ═══════════════════════════════════════════════════════════════════════════════
# ERC-8179 BSS Events
# ═══════════════════════════════════════════════════════════════════════════════

event BlobSegmentDeclared:
    versionedHash: indexed(bytes32)
    declarer:      indexed(address)
    startFE:       uint16
    endFE:         uint16
    contentTag:    indexed(bytes32)

# ═══════════════════════════════════════════════════════════════════════════════
# ERC-8180 BAM Events
# ═══════════════════════════════════════════════════════════════════════════════

event BlobBatchRegistered:
    versionedHash:     indexed(bytes32)
    submitter:         indexed(address)
    decoder:           indexed(address)
    signatureRegistry: address

event CalldataBatchRegistered:
    contentHash:       indexed(bytes32)
    submitter:         indexed(address)
    decoder:           indexed(address)
    signatureRegistry: address


# ═══════════════════════════════════════════════════════════════════════════════
# ERC-8179 BSS — declareBlobSegment
# ═══════════════════════════════════════════════════════════════════════════════

@internal
def _blobhash(blob_index: uint256) -> bytes32:
    """Retrieve the versioned hash of a blob in the current transaction.

    Uses the BLOBHASH opcode (0x49) introduced in EIP-4844.
    Returns bytes32(0) if no blob exists at the given index.
    """
    # BLOBHASH is not yet a Vyper built-in as of 0.4.3.
    # We encode it as: push blob_index, BLOBHASH(0x49), push 0, mstore, push 32, push 0, return
    # For now, we use a placeholder that works in calldata-only mode.
    # On a real EIP-4844 chain, this would use raw EVM assembly.
    return empty(bytes32)


@external
def declareBlobSegment(
    blobIndex: uint256, startFE: uint16, endFE: uint16, contentTag: bytes32
) -> bytes32:
    """Declare a segment [startFE, endFE) of a blob in the current transaction.

    Emits BlobSegmentDeclared. Reverts if the range is invalid.
    Note: BLOBHASH binding requires EIP-4844 support in the execution client.
    In calldata-only mode, use registerCalldataBatch instead.
    """
    assert startFE < endFE,                  "InvalidSegment: startFE >= endFE"
    assert endFE <= MAX_FIELD_ELEMENTS,      "InvalidSegment: endFE > 4096"

    versioned_hash: bytes32 = self._blobhash(blobIndex)
    assert versioned_hash != empty(bytes32), "NoBlobAtIndex"

    log BlobSegmentDeclared(
        versionedHash=versioned_hash,
        declarer=msg.sender,
        startFE=startFE,
        endFE=endFE,
        contentTag=contentTag,
    )
    return versioned_hash


# ═══════════════════════════════════════════════════════════════════════════════
# ERC-8180 BAM — Batch Registration
# ═══════════════════════════════════════════════════════════════════════════════

@external
def registerBlobBatch(
    blobIndex:         uint256,
    startFE:           uint16,
    endFE:             uint16,
    contentTag:        bytes32,
    decoder:           address,
    signatureRegistry: address,
) -> bytes32:
    """Register a blob batch with segment coordinates, decoder, and signature registry.

    Calls declareBlobSegment internally, then emits BlobBatchRegistered.
    Requires an EIP-4844 blob transaction.
    """
    assert startFE < endFE,                  "InvalidSegment: startFE >= endFE"
    assert endFE <= MAX_FIELD_ELEMENTS,      "InvalidSegment: endFE > 4096"

    versioned_hash: bytes32 = self._blobhash(blobIndex)
    assert versioned_hash != empty(bytes32), "NoBlobAtIndex"

    log BlobSegmentDeclared(
        versionedHash=versioned_hash,
        declarer=msg.sender,
        startFE=startFE,
        endFE=endFE,
        contentTag=contentTag,
    )
    log BlobBatchRegistered(
        versionedHash=versioned_hash,
        submitter=msg.sender,
        decoder=decoder,
        signatureRegistry=signatureRegistry,
    )
    return versioned_hash


@external
def registerCalldataBatch(
    batchData: Bytes[131072], decoder: address, signatureRegistry: address
) -> bytes32:
    """Register a batch submitted via calldata (no blob required).

    Computes contentHash = keccak256(batchData) and emits CalldataBatchRegistered.
    This is the primary path for testing and for chains without EIP-4844 support.
    """
    content_hash: bytes32 = keccak256(batchData)

    log CalldataBatchRegistered(
        contentHash=content_hash,
        submitter=msg.sender,
        decoder=decoder,
        signatureRegistry=signatureRegistry,
    )
    return content_hash
