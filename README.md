# SocialBlobs

An implementation of [ERC-8180 (Blob Authenticated Messaging)](https://github.com/ethereum/ERCs/pull/1578) and [ERC-8179 (Blob Space Segments)](https://github.com/ethereum/ERCs/pull/1577) — a minimalistic "social on Ethereum blobs/calldata" protocol.

## ERC Coverage

| Interface | File | Status |
|-----------|------|--------|
| **IERC_BSS** (ERC-8179) — Blob Space Segments | `bam_core.vy` | `declareBlobSegment` + `BlobSegmentDeclared` event |
| **IERC_BAM_Core** (ERC-8180) — Batch Registration | `bam_core.vy` | `registerBlobBatch` + `registerCalldataBatch` |
| **IERC_BAM_Decoder** (ERC-8180) — Message Decoding | `decoder.vy` | `decode()` returning messages + signature data |
| **IERC_BAM_SignatureRegistry** (ERC-8180) — Key Registry | `signature_registry.vy` | BLS12-381 scheme with registration, verification, aggregation |
| **IERC_BAM_Exposer** (ERC-8180) — Message Exposure | `exposer.vy` | `exposeMessage` + `isExposed` + `MessageExposed` event |

## Files

| File | Description |
|------|-------------|
| `bam_core.vy` | BAM Core contract — BSS segment declaration + batch registration (ERC-8179/8180) |
| `decoder.vy` | Blob decoder — extracts messages and aggregate BLS signature from payload |
| `signature_registry.vy` | BLS12-381 signature registry — key registration with PoP, single + aggregate verification |
| `exposer.vy` | Message exposer — on-chain message proving with `messageId = keccak256(author \|\| nonce \|\| contentHash)` |
| `blob_encoder.py` | Python encoder — constructs binary blob format from messages + signatures |
| `data_signer.py` | Python BLS12-381 signing — key generation, signing, aggregation, verification |
| `test.py` | End-to-end integration test — deploys all contracts, full signing/encoding/verification/exposure flow |
| `hash_to_point_test.py` | hash_to_G2 test — verifies Vyper implementation matches py_ecc reference |

## Quick Start

```bash
pip install -r requirements.txt
python test.py
```

## Related

- [ERC-8180: Blob Authenticated Messaging](https://ethereum-magicians.org/t/blob-authenticated-messaging-bam/27868)
- [ERC-8179: Blob Space Segments](https://ethereum-magicians.org/t/blob-space-segments-bss/27867)
