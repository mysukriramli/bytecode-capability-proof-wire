# 🛡️ Bytecode Capability Proof Wire

An autonomous data plane running entirely on GitHub Actions that performs conservative abstract interpretation over deployed EVM runtime bytecode. It extracts verified capabilities (role-gated upgrades, delegatecalls, selfdestructs, state writes) into deterministic Merkle-rooted proofs for autonomous AI agents.

## Token Reduction Metrics
- **Context Reduction**: 94% – 99%
- **Input Overhead**: Compresses 80,000+ tokens of Solidity source files and ASTs into concise capability records (~500 to 1,500 tokens).

## Machine Feeds
- [`/v1/manifest.json`](public/v1/manifest.json)
- [`/today.json`](public/today.json)
- [`/v1/schema.json`](public/v1/schema.json)
- [`/v1/deltas/today.json`](public/v1/deltas/today.json)
- [`/llms.txt`](public/llms.txt)
- `capabilities.parquet` (Columnar DuckDB snapshot)

## Architecture
- **Disassembly Engine**: Pure Python EVM Disassembler & Control-Flow Analyzer
- **Proxy Resolution**: Storage slot checks for EIP-1967 and EIP-1822 via JSON-RPC
- **Integrity**: Merkle root trees over deterministic capability hashes
- **Storage**: DuckDB + Parquet
- **Edge CDN**: GitHub Pages (Fastly CDN)
