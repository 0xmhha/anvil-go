# Anvil-Go

A high-performance local Ethereum development node simulator written in Go, designed specifically for StableNet blockchain testing and development. Fully compatible with Foundry and Hardhat toolchains.

## Features

### Core Capabilities
- **Fast Local Development**: Instant transaction confirmation with auto-mining
- **Foundry Compatible**: Full support for `anvil_*` cheat codes
- **Hardhat Compatible**: Support for `evm_*` methods
- **StableNet Native**: First-class support for WBFT consensus and system contracts

### State Management
- **State Snapshots**: Save and restore blockchain state instantly
- **State Dump/Load**: Export and import full blockchain state
- **Account Impersonation**: Send transactions as any address without private keys

### Testing Features
- **Time Manipulation**: Control block timestamps for testing time-dependent logic
- **Gas Price Control**: Set custom gas prices and base fees
- **Transaction Pool**: Full mempool simulation with pending transaction queries
- **Transaction Tracing**: Debug traces for transaction execution analysis

### Advanced Features
- **Fork Mode**: Fork from any EVM-compatible chain
- **Validator Management**: StableNet-specific validator operations
- **Debug Tracing**: Full debug_traceTransaction and debug_traceCall support

## Installation

```bash
# Build from source
make build

# Install to GOPATH/bin
make install
```

## Quick Start

```bash
# Start with default settings
anvil

# Start with custom port
anvil --port 8546

# Start with more test accounts
anvil --accounts 20

# Start with StableNet system contracts
anvil --stablenet
```

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `127.0.0.1` | Host to listen on |
| `--port` | `8545` | Port to listen on |
| `--chain-id` | `31337` | Chain ID |
| `--accounts` | `10` | Number of test accounts |
| `--balance` | `10000` | Initial balance in ETH |
| `--block-time` | `0` | Block time in seconds (0 = auto-mine) |
| `--stablenet` | `false` | Deploy StableNet system contracts |

## RPC Methods

### Standard Ethereum JSON-RPC

#### Chain Information
| Method | Description |
|--------|-------------|
| `eth_chainId` | Returns the chain ID |
| `eth_blockNumber` | Returns the current block number |
| `eth_gasPrice` | Returns the current gas price |
| `net_version` | Returns the network ID |
| `net_listening` | Returns true if listening for connections |
| `web3_clientVersion` | Returns the client version |

#### Account State
| Method | Description |
|--------|-------------|
| `eth_getBalance` | Returns the balance of an address |
| `eth_getCode` | Returns the code at an address |
| `eth_getStorageAt` | Returns storage at a position |
| `eth_getTransactionCount` | Returns the nonce of an address |

#### Transactions
| Method | Description |
|--------|-------------|
| `eth_sendTransaction` | Sends a transaction |
| `eth_sendRawTransaction` | Sends a signed transaction |
| `eth_call` | Executes a call without creating a transaction |
| `eth_estimateGas` | Estimates gas for a transaction |
| `eth_getTransactionReceipt` | Returns transaction receipt |
| `eth_getTransactionByHash` | Returns transaction by hash |

#### Blocks
| Method | Description |
|--------|-------------|
| `eth_getBlockByNumber` | Returns block by number |
| `eth_getBlockByHash` | Returns block by hash |
| `eth_getBlockTransactionCountByNumber` | Returns transaction count in block |
| `eth_getBlockTransactionCountByHash` | Returns transaction count in block |

#### Transaction Pool
| Method | Description |
|--------|-------------|
| `txpool_content` | Returns pending and queued transactions |
| `txpool_status` | Returns transaction pool status |

### Anvil Cheat Codes (Foundry Compatible)

#### State Manipulation
| Method | Parameters | Description |
|--------|------------|-------------|
| `anvil_setBalance` | `address, balance` | Set account balance |
| `anvil_setCode` | `address, code` | Set account bytecode |
| `anvil_setStorageAt` | `address, slot, value` | Set storage slot value |
| `anvil_setNonce` | `address, nonce` | Set account nonce |

#### Block Mining
| Method | Parameters | Description |
|--------|------------|-------------|
| `anvil_mine` | `blocks, [timestamp]` | Mine specified number of blocks |
| `anvil_setNextBlockTimestamp` | `timestamp` | Set next block's timestamp |
| `anvil_setCoinbase` | `address` | Set coinbase address |

#### Account Impersonation
| Method | Parameters | Description |
|--------|------------|-------------|
| `anvil_impersonateAccount` | `address` | Start impersonating an address |
| `anvil_stopImpersonatingAccount` | `address` | Stop impersonating an address |
| `anvil_autoImpersonateAccount` | `enabled` | Enable/disable auto-impersonation |

#### State Snapshots
| Method | Parameters | Description |
|--------|------------|-------------|
| `anvil_snapshot` | none | Create state snapshot, returns ID |
| `anvil_revert` | `snapshotId` | Revert to snapshot |
| `anvil_reset` | `[options]` | Reset chain state |

#### State Persistence
| Method | Parameters | Description |
|--------|------------|-------------|
| `anvil_dumpState` | none | Export full blockchain state |
| `anvil_loadState` | `state` | Import blockchain state |

#### Transaction Management
| Method | Parameters | Description |
|--------|------------|-------------|
| `anvil_dropTransaction` | `txHash` | Remove transaction from pool |

### EVM Control (Hardhat Compatible)

| Method | Parameters | Description |
|--------|------------|-------------|
| `evm_snapshot` | none | Alias for `anvil_snapshot` |
| `evm_revert` | `snapshotId` | Alias for `anvil_revert` |
| `evm_increaseTime` | `seconds` | Increase blockchain time |
| `evm_setNextBlockTimestamp` | `timestamp` | Set next block timestamp |
| `evm_mine` | `[timestamp]` | Mine a single block |

### Debug Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `debug_traceTransaction` | `txHash, [options]` | Trace transaction execution |
| `debug_traceCall` | `callObject, blockId, [options]` | Trace call execution |
| `debug_traceBlockByNumber` | `blockNumber, [options]` | Trace all transactions in block |
| `debug_traceBlockByHash` | `blockHash, [options]` | Trace all transactions in block |

Supported tracers:
- `callTracer` - Returns call frame tree
- Default tracer - Returns step-by-step execution trace

### StableNet Specific

#### Validator Management
| Method | Parameters | Description |
|--------|------------|-------------|
| `stablenet_addValidator` | `address, operator` | Add a new validator |
| `stablenet_removeValidator` | `address` | Remove a validator |
| `stablenet_getValidators` | none | Get all validators |
| `stablenet_getProposer` | `blockNumber` | Get block proposer |

#### Stablecoin Operations
| Method | Parameters | Description |
|--------|------------|-------------|
| `stablenet_mintStablecoin` | `to, amount` | Mint stablecoins |
| `stablenet_burnStablecoin` | `from, amount` | Burn stablecoins |
| `stablenet_getStablecoinBalance` | `address` | Get stablecoin balance |
| `stablenet_getStablecoinTotalSupply` | none | Get total stablecoin supply |

## Usage Examples

### Using with curl

```bash
# Get chain ID
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'

# Set balance for an address
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"anvil_setBalance","params":["0x1234...","0xde0b6b3a7640000"],"id":1}'

# Mine 10 blocks
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"anvil_mine","params":["0xa"],"id":1}'

# Take a snapshot
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"anvil_snapshot","params":[],"id":1}'

# Impersonate an account
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"anvil_impersonateAccount","params":["0x1234..."],"id":1}'
```

### Using with Foundry

```bash
# Start anvil-go
anvil

# In another terminal, use forge/cast
cast chain-id --rpc-url http://localhost:8545
cast balance 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --rpc-url http://localhost:8545
cast rpc anvil_setBalance 0x1234... 0xde0b6b3a7640000 --rpc-url http://localhost:8545
```

### Using with ethers.js

```javascript
const { ethers } = require('ethers');

const provider = new ethers.JsonRpcProvider('http://localhost:8545');

// Get chain ID
const chainId = await provider.getNetwork().then(n => n.chainId);

// Set balance using anvil cheat code
await provider.send('anvil_setBalance', [
  '0x1234567890123456789012345678901234567890',
  '0xde0b6b3a7640000' // 1 ETH
]);

// Mine blocks
await provider.send('anvil_mine', ['0xa']); // Mine 10 blocks

// Snapshot and revert
const snapshotId = await provider.send('anvil_snapshot', []);
// ... do some transactions ...
await provider.send('anvil_revert', [snapshotId]);
```

### Using with web3.py

```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

# Get chain ID
chain_id = w3.eth.chain_id

# Set balance
w3.provider.make_request('anvil_setBalance', [
    '0x1234567890123456789012345678901234567890',
    '0xde0b6b3a7640000'
])

# Mine blocks
w3.provider.make_request('anvil_mine', ['0xa'])

# Snapshot and revert
result = w3.provider.make_request('anvil_snapshot', [])
snapshot_id = result['result']
# ... do some transactions ...
w3.provider.make_request('anvil_revert', [snapshot_id])
```

## Development

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage

# Run linter
make lint

# Format code
make fmt

# Build
make build

# Run benchmarks
go test ./test/benchmark/... -bench=. -benchmem
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) - Design philosophy and component overview
- [Specification](docs/SPEC.md) - Technical specification and API reference
- [Roadmap](docs/ROADMAP.md) - Implementation phases and timeline
- [Tasks](docs/TASKS.md) - Detailed work items and TDD steps

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read the documentation before submitting PRs.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests first (TDD)
4. Implement the feature
5. Ensure tests pass (`make test`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request
