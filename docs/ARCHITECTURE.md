# Anvil-Go Architecture

## Overview

Anvil-Go is a local Ethereum development node simulator written in Go, designed specifically for StableNet blockchain testing and development. It provides a fast, deterministic environment for smart contract development with full EVM compatibility.

## Design Philosophy

### Core Principles

1. **Simplicity Over Complexity**
   - Prefer straightforward implementations over clever solutions
   - Each component should do one thing well (Single Responsibility)
   - Minimize external dependencies

2. **Go-Ethereum Compatibility**
   - Leverage existing go-ethereum packages (`core/vm`, `core/state`, `core/types`)
   - Maintain RPC API compatibility with standard Ethereum nodes
   - Support existing tooling (ethers.js, web3.js, viem)

3. **Developer Experience First**
   - Fast startup time (< 1 second)
   - Instant transaction confirmation (auto-mining)
   - Rich debugging capabilities
   - Clear error messages

4. **StableNet Native**
   - First-class support for WBFT consensus simulation
   - Built-in system contracts (GovValidator, GovMinter, GovMasterMinter)
   - Stablecoin-specific testing utilities

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                      Interface Layer                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   HTTP/RPC   │  │  WebSocket   │  │     CLI      │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
├─────────────────────────────────────────────────────────────┤
│                       API Layer                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   Eth API    │  │  Debug API   │  │  Anvil API   │       │
│  │  (Standard)  │  │  (Tracing)   │  │(Cheat Codes) │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
├─────────────────────────────────────────────────────────────┤
│                      Service Layer                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   TxPool     │  │    Miner     │  │   Snapshot   │       │
│  │   Service    │  │   Service    │  │   Manager    │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
├─────────────────────────────────────────────────────────────┤
│                       Core Layer                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │    State     │  │  Blockchain  │  │     EVM      │       │
│  │   Manager    │  │   Manager    │  │   Executor   │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
├─────────────────────────────────────────────────────────────┤
│                    Foundation Layer                          │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              go-ethereum / go-stablenet              │    │
│  │     (core/vm, core/state, core/types, ethdb)        │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Component Design

### 1. Backend (Core Engine)

The central orchestrator that coordinates all components.

```go
type Backend interface {
    // State access
    StateAt(root common.Hash) (*state.StateDB, error)
    CurrentState() *state.StateDB

    // Blockchain access
    CurrentBlock() *types.Block
    BlockByNumber(number uint64) *types.Block
    BlockByHash(hash common.Hash) *types.Block

    // Transaction handling
    SendTransaction(tx *types.Transaction) error
    PendingTransactions() []*types.Transaction

    // Mining control
    Mine(blocks uint64) error
    SetAutomine(enabled bool)

    // Cheat codes
    SetBalance(addr common.Address, balance *big.Int) error
    SetCode(addr common.Address, code []byte) error
    SetStorageAt(addr common.Address, slot, value common.Hash) error

    // Snapshots
    Snapshot() uint64
    Revert(id uint64) bool
}
```

### 2. State Manager

In-memory state management with snapshot support.

**Responsibilities:**
- Account balance, nonce, code management
- Storage slot management
- State root calculation
- Snapshot/revert functionality

**Design Decisions:**
- Use go-ethereum's `state.StateDB` internally
- Wrap with snapshot layer for efficient revert
- Copy-on-write for memory efficiency

### 3. Blockchain Manager

Block chain management and block production.

**Responsibilities:**
- Genesis block initialization
- Block storage and retrieval
- Chain reorganization (minimal, for fork mode)
- Block number/hash indexing

### 4. Transaction Pool

Pending transaction management.

**Responsibilities:**
- Transaction validation (nonce, balance, gas)
- Transaction ordering (by gas price or FIFO)
- Impersonation support (skip signature verification)
- Nonce management

### 5. Miner Service

Block production with configurable mining modes.

**Mining Modes:**
```go
type MiningMode int

const (
    ModeAutomine   MiningMode = iota  // Mine on each tx
    ModeInterval                       // Mine every N seconds
    ModeManual                         // Mine on explicit call
)
```

### 6. RPC Server

JSON-RPC server with multiple API namespaces.

**Namespaces:**
- `eth_*` - Standard Ethereum API
- `net_*` - Network API
- `web3_*` - Web3 API
- `debug_*` - Debug/tracing API
- `anvil_*` - Cheat codes (Foundry compatible)
- `evm_*` - EVM control (Hardhat compatible)
- `stablenet_*` - StableNet specific

## Data Flow

### Transaction Execution Flow

```
User sends tx via eth_sendTransaction
         │
         ▼
┌─────────────────┐
│   RPC Server    │  Parse and validate RPC request
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Eth API      │  Build transaction object
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Transaction   │  Validate nonce, balance, gas
│      Pool       │  Check impersonation
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Miner Service  │  If automine: immediately build block
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  EVM Executor   │  Execute transaction
│  (core/vm)      │  Apply state changes
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ State Manager   │  Commit state changes
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Blockchain    │  Add block to chain
│    Manager      │  Update indices
└─────────────────┘
```

### Snapshot/Revert Flow

```
anvil_snapshot
      │
      ▼
┌──────────────────┐
│ Snapshot Manager │
│                  │
│  ┌────────────┐  │
│  │ Snapshot 0 │  │  Save: block number, state root,
│  │ Snapshot 1 │  │        timestamp, full state copy
│  │ Snapshot 2 │  │
│  └────────────┘  │
└──────────────────┘

anvil_revert(1)
      │
      ▼
┌──────────────────┐
│ Snapshot Manager │
│                  │
│  1. Restore state from Snapshot 1
│  2. Reset blockchain to snapshot block
│  3. Delete snapshots > 1
│  4. Reset timestamp
└──────────────────┘
```

## SOLID Principles Application

### Single Responsibility Principle (SRP)

Each component has one reason to change:
- `StateManager` - only state-related changes
- `Miner` - only mining logic changes
- `RpcServer` - only RPC protocol changes

### Open/Closed Principle (OCP)

- API handlers are open for extension via interface
- Mining modes can be added without modifying existing code
- New cheat codes can be added as new API methods

### Liskov Substitution Principle (LSP)

- All `Backend` implementations are interchangeable
- `StateDB` interface allows different storage backends
- Fork backend can substitute for in-memory backend

### Interface Segregation Principle (ISP)

```go
// Small, focused interfaces
type StateReader interface {
    GetBalance(addr common.Address) *big.Int
    GetCode(addr common.Address) []byte
    GetNonce(addr common.Address) uint64
}

type StateWriter interface {
    SetBalance(addr common.Address, balance *big.Int)
    SetCode(addr common.Address, code []byte)
    SetNonce(addr common.Address, nonce uint64)
}

type StateManager interface {
    StateReader
    StateWriter
    Snapshot() uint64
    Revert(id uint64) bool
}
```

### Dependency Inversion Principle (DIP)

- High-level modules depend on abstractions (interfaces)
- Dependencies injected via constructors
- Easy to mock for testing

```go
// Depend on abstraction, not concrete implementation
type Miner struct {
    state      StateManager    // interface
    blockchain BlockchainReader // interface
    txpool     TxPoolReader    // interface
}
```

## Testing Strategy

### Unit Tests
- Each component tested in isolation
- Mock dependencies using interfaces
- Table-driven tests for edge cases

### Integration Tests
- End-to-end RPC tests
- Multi-component interaction tests
- State consistency tests

### Compatibility Tests
- Foundry test suite compatibility
- Hardhat test suite compatibility
- Standard Ethereum JSON-RPC compliance

## Configuration

```go
type Config struct {
    // Network
    ChainID     uint64
    Port        int
    Host        string

    // Accounts
    AccountCount   int
    DefaultBalance *big.Int
    Mnemonic       string

    // Mining
    MiningMode     MiningMode
    BlockTime      time.Duration

    // Features
    AutoImpersonate bool
    EnableTracing   bool

    // Fork (optional)
    ForkURL        string
    ForkBlockNumber uint64

    // StableNet specific
    EnableWBFT           bool
    DeploySystemContracts bool
    Validators           []common.Address
}
```

## Future Considerations

1. **Fork Mode**
   - Lazy state loading from remote node
   - State caching and invalidation
   - Block replay capability

2. **Performance Optimization**
   - Parallel transaction execution
   - State caching strategies
   - Memory pooling

3. **Advanced Debugging**
   - Step-by-step execution
   - Breakpoints
   - State diff visualization

4. **Network Simulation**
   - Multiple node simulation
   - Network partitioning
   - Latency injection
