# Anvil-Go Technical Specification

## Version
- Specification Version: 1.0.0
- Target Go Version: 1.21+
- Target go-stablenet Version: latest

---

## 1. Core Interfaces

### 1.1 Backend Interface

```go
package backend

import (
    "math/big"

    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/core/state"
    "github.com/ethereum/go-ethereum/core/types"
)

// Backend is the main interface for the simulator engine
type Backend interface {
    // Lifecycle
    Start() error
    Stop() error

    // Chain information
    ChainID() *big.Int
    CurrentBlock() *types.Block
    BlockByNumber(number uint64) (*types.Block, error)
    BlockByHash(hash common.Hash) (*types.Block, error)
    BlockNumber() uint64

    // State access
    StateAt(root common.Hash) (*state.StateDB, error)
    CurrentState() *state.StateDB

    // Transaction handling
    SendTransaction(tx *types.Transaction) (common.Hash, error)
    SendRawTransaction(data []byte) (common.Hash, error)
    Call(msg CallMsg, blockNumber *big.Int) ([]byte, error)
    EstimateGas(msg CallMsg) (uint64, error)
    PendingTransactions() []*types.Transaction

    // Receipt/Log access
    TransactionReceipt(hash common.Hash) (*types.Receipt, error)
    GetLogs(filter FilterQuery) ([]*types.Log, error)

    // Mining control
    Mine(blocks uint64) ([]*types.Block, error)
    SetAutomine(enabled bool) error
    SetIntervalMining(interval time.Duration) error
    IsAutomine() bool

    // Cheat codes
    CheatCodes() CheatCodes

    // Snapshot
    Snapshots() SnapshotManager

    // Accounts
    Accounts() []common.Address
    GetPrivateKey(addr common.Address) (*ecdsa.PrivateKey, error)
}
```

### 1.2 CheatCodes Interface

```go
package backend

// CheatCodes provides test helper methods
type CheatCodes interface {
    // Account manipulation
    SetBalance(addr common.Address, balance *big.Int) error
    SetNonce(addr common.Address, nonce uint64) error
    SetCode(addr common.Address, code []byte) error
    SetStorageAt(addr common.Address, slot, value common.Hash) error

    // Impersonation
    ImpersonateAccount(addr common.Address) error
    StopImpersonatingAccount(addr common.Address) error
    IsImpersonating(addr common.Address) bool

    // Time manipulation
    IncreaseTime(seconds uint64) (uint64, error)
    SetNextBlockTimestamp(timestamp uint64) error
    GetCurrentTimestamp() uint64

    // Block manipulation
    SetNextBlockBaseFee(baseFee *big.Int) error
    SetCoinbase(addr common.Address) error

    // Transaction manipulation
    DropTransaction(hash common.Hash) error
    DropAllTransactions() error

    // Reset
    Reset(forkConfig *ForkConfig) error
}
```

### 1.3 SnapshotManager Interface

```go
package backend

// SnapshotManager handles state snapshots
type SnapshotManager interface {
    // Snapshot creates a new snapshot and returns its ID
    Snapshot() (uint64, error)

    // Revert reverts to the given snapshot ID
    // Returns true if successful, false if snapshot not found
    Revert(id uint64) (bool, error)

    // List returns all snapshot IDs
    List() []uint64

    // Delete removes a specific snapshot
    Delete(id uint64) error

    // Clear removes all snapshots
    Clear() error
}
```

### 1.4 StateManager Interface

```go
package state

import (
    "math/big"

    "github.com/ethereum/go-ethereum/common"
)

// StateReader provides read-only state access
type StateReader interface {
    GetBalance(addr common.Address) *big.Int
    GetNonce(addr common.Address) uint64
    GetCode(addr common.Address) []byte
    GetCodeHash(addr common.Address) common.Hash
    GetStorageAt(addr common.Address, slot common.Hash) common.Hash
    Exist(addr common.Address) bool
}

// StateWriter provides state modification
type StateWriter interface {
    SetBalance(addr common.Address, balance *big.Int) error
    SetNonce(addr common.Address, nonce uint64) error
    SetCode(addr common.Address, code []byte) error
    SetStorageAt(addr common.Address, slot, value common.Hash) error
    CreateAccount(addr common.Address) error
    DeleteAccount(addr common.Address) error
}

// StateManager combines read and write operations
type StateManager interface {
    StateReader
    StateWriter

    // Root returns the current state root
    Root() common.Hash

    // Commit commits pending changes
    Commit() (common.Hash, error)

    // Copy creates a deep copy of the state
    Copy() StateManager
}
```

### 1.5 Miner Interface

```go
package miner

import (
    "time"

    "github.com/ethereum/go-ethereum/core/types"
)

// MiningMode defines how blocks are mined
type MiningMode int

const (
    ModeAutomine MiningMode = iota
    ModeInterval
    ModeManual
)

// Miner handles block production
type Miner interface {
    // MineBlock mines a single block with pending transactions
    MineBlock() (*types.Block, error)

    // MineBlocks mines multiple empty blocks
    MineBlocks(count uint64) ([]*types.Block, error)

    // MineBlockWithTransactions mines a block with specific transactions
    MineBlockWithTransactions(txs []*types.Transaction) (*types.Block, error)

    // Mode returns the current mining mode
    Mode() MiningMode

    // SetMode sets the mining mode
    SetMode(mode MiningMode) error

    // SetInterval sets the interval for interval mining
    SetInterval(d time.Duration) error

    // Start starts the miner (for interval mode)
    Start() error

    // Stop stops the miner
    Stop() error
}
```

### 1.6 TxPool Interface

```go
package txpool

import (
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/core/types"
)

// TxPool manages pending transactions
type TxPool interface {
    // Add adds a transaction to the pool
    Add(tx *types.Transaction) error

    // AddWithImpersonation adds a transaction, bypassing signature verification
    AddWithImpersonation(tx *types.Transaction) error

    // Remove removes a transaction from the pool
    Remove(hash common.Hash) error

    // Get retrieves a transaction by hash
    Get(hash common.Hash) *types.Transaction

    // Pending returns all pending transactions
    Pending() []*types.Transaction

    // PendingFrom returns pending transactions from a specific address
    PendingFrom(addr common.Address) []*types.Transaction

    // Count returns the number of pending transactions
    Count() int

    // Clear removes all transactions
    Clear()
}
```

---

## 2. RPC API Specification

### 2.1 Standard Ethereum APIs

#### eth_* Namespace

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `eth_chainId` | - | `QUANTITY` | Returns chain ID |
| `eth_blockNumber` | - | `QUANTITY` | Returns current block number |
| `eth_gasPrice` | - | `QUANTITY` | Returns current gas price |
| `eth_getBalance` | `address`, `block` | `QUANTITY` | Returns account balance |
| `eth_getCode` | `address`, `block` | `DATA` | Returns account code |
| `eth_getStorageAt` | `address`, `slot`, `block` | `DATA` | Returns storage value |
| `eth_getTransactionCount` | `address`, `block` | `QUANTITY` | Returns nonce |
| `eth_getBlockByNumber` | `number`, `full` | `Block` | Returns block by number |
| `eth_getBlockByHash` | `hash`, `full` | `Block` | Returns block by hash |
| `eth_getTransactionByHash` | `hash` | `Transaction` | Returns transaction |
| `eth_getTransactionReceipt` | `hash` | `Receipt` | Returns receipt |
| `eth_sendTransaction` | `TransactionArgs` | `DATA` | Sends transaction |
| `eth_sendRawTransaction` | `DATA` | `DATA` | Sends signed transaction |
| `eth_call` | `CallArgs`, `block` | `DATA` | Executes call |
| `eth_estimateGas` | `CallArgs`, `block` | `QUANTITY` | Estimates gas |
| `eth_getLogs` | `FilterQuery` | `[]Log` | Returns logs |
| `eth_accounts` | - | `[]Address` | Returns accounts |
| `eth_sign` | `address`, `data` | `DATA` | Signs data |
| `eth_signTransaction` | `TransactionArgs` | `DATA` | Signs transaction |

#### net_* Namespace

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `net_version` | - | `String` | Returns network ID |
| `net_listening` | - | `Boolean` | Always returns true |
| `net_peerCount` | - | `QUANTITY` | Always returns 0 |

#### web3_* Namespace

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `web3_clientVersion` | - | `String` | Returns client version |
| `web3_sha3` | `DATA` | `DATA` | Returns Keccak-256 hash |

### 2.2 Anvil Cheat Codes (Foundry Compatible)

#### anvil_* Namespace

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `anvil_setBalance` | `address`, `balance` | `Boolean` | Sets account balance |
| `anvil_setCode` | `address`, `code` | `Boolean` | Sets account code |
| `anvil_setStorageAt` | `address`, `slot`, `value` | `Boolean` | Sets storage slot |
| `anvil_setNonce` | `address`, `nonce` | `Boolean` | Sets account nonce |
| `anvil_impersonateAccount` | `address` | `Boolean` | Enables impersonation |
| `anvil_stopImpersonatingAccount` | `address` | `Boolean` | Disables impersonation |
| `anvil_autoImpersonateAccount` | `enabled` | `Boolean` | Auto-impersonate all |
| `anvil_mine` | `blocks`, `interval` | `Boolean` | Mines blocks |
| `anvil_dropTransaction` | `hash` | `Boolean` | Drops pending tx |
| `anvil_dropAllTransactions` | - | `Boolean` | Drops all pending txs |
| `anvil_reset` | `forkConfig` | `Boolean` | Resets state |
| `anvil_setMinGasPrice` | `gasPrice` | `Boolean` | Sets min gas price |
| `anvil_setNextBlockBaseFee` | `baseFee` | `Boolean` | Sets next block base fee |
| `anvil_setCoinbase` | `address` | `Boolean` | Sets coinbase |
| `anvil_dumpState` | - | `DATA` | Dumps entire state |
| `anvil_loadState` | `DATA` | `Boolean` | Loads state dump |
| `anvil_nodeInfo` | - | `NodeInfo` | Returns node info |

### 2.3 EVM Control (Hardhat Compatible)

#### evm_* Namespace

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `evm_snapshot` | - | `QUANTITY` | Creates snapshot |
| `evm_revert` | `id` | `Boolean` | Reverts to snapshot |
| `evm_increaseTime` | `seconds` | `QUANTITY` | Increases time |
| `evm_setNextBlockTimestamp` | `timestamp` | `Boolean` | Sets next block time |
| `evm_mine` | `timestamp` | `Boolean` | Mines block |
| `evm_setAutomine` | `enabled` | `Boolean` | Sets automine mode |
| `evm_setIntervalMining` | `interval` | `Boolean` | Sets interval mining |

### 2.4 Debug APIs

#### debug_* Namespace

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `debug_traceTransaction` | `hash`, `options` | `Trace` | Traces transaction |
| `debug_traceCall` | `CallArgs`, `block`, `options` | `Trace` | Traces call |
| `debug_traceBlockByNumber` | `number`, `options` | `[]Trace` | Traces block |
| `debug_traceBlockByHash` | `hash`, `options` | `[]Trace` | Traces block |

### 2.5 StableNet Specific APIs

#### stablenet_* Namespace

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `stablenet_addValidator` | `address` | `Boolean` | Adds validator |
| `stablenet_removeValidator` | `address` | `Boolean` | Removes validator |
| `stablenet_getValidators` | - | `[]Address` | Returns validators |
| `stablenet_setProposer` | `address` | `Boolean` | Sets block proposer |
| `stablenet_mintStablecoin` | `address`, `amount` | `Boolean` | Mints stablecoin |
| `stablenet_burnStablecoin` | `address`, `amount` | `Boolean` | Burns stablecoin |

---

## 3. Data Structures

### 3.1 Configuration

```go
package config

import (
    "math/big"
    "time"

    "github.com/ethereum/go-ethereum/common"
)

// Config defines the simulator configuration
type Config struct {
    // Network configuration
    ChainID  uint64 `json:"chainId" default:"31337"`
    GasLimit uint64 `json:"gasLimit" default:"30000000"`
    GasPrice *big.Int `json:"gasPrice"`
    BaseFee  *big.Int `json:"baseFee"`

    // Server configuration
    Host string `json:"host" default:"127.0.0.1"`
    Port int    `json:"port" default:"8545"`

    // Account configuration
    AccountCount   int      `json:"accountCount" default:"10"`
    DefaultBalance *big.Int `json:"defaultBalance"` // default: 10000 ETH
    Mnemonic       string   `json:"mnemonic"`
    DerivationPath string   `json:"derivationPath" default:"m/44'/60'/0'/0/"`

    // Mining configuration
    MiningMode  string        `json:"miningMode" default:"auto"` // auto, interval, manual
    BlockTime   time.Duration `json:"blockTime" default:"0s"`

    // Feature flags
    AutoImpersonate bool `json:"autoImpersonate" default:"false"`
    AllowOrigin     string `json:"allowOrigin" default:"*"`

    // Fork configuration (optional)
    Fork *ForkConfig `json:"fork,omitempty"`

    // StableNet configuration
    StableNet *StableNetConfig `json:"stablenet,omitempty"`
}

// ForkConfig defines fork mode configuration
type ForkConfig struct {
    URL         string `json:"url"`
    BlockNumber uint64 `json:"blockNumber,omitempty"` // 0 = latest
    RetryCount  int    `json:"retryCount" default:"3"`
    Timeout     time.Duration `json:"timeout" default:"30s"`
}

// StableNetConfig defines StableNet-specific configuration
type StableNetConfig struct {
    DeploySystemContracts bool              `json:"deploySystemContracts" default:"true"`
    Validators            []common.Address  `json:"validators,omitempty"`
    EnableWBFT            bool              `json:"enableWbft" default:"false"`
}
```

### 3.2 Snapshot

```go
package snapshot

import (
    "github.com/ethereum/go-ethereum/common"
)

// Snapshot represents a point-in-time state capture
type Snapshot struct {
    ID          uint64      `json:"id"`
    BlockNumber uint64      `json:"blockNumber"`
    BlockHash   common.Hash `json:"blockHash"`
    StateRoot   common.Hash `json:"stateRoot"`
    Timestamp   uint64      `json:"timestamp"`
    CreatedAt   time.Time   `json:"createdAt"`
}
```

### 3.3 NodeInfo

```go
package types

// NodeInfo represents simulator node information
type NodeInfo struct {
    Version        string           `json:"version"`
    ChainID        uint64           `json:"chainId"`
    CurrentBlock   uint64           `json:"currentBlockNumber"`
    Accounts       []common.Address `json:"accounts"`
    MiningMode     string           `json:"miningMode"`
    AutoImpersonate bool            `json:"autoImpersonate"`
    ForkConfig     *ForkInfo        `json:"forkConfig,omitempty"`
}

// ForkInfo represents fork state information
type ForkInfo struct {
    URL         string `json:"url"`
    BlockNumber uint64 `json:"blockNumber"`
}
```

---

## 4. Error Codes

| Code | Name | Description |
|------|------|-------------|
| -32700 | ParseError | Invalid JSON |
| -32600 | InvalidRequest | Invalid request object |
| -32601 | MethodNotFound | Method not found |
| -32602 | InvalidParams | Invalid parameters |
| -32603 | InternalError | Internal error |
| -32000 | ExecutionError | Transaction execution failed |
| -32001 | NonceError | Invalid nonce |
| -32002 | InsufficientFunds | Insufficient balance |
| -32003 | GasLimitExceeded | Gas limit exceeded |
| -32004 | SnapshotNotFound | Snapshot ID not found |
| -32005 | AccountNotImpersonated | Account not impersonated |

---

## 5. Genesis State

### 5.1 Default Test Accounts

The simulator creates 10 test accounts by default:

```go
// Default mnemonic for deterministic accounts
const DefaultMnemonic = "test test test test test test test test test test test junk"

// Default balance: 10,000 ETH
var DefaultBalance = new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e18))
```

### 5.2 System Contracts (StableNet Mode)

When `stablenet.deploySystemContracts` is enabled:

| Contract | Address | Description |
|----------|---------|-------------|
| GovValidator | `0x0000...0100` | Validator governance |
| GovMinter | `0x0000...0101` | Minter governance |
| GovMasterMinter | `0x0000...0102` | Master minter governance |
| NativeCoinAdapter | `0x0000...0103` | ERC20 wrapper |

---

## 6. Performance Requirements

| Metric | Target |
|--------|--------|
| Startup time | < 1 second |
| Transaction execution | < 10ms |
| Block production | < 50ms |
| Snapshot creation | < 100ms |
| Snapshot revert | < 100ms |
| RPC response time | < 50ms |
| Memory usage (idle) | < 100MB |
| Memory usage (1M txs) | < 2GB |

---

## 7. Compatibility Requirements

### 7.1 Foundry Compatibility

- All `anvil_*` methods must match Foundry Anvil behavior
- Cheat codes must work with Foundry's `forge test`

### 7.2 Hardhat Compatibility

- All `evm_*` methods must match Hardhat Network behavior
- Must work with Hardhat's test runner

### 7.3 Standard Tooling

- ethers.js v5/v6 compatibility
- web3.js compatibility
- viem compatibility
- Standard wallet compatibility (MetaMask, etc.)
