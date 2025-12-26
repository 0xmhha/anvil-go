// Package backend provides the main simulator backend implementation.
package backend

import (
	"crypto/ecdsa"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Backend is the main interface for the simulator engine.
// It coordinates all components and provides the primary API.
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

	// Transaction handling
	SendTransaction(tx *types.Transaction) (common.Hash, error)
	SendRawTransaction(data []byte) (common.Hash, error)
	Call(msg CallMsg, blockNumber *big.Int) ([]byte, error)
	EstimateGas(msg CallMsg) (uint64, error)
	PendingTransactions() []*types.Transaction

	// Receipt/Log access
	TransactionReceipt(hash common.Hash) (*types.Receipt, error)
	TransactionByHash(hash common.Hash) (*types.Transaction, error)
	GetLogs(filter FilterQuery) ([]*types.Log, error)

	// State access
	GetBalance(addr common.Address, blockNumber *big.Int) (*big.Int, error)
	GetCode(addr common.Address, blockNumber *big.Int) ([]byte, error)
	GetNonce(addr common.Address, blockNumber *big.Int) (uint64, error)
	GetStorageAt(addr common.Address, slot common.Hash, blockNumber *big.Int) (common.Hash, error)

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

// CallMsg represents a call message.
type CallMsg struct {
	From       common.Address
	To         *common.Address
	Gas        uint64
	GasPrice   *big.Int
	GasFeeCap  *big.Int
	GasTipCap  *big.Int
	Value      *big.Int
	Data       []byte
	AccessList types.AccessList
}

// FilterQuery represents a log filter query.
type FilterQuery struct {
	BlockHash *common.Hash
	FromBlock *big.Int
	ToBlock   *big.Int
	Addresses []common.Address
	Topics    [][]common.Hash
}

// CheatCodes provides test helper methods.
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
	SetAutoImpersonate(enabled bool)

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
	Reset(fork *ForkConfig) error
}

// ForkConfig represents fork configuration for reset.
type ForkConfig struct {
	URL         string
	BlockNumber uint64
}

// SnapshotManager handles state snapshots.
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
