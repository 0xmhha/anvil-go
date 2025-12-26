// Package miner provides block production for the simulator.
package miner

import (
	"time"

	"github.com/ethereum/go-ethereum/core/types"
)

// MiningMode defines how blocks are mined.
type MiningMode int

const (
	// ModeAutomine mines a block immediately when a transaction is received.
	ModeAutomine MiningMode = iota

	// ModeInterval mines a block at regular intervals.
	ModeInterval

	// ModeManual only mines when explicitly requested.
	ModeManual
)

// String returns the string representation of the mining mode.
func (m MiningMode) String() string {
	switch m {
	case ModeAutomine:
		return "auto"
	case ModeInterval:
		return "interval"
	case ModeManual:
		return "manual"
	default:
		return "unknown"
	}
}

// ParseMiningMode parses a string into a MiningMode.
func ParseMiningMode(s string) MiningMode {
	switch s {
	case "auto":
		return ModeAutomine
	case "interval":
		return ModeInterval
	case "manual":
		return ModeManual
	default:
		return ModeAutomine
	}
}

// Miner handles block production.
type Miner interface {
	// MineBlock mines a single block with pending transactions.
	MineBlock() (*types.Block, error)

	// MineBlocks mines multiple empty blocks.
	MineBlocks(count uint64) ([]*types.Block, error)

	// MineBlockWithTransactions mines a block with specific transactions.
	MineBlockWithTransactions(txs []*types.Transaction) (*types.Block, error)

	// Mode returns the current mining mode.
	Mode() MiningMode

	// SetMode sets the mining mode.
	SetMode(mode MiningMode) error

	// SetInterval sets the interval for interval mining.
	SetInterval(d time.Duration) error

	// Start starts the miner (for interval mode).
	Start() error

	// Stop stops the miner.
	Stop() error
}
