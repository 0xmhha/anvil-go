// Package cheats provides cheat code functionality for the simulator.
package cheats

import (
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stable-net/anvil-go/pkg/state"
)

// Manager implements cheat code functionality.
type Manager struct {
	stateManager *state.InMemoryManager

	// Impersonation
	impersonated    map[common.Address]bool
	autoImpersonate bool

	// Time manipulation
	currentTimestamp   uint64
	nextBlockTimestamp uint64
	timeOffset         uint64

	// Block manipulation
	nextBlockBaseFee *big.Int
	coinbase         common.Address

	// Mining control
	pendingMineCount uint64
	automine         bool   // true = mine immediately on tx, false = manual mining
	intervalMining   uint64 // mining interval in seconds (0 = disabled)

	mu sync.RWMutex
}

// NewManager creates a new cheat code manager.
func NewManager(sm *state.InMemoryManager) *Manager {
	return &Manager{
		stateManager:     sm,
		impersonated:     make(map[common.Address]bool),
		currentTimestamp: uint64(time.Now().Unix()),
		coinbase:         common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
		automine:         true, // Anvil default: auto-mine enabled
	}
}

// SetBalance sets the balance of an account.
func (m *Manager) SetBalance(addr common.Address, balance *big.Int) error {
	return m.stateManager.SetBalance(addr, balance)
}

// SetNonce sets the nonce of an account.
func (m *Manager) SetNonce(addr common.Address, nonce uint64) error {
	return m.stateManager.SetNonce(addr, nonce)
}

// SetCode sets the code of a contract.
func (m *Manager) SetCode(addr common.Address, code []byte) error {
	return m.stateManager.SetCode(addr, code)
}

// SetStorageAt sets the storage value at a slot.
func (m *Manager) SetStorageAt(addr common.Address, slot, value common.Hash) error {
	return m.stateManager.SetStorageAt(addr, slot, value)
}

// Deal is an alias for SetBalance (Foundry compatibility).
func (m *Manager) Deal(addr common.Address, amount *big.Int) error {
	return m.SetBalance(addr, amount)
}

// ImpersonateAccount enables impersonation for an address.
func (m *Manager) ImpersonateAccount(addr common.Address) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.impersonated[addr] = true
	return nil
}

// StopImpersonatingAccount disables impersonation for an address.
func (m *Manager) StopImpersonatingAccount(addr common.Address) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.impersonated, addr)
	return nil
}

// IsImpersonating returns true if the address is being impersonated.
func (m *Manager) IsImpersonating(addr common.Address) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.autoImpersonate {
		return true
	}
	return m.impersonated[addr]
}

// SetAutoImpersonate enables or disables auto-impersonation for all addresses.
func (m *Manager) SetAutoImpersonate(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.autoImpersonate = enabled
}

// IsAutoImpersonate returns true if auto-impersonation is enabled.
func (m *Manager) IsAutoImpersonate() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.autoImpersonate
}

// GetImpersonatedAccounts returns all impersonated addresses.
func (m *Manager) GetImpersonatedAccounts() []common.Address {
	m.mu.RLock()
	defer m.mu.RUnlock()

	accounts := make([]common.Address, 0, len(m.impersonated))
	for addr := range m.impersonated {
		accounts = append(accounts, addr)
	}
	return accounts
}

// IncreaseTime increases the current timestamp.
func (m *Manager) IncreaseTime(seconds uint64) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.timeOffset += seconds
	m.currentTimestamp = uint64(time.Now().Unix()) + m.timeOffset
	return m.currentTimestamp, nil
}

// GetCurrentTimestamp returns the current virtual timestamp.
func (m *Manager) GetCurrentTimestamp() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return uint64(time.Now().Unix()) + m.timeOffset
}

// SetNextBlockTimestamp sets the timestamp for the next block.
func (m *Manager) SetNextBlockTimestamp(timestamp uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextBlockTimestamp = timestamp
	return nil
}

// GetNextBlockTimestamp returns the next block's timestamp.
func (m *Manager) GetNextBlockTimestamp() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.nextBlockTimestamp
}

// ConsumeNextBlockTimestamp returns and clears the next block timestamp.
func (m *Manager) ConsumeNextBlockTimestamp() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	ts := m.nextBlockTimestamp
	m.nextBlockTimestamp = 0
	return ts
}

// SetNextBlockBaseFee sets the base fee for the next block.
func (m *Manager) SetNextBlockBaseFee(baseFee *big.Int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextBlockBaseFee = new(big.Int).Set(baseFee)
	return nil
}

// GetNextBlockBaseFee returns the next block's base fee.
func (m *Manager) GetNextBlockBaseFee() *big.Int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.nextBlockBaseFee == nil {
		return nil
	}
	return new(big.Int).Set(m.nextBlockBaseFee)
}

// ConsumeNextBlockBaseFee returns and clears the next block base fee.
func (m *Manager) ConsumeNextBlockBaseFee() *big.Int {
	m.mu.Lock()
	defer m.mu.Unlock()

	bf := m.nextBlockBaseFee
	m.nextBlockBaseFee = nil
	return bf
}

// SetCoinbase sets the coinbase address.
func (m *Manager) SetCoinbase(addr common.Address) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.coinbase = addr
	return nil
}

// GetCoinbase returns the coinbase address.
func (m *Manager) GetCoinbase() common.Address {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.coinbase
}

// Mine queues blocks to be mined.
func (m *Manager) Mine(count uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pendingMineCount += count
	return nil
}

// GetPendingMineCount returns the number of pending blocks to mine.
func (m *Manager) GetPendingMineCount() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.pendingMineCount
}

// ConsumePendingMines returns and clears the pending mine count.
func (m *Manager) ConsumePendingMines() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := m.pendingMineCount
	m.pendingMineCount = 0
	return count
}

// SetAutomine enables or disables auto-mining mode.
// When enabled, blocks are mined immediately when transactions are submitted.
func (m *Manager) SetAutomine(enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.automine = enabled
	return nil
}

// IsAutomine returns true if auto-mining is enabled.
func (m *Manager) IsAutomine() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.automine
}

// SetIntervalMining sets the interval (in seconds) for automatic block mining.
// When set to a value > 0, blocks are mined automatically at that interval.
// Setting this also disables automine mode.
func (m *Manager) SetIntervalMining(interval uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.intervalMining = interval
	if interval > 0 {
		m.automine = false // Disable automine when interval mining is enabled
	}
	return nil
}

// GetIntervalMining returns the current mining interval in seconds.
// Returns 0 if interval mining is disabled.
func (m *Manager) GetIntervalMining() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.intervalMining
}

// Reset resets all cheat state.
func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.impersonated = make(map[common.Address]bool)
	m.autoImpersonate = false
	m.timeOffset = 0
	m.nextBlockTimestamp = 0
	m.nextBlockBaseFee = nil
	m.pendingMineCount = 0
	m.automine = true // Reset to default (auto-mine enabled)
	m.intervalMining = 0
}
