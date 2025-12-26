package stablenet

import (
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// StablecoinManager manages stablecoin balances and supply for testing.
type StablecoinManager struct {
	balances    map[common.Address]*big.Int
	totalSupply *big.Int

	mu sync.RWMutex
}

// NewStablecoinManager creates a new stablecoin manager.
func NewStablecoinManager() *StablecoinManager {
	return &StablecoinManager{
		balances:    make(map[common.Address]*big.Int),
		totalSupply: big.NewInt(0),
	}
}

// Mint mints stablecoins to an address.
func (m *StablecoinManager) Mint(to common.Address, amount *big.Int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if amount.Sign() < 0 {
		return ErrInsufficientSupply
	}

	// Get existing balance or initialize to 0
	balance := m.balances[to]
	if balance == nil {
		balance = big.NewInt(0)
	}

	// Add amount to balance
	newBalance := new(big.Int).Add(balance, amount)
	m.balances[to] = newBalance

	// Update total supply
	m.totalSupply = new(big.Int).Add(m.totalSupply, amount)

	return nil
}

// Burn burns stablecoins from an address.
func (m *StablecoinManager) Burn(from common.Address, amount *big.Int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get existing balance
	balance := m.balances[from]
	if balance == nil {
		balance = big.NewInt(0)
	}

	// Check sufficient balance
	if balance.Cmp(amount) < 0 {
		return ErrInsufficientSupply
	}

	// Subtract amount from balance
	newBalance := new(big.Int).Sub(balance, amount)
	m.balances[from] = newBalance

	// Update total supply
	m.totalSupply = new(big.Int).Sub(m.totalSupply, amount)

	return nil
}

// GetBalance returns the stablecoin balance of an address.
func (m *StablecoinManager) GetBalance(addr common.Address) *big.Int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	balance := m.balances[addr]
	if balance == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(balance)
}

// GetTotalSupply returns the total supply of stablecoins.
func (m *StablecoinManager) GetTotalSupply() *big.Int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return new(big.Int).Set(m.totalSupply)
}

// Clear resets all stablecoin balances and supply.
func (m *StablecoinManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.balances = make(map[common.Address]*big.Int)
	m.totalSupply = big.NewInt(0)
}
