package stablenet

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStablecoinManager(t *testing.T) {
	manager := NewStablecoinManager()
	require.NotNil(t, manager)
	assert.Equal(t, big.NewInt(0), manager.GetTotalSupply())
}

func TestStablecoinManager_Mint(t *testing.T) {
	manager := NewStablecoinManager()
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	amount := big.NewInt(1000)

	// Mint stablecoins
	err := manager.Mint(addr, amount)
	require.NoError(t, err)

	// Check balance
	balance := manager.GetBalance(addr)
	assert.Equal(t, amount, balance)

	// Check total supply
	assert.Equal(t, amount, manager.GetTotalSupply())
}

func TestStablecoinManager_Mint_MultipleAccounts(t *testing.T) {
	manager := NewStablecoinManager()
	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")

	// Mint to first address
	err := manager.Mint(addr1, big.NewInt(1000))
	require.NoError(t, err)

	// Mint to second address
	err = manager.Mint(addr2, big.NewInt(2000))
	require.NoError(t, err)

	// Check balances
	assert.Equal(t, big.NewInt(1000), manager.GetBalance(addr1))
	assert.Equal(t, big.NewInt(2000), manager.GetBalance(addr2))

	// Check total supply
	assert.Equal(t, big.NewInt(3000), manager.GetTotalSupply())
}

func TestStablecoinManager_Mint_AddsToExistingBalance(t *testing.T) {
	manager := NewStablecoinManager()
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// First mint
	err := manager.Mint(addr, big.NewInt(1000))
	require.NoError(t, err)

	// Second mint
	err = manager.Mint(addr, big.NewInt(500))
	require.NoError(t, err)

	// Check balance is sum
	assert.Equal(t, big.NewInt(1500), manager.GetBalance(addr))
	assert.Equal(t, big.NewInt(1500), manager.GetTotalSupply())
}

func TestStablecoinManager_Burn(t *testing.T) {
	manager := NewStablecoinManager()
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Mint first
	err := manager.Mint(addr, big.NewInt(1000))
	require.NoError(t, err)

	// Burn some
	err = manager.Burn(addr, big.NewInt(300))
	require.NoError(t, err)

	// Check balance decreased
	assert.Equal(t, big.NewInt(700), manager.GetBalance(addr))

	// Check total supply decreased
	assert.Equal(t, big.NewInt(700), manager.GetTotalSupply())
}

func TestStablecoinManager_Burn_InsufficientBalance(t *testing.T) {
	manager := NewStablecoinManager()
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Mint first
	err := manager.Mint(addr, big.NewInt(1000))
	require.NoError(t, err)

	// Try to burn more than balance
	err = manager.Burn(addr, big.NewInt(1500))
	require.Error(t, err)
	assert.Equal(t, ErrInsufficientSupply, err)

	// Balance should be unchanged
	assert.Equal(t, big.NewInt(1000), manager.GetBalance(addr))
}

func TestStablecoinManager_Burn_ZeroBalance(t *testing.T) {
	manager := NewStablecoinManager()
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Try to burn from account with zero balance
	err := manager.Burn(addr, big.NewInt(100))
	require.Error(t, err)
	assert.Equal(t, ErrInsufficientSupply, err)
}

func TestStablecoinManager_GetBalance_NonexistentAccount(t *testing.T) {
	manager := NewStablecoinManager()
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Should return 0 for nonexistent account
	balance := manager.GetBalance(addr)
	assert.Equal(t, big.NewInt(0), balance)
}

func TestStablecoinManager_Clear(t *testing.T) {
	manager := NewStablecoinManager()
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Mint some
	err := manager.Mint(addr, big.NewInt(1000))
	require.NoError(t, err)

	// Clear
	manager.Clear()

	// All balances and supply should be reset
	assert.Equal(t, big.NewInt(0), manager.GetBalance(addr))
	assert.Equal(t, big.NewInt(0), manager.GetTotalSupply())
}
