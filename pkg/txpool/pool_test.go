package txpool

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stable-net/anvil-go/pkg/state"
)

// Test helpers
func generateKey(t *testing.T) (*ecdsa.PrivateKey, common.Address) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	addr := crypto.PubkeyToAddress(key.PublicKey)
	return key, addr
}

func createSignedTx(t *testing.T, key *ecdsa.PrivateKey, nonce uint64, to common.Address, value *big.Int, gasLimit uint64, gasPrice *big.Int) *types.Transaction {
	tx := types.NewTransaction(nonce, to, value, gasLimit, gasPrice, nil)
	signer := types.NewEIP155Signer(big.NewInt(31337))
	signedTx, err := types.SignTx(tx, signer, key)
	require.NoError(t, err)
	return signedTx
}

func setupPool(t *testing.T) (*InMemoryPool, *state.InMemoryManager, *ecdsa.PrivateKey, common.Address) {
	sm := state.NewInMemoryManager()
	key, addr := generateKey(t)

	// Fund the account
	balance := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18)) // 1000 ETH
	sm.SetBalance(addr, balance)

	pool := NewInMemoryPool(sm, big.NewInt(31337))
	return pool, sm, key, addr
}

func TestNewInMemoryPool(t *testing.T) {
	sm := state.NewInMemoryManager()
	pool := NewInMemoryPool(sm, big.NewInt(31337))
	require.NotNil(t, pool)
	assert.Equal(t, 0, pool.Count())
}

func TestPoolAdd_ValidTx(t *testing.T) {
	pool, _, key, from := setupPool(t)
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")

	tx := createSignedTx(t, key, 0, to, big.NewInt(1e18), 21000, big.NewInt(1e9))

	err := pool.Add(tx)

	require.NoError(t, err)
	assert.Equal(t, 1, pool.Count())

	// Verify tx is retrievable
	got := pool.Get(tx.Hash())
	assert.NotNil(t, got)
	assert.Equal(t, tx.Hash(), got.Hash())

	_ = from // Used in setup
}

func TestPoolAdd_InvalidNonce_TooLow(t *testing.T) {
	pool, sm, key, from := setupPool(t)
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Set nonce to 5
	sm.SetNonce(from, 5)

	// Try to add tx with nonce 3 (too low)
	tx := createSignedTx(t, key, 3, to, big.NewInt(1e18), 21000, big.NewInt(1e9))

	err := pool.Add(tx)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNonceTooLow)
	assert.Equal(t, 0, pool.Count())
}

func TestPoolAdd_InvalidNonce_TooHigh(t *testing.T) {
	pool, _, key, _ := setupPool(t)
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Account nonce is 0, try to add tx with nonce 10 (too high, gap)
	tx := createSignedTx(t, key, 10, to, big.NewInt(1e18), 21000, big.NewInt(1e9))

	err := pool.Add(tx)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNonceTooHigh)
}

func TestPoolAdd_InsufficientBalance(t *testing.T) {
	sm := state.NewInMemoryManager()
	key, addr := generateKey(t)

	// Only give 1 ETH
	sm.SetBalance(addr, big.NewInt(1e18))

	pool := NewInMemoryPool(sm, big.NewInt(31337))
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Try to send 10 ETH
	tx := createSignedTx(t, key, 0, to, new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)), 21000, big.NewInt(1e9))

	err := pool.Add(tx)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInsufficientFunds)
}

func TestPoolAdd_DuplicateTx(t *testing.T) {
	pool, _, key, _ := setupPool(t)
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")

	tx := createSignedTx(t, key, 0, to, big.NewInt(1e18), 21000, big.NewInt(1e9))

	err := pool.Add(tx)
	require.NoError(t, err)

	// Try to add same tx again
	err = pool.Add(tx)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrTxAlreadyKnown)
}

func TestPoolRemove(t *testing.T) {
	pool, _, key, _ := setupPool(t)
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")

	tx := createSignedTx(t, key, 0, to, big.NewInt(1e18), 21000, big.NewInt(1e9))

	pool.Add(tx)
	assert.Equal(t, 1, pool.Count())

	err := pool.Remove(tx.Hash())
	require.NoError(t, err)
	assert.Equal(t, 0, pool.Count())

	// Verify tx is no longer retrievable
	assert.Nil(t, pool.Get(tx.Hash()))
}

func TestPoolRemove_NotFound(t *testing.T) {
	pool, _, _, _ := setupPool(t)

	err := pool.Remove(common.HexToHash("0x1234"))

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrTxNotFound)
}

func TestPoolPending(t *testing.T) {
	pool, _, key, _ := setupPool(t)
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Add multiple transactions
	tx1 := createSignedTx(t, key, 0, to, big.NewInt(1e18), 21000, big.NewInt(2e9)) // Higher gas price
	tx2 := createSignedTx(t, key, 1, to, big.NewInt(1e18), 21000, big.NewInt(1e9)) // Lower gas price

	pool.Add(tx1)
	pool.Add(tx2)

	pending := pool.Pending()

	assert.Len(t, pending, 2)
	// Should be ordered by nonce for same sender
	assert.Equal(t, uint64(0), pending[0].Nonce())
	assert.Equal(t, uint64(1), pending[1].Nonce())
}

func TestPoolPendingFrom(t *testing.T) {
	pool, sm, key1, addr1 := setupPool(t)
	key2, addr2 := generateKey(t)
	sm.SetBalance(addr2, new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18)))

	to := common.HexToAddress("0x1234567890123456789012345678901234567890")

	tx1 := createSignedTx(t, key1, 0, to, big.NewInt(1e18), 21000, big.NewInt(1e9))
	tx2 := createSignedTx(t, key2, 0, to, big.NewInt(1e18), 21000, big.NewInt(1e9))

	pool.Add(tx1)
	pool.Add(tx2)

	pending1 := pool.PendingFrom(addr1)
	pending2 := pool.PendingFrom(addr2)

	assert.Len(t, pending1, 1)
	assert.Len(t, pending2, 1)
	assert.Equal(t, tx1.Hash(), pending1[0].Hash())
	assert.Equal(t, tx2.Hash(), pending2[0].Hash())
}

func TestPoolClear(t *testing.T) {
	pool, _, key, _ := setupPool(t)
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")

	tx1 := createSignedTx(t, key, 0, to, big.NewInt(1e18), 21000, big.NewInt(1e9))
	tx2 := createSignedTx(t, key, 1, to, big.NewInt(1e18), 21000, big.NewInt(1e9))

	pool.Add(tx1)
	pool.Add(tx2)
	assert.Equal(t, 2, pool.Count())

	pool.Clear()

	assert.Equal(t, 0, pool.Count())
	assert.Empty(t, pool.Pending())
}

func TestPoolImpersonation(t *testing.T) {
	pool, _, _, from := setupPool(t)
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Create unsigned tx (impersonation)
	tx := types.NewTransaction(0, to, big.NewInt(1e18), 21000, big.NewInt(1e9), nil)

	// Should fail without impersonation
	// (We can't easily test this without proper sender extraction)

	// Enable impersonation
	pool.EnableImpersonation(from)

	// Add with impersonation - should succeed
	err := pool.AddWithImpersonation(tx, from)
	require.NoError(t, err)
	assert.Equal(t, 1, pool.Count())
}

func TestPoolAutoImpersonation(t *testing.T) {
	pool, _, _, _ := setupPool(t)

	assert.False(t, pool.IsAutoImpersonate())

	pool.SetAutoImpersonate(true)

	assert.True(t, pool.IsAutoImpersonate())
}

func TestPoolNonceTracking(t *testing.T) {
	pool, _, key, from := setupPool(t)
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Add transactions in sequence
	for i := uint64(0); i < 5; i++ {
		tx := createSignedTx(t, key, i, to, big.NewInt(1e18), 21000, big.NewInt(1e9))
		err := pool.Add(tx)
		require.NoError(t, err)
	}

	assert.Equal(t, 5, pool.Count())

	// Pending nonce should be 5 (next expected nonce)
	assert.Equal(t, uint64(5), pool.PendingNonce(from))
}
