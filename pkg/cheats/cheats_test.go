package cheats

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stable-net/anvil-go/pkg/state"
)

func setupCheats(t *testing.T) (*Manager, *state.InMemoryManager) {
	sm := state.NewInMemoryManager()
	cheats := NewManager(sm)
	return cheats, sm
}

func TestNewManager(t *testing.T) {
	cheats, _ := setupCheats(t)
	require.NotNil(t, cheats)
}

func TestCheats_SetBalance(t *testing.T) {
	cheats, sm := setupCheats(t)
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	balance := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))

	err := cheats.SetBalance(addr, balance)
	require.NoError(t, err)

	got := sm.GetBalance(addr)
	assert.Equal(t, balance, got)
}

func TestCheats_SetNonce(t *testing.T) {
	cheats, sm := setupCheats(t)
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	err := cheats.SetNonce(addr, 42)
	require.NoError(t, err)

	got := sm.GetNonce(addr)
	assert.Equal(t, uint64(42), got)
}

func TestCheats_SetCode(t *testing.T) {
	cheats, sm := setupCheats(t)
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	code := []byte{0x60, 0x00, 0x60, 0x00, 0xf3} // PUSH1 0 PUSH1 0 RETURN

	err := cheats.SetCode(addr, code)
	require.NoError(t, err)

	got := sm.GetCode(addr)
	assert.Equal(t, code, got)
}

func TestCheats_SetStorageAt(t *testing.T) {
	cheats, sm := setupCheats(t)
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	slot := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	value := common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000002a")

	err := cheats.SetStorageAt(addr, slot, value)
	require.NoError(t, err)

	got := sm.GetStorageAt(addr, slot)
	assert.Equal(t, value, got)
}

func TestCheats_ImpersonateAccount(t *testing.T) {
	cheats, _ := setupCheats(t)
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Initially not impersonating
	assert.False(t, cheats.IsImpersonating(addr))

	// Start impersonating
	err := cheats.ImpersonateAccount(addr)
	require.NoError(t, err)
	assert.True(t, cheats.IsImpersonating(addr))

	// Stop impersonating
	err = cheats.StopImpersonatingAccount(addr)
	require.NoError(t, err)
	assert.False(t, cheats.IsImpersonating(addr))
}

func TestCheats_AutoImpersonate(t *testing.T) {
	cheats, _ := setupCheats(t)
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Initially auto-impersonate is disabled
	assert.False(t, cheats.IsAutoImpersonate())
	assert.False(t, cheats.IsImpersonating(addr))

	// Enable auto-impersonate
	cheats.SetAutoImpersonate(true)
	assert.True(t, cheats.IsAutoImpersonate())
	assert.True(t, cheats.IsImpersonating(addr)) // Any address is now impersonated
}

func TestCheats_IncreaseTime(t *testing.T) {
	cheats, _ := setupCheats(t)

	initialTime := cheats.GetCurrentTimestamp()

	newTime, err := cheats.IncreaseTime(3600) // +1 hour
	require.NoError(t, err)

	assert.GreaterOrEqual(t, newTime, initialTime+3600)
	assert.Equal(t, newTime, cheats.GetCurrentTimestamp())
}

func TestCheats_SetNextBlockTimestamp(t *testing.T) {
	cheats, _ := setupCheats(t)

	expectedTime := uint64(1800000000)
	err := cheats.SetNextBlockTimestamp(expectedTime)
	require.NoError(t, err)

	assert.Equal(t, expectedTime, cheats.GetNextBlockTimestamp())
}

func TestCheats_SetNextBlockBaseFee(t *testing.T) {
	cheats, _ := setupCheats(t)

	baseFee := big.NewInt(2e9) // 2 gwei
	err := cheats.SetNextBlockBaseFee(baseFee)
	require.NoError(t, err)

	assert.Equal(t, baseFee, cheats.GetNextBlockBaseFee())
}

func TestCheats_SetCoinbase(t *testing.T) {
	cheats, _ := setupCheats(t)

	coinbase := common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	err := cheats.SetCoinbase(coinbase)
	require.NoError(t, err)

	assert.Equal(t, coinbase, cheats.GetCoinbase())
}

func TestCheats_Deal(t *testing.T) {
	cheats, sm := setupCheats(t)
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Deal is an alias for SetBalance (Foundry compatibility)
	amount := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	err := cheats.Deal(addr, amount)
	require.NoError(t, err)

	assert.Equal(t, amount, sm.GetBalance(addr))
}

func TestCheats_GetImpersonatedAccounts(t *testing.T) {
	cheats, _ := setupCheats(t)
	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")

	cheats.ImpersonateAccount(addr1)
	cheats.ImpersonateAccount(addr2)

	accounts := cheats.GetImpersonatedAccounts()
	assert.Len(t, accounts, 2)
	assert.Contains(t, accounts, addr1)
	assert.Contains(t, accounts, addr2)
}

func TestCheats_Mine(t *testing.T) {
	cheats, _ := setupCheats(t)

	// Test mine count tracking
	err := cheats.Mine(5)
	require.NoError(t, err)
	assert.Equal(t, uint64(5), cheats.GetPendingMineCount())

	// Consume pending mines
	count := cheats.ConsumePendingMines()
	assert.Equal(t, uint64(5), count)
	assert.Equal(t, uint64(0), cheats.GetPendingMineCount())
}

func TestCheats_SetAutomine(t *testing.T) {
	cheats, _ := setupCheats(t)

	// Default should be true (auto-mine enabled)
	assert.True(t, cheats.IsAutomine())

	// Disable auto-mine
	err := cheats.SetAutomine(false)
	require.NoError(t, err)
	assert.False(t, cheats.IsAutomine())

	// Re-enable auto-mine
	err = cheats.SetAutomine(true)
	require.NoError(t, err)
	assert.True(t, cheats.IsAutomine())
}

func TestCheats_SetIntervalMining(t *testing.T) {
	cheats, _ := setupCheats(t)

	// Default should be 0 (no interval mining)
	assert.Equal(t, uint64(0), cheats.GetIntervalMining())

	// Set interval mining to 5 seconds
	err := cheats.SetIntervalMining(5)
	require.NoError(t, err)
	assert.Equal(t, uint64(5), cheats.GetIntervalMining())

	// Setting interval mining should disable automine
	assert.False(t, cheats.IsAutomine())

	// Disable interval mining (set to 0)
	err = cheats.SetIntervalMining(0)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), cheats.GetIntervalMining())
}

func TestCheats_Reset(t *testing.T) {
	cheats, _ := setupCheats(t)
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Set various states
	cheats.ImpersonateAccount(addr)
	cheats.SetAutoImpersonate(true)
	cheats.SetAutomine(false)
	cheats.SetIntervalMining(10)
	cheats.SetNextBlockTimestamp(1800000000)
	cheats.Mine(5)

	// Reset all
	cheats.Reset()

	// Verify all states are reset
	assert.False(t, cheats.IsImpersonating(addr))
	assert.False(t, cheats.IsAutoImpersonate())
	assert.True(t, cheats.IsAutomine())
	assert.Equal(t, uint64(0), cheats.GetIntervalMining())
	assert.Equal(t, uint64(0), cheats.GetNextBlockTimestamp())
	assert.Equal(t, uint64(0), cheats.GetPendingMineCount())
}
