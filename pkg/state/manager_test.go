package state

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInMemoryManager(t *testing.T) {
	sm := NewInMemoryManager()
	require.NotNil(t, sm)
}

func TestStateBalance(t *testing.T) {
	sm := NewInMemoryManager()
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	balance := big.NewInt(1000)

	// Initial balance is zero
	assert.Equal(t, big.NewInt(0), sm.GetBalance(addr))

	// Set balance
	err := sm.SetBalance(addr, balance)
	require.NoError(t, err)

	// Get balance
	assert.Equal(t, balance, sm.GetBalance(addr))
}

func TestStateBalance_Large(t *testing.T) {
	sm := NewInMemoryManager()
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// 10000 ETH in wei
	balance := new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e18))

	err := sm.SetBalance(addr, balance)
	require.NoError(t, err)

	got := sm.GetBalance(addr)
	assert.Equal(t, balance, got)
}

func TestStateNonce(t *testing.T) {
	sm := NewInMemoryManager()
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Initial nonce is zero
	assert.Equal(t, uint64(0), sm.GetNonce(addr))

	// Set nonce
	err := sm.SetNonce(addr, 5)
	require.NoError(t, err)

	// Get nonce
	assert.Equal(t, uint64(5), sm.GetNonce(addr))
}

func TestStateCode(t *testing.T) {
	sm := NewInMemoryManager()
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	code := []byte{0x60, 0x00, 0x60, 0x00, 0xf3} // PUSH1 0 PUSH1 0 RETURN

	// Initial code is nil
	assert.Nil(t, sm.GetCode(addr))

	// Set code
	err := sm.SetCode(addr, code)
	require.NoError(t, err)

	// Get code
	assert.Equal(t, code, sm.GetCode(addr))
}

func TestStateCodeHash(t *testing.T) {
	sm := NewInMemoryManager()
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	code := []byte{0x60, 0x00, 0x60, 0x00, 0xf3}

	// Set code
	err := sm.SetCode(addr, code)
	require.NoError(t, err)

	// Code hash should be non-zero after setting code
	codeHash := sm.GetCodeHash(addr)
	assert.NotEqual(t, common.Hash{}, codeHash)
}

func TestStateStorage(t *testing.T) {
	sm := NewInMemoryManager()
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	slot := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	value := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000042")

	// Initial storage is zero
	assert.Equal(t, common.Hash{}, sm.GetStorageAt(addr, slot))

	// Set storage
	err := sm.SetStorageAt(addr, slot, value)
	require.NoError(t, err)

	// Get storage
	assert.Equal(t, value, sm.GetStorageAt(addr, slot))
}

func TestStateExist(t *testing.T) {
	sm := NewInMemoryManager()
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Non-existent account
	assert.False(t, sm.Exist(addr))

	// After setting balance, account exists
	sm.SetBalance(addr, big.NewInt(1))
	assert.True(t, sm.Exist(addr))
}

func TestStateCreateAccount(t *testing.T) {
	sm := NewInMemoryManager()
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	assert.False(t, sm.Exist(addr))

	err := sm.CreateAccount(addr)
	require.NoError(t, err)

	assert.True(t, sm.Exist(addr))
	assert.Equal(t, big.NewInt(0), sm.GetBalance(addr))
	assert.Equal(t, uint64(0), sm.GetNonce(addr))
}

func TestStateDeleteAccount(t *testing.T) {
	sm := NewInMemoryManager()
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Create and set up account
	sm.CreateAccount(addr)
	sm.SetBalance(addr, big.NewInt(1000))
	sm.SetNonce(addr, 5)
	sm.SetCode(addr, []byte{0x60, 0x00})

	assert.True(t, sm.Exist(addr))

	// Delete account
	err := sm.DeleteAccount(addr)
	require.NoError(t, err)

	// Account should no longer exist
	assert.False(t, sm.Exist(addr))
	assert.Equal(t, big.NewInt(0), sm.GetBalance(addr))
	assert.Equal(t, uint64(0), sm.GetNonce(addr))
}

func TestStateCopy(t *testing.T) {
	sm := NewInMemoryManager()
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	balance := big.NewInt(1000)

	sm.SetBalance(addr, balance)

	// Create copy
	copied := sm.Copy()

	// Modify original
	sm.SetBalance(addr, big.NewInt(9999))

	// Copy should be unchanged
	assert.Equal(t, balance, copied.GetBalance(addr))
}

func TestStateSnapshot(t *testing.T) {
	sm := NewInMemoryManager()
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Set initial balance
	sm.SetBalance(addr, big.NewInt(1000))

	// Take snapshot
	snapID := sm.Snapshot()

	// Modify state
	sm.SetBalance(addr, big.NewInt(2000))
	assert.Equal(t, big.NewInt(2000), sm.GetBalance(addr))

	// Revert to snapshot
	sm.RevertToSnapshot(snapID)

	// State should be restored
	assert.Equal(t, big.NewInt(1000), sm.GetBalance(addr))
}

func TestStateMultipleSnapshots(t *testing.T) {
	sm := NewInMemoryManager()
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	sm.SetBalance(addr, big.NewInt(100))
	snap1 := sm.Snapshot()

	sm.SetBalance(addr, big.NewInt(200))
	snap2 := sm.Snapshot()

	sm.SetBalance(addr, big.NewInt(300))

	// Revert to snap2
	sm.RevertToSnapshot(snap2)
	assert.Equal(t, big.NewInt(200), sm.GetBalance(addr))

	// Revert to snap1
	sm.RevertToSnapshot(snap1)
	assert.Equal(t, big.NewInt(100), sm.GetBalance(addr))
}

func TestStateRoot(t *testing.T) {
	sm := NewInMemoryManager()
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Get initial root
	root1 := sm.Root()

	// Modify state
	sm.SetBalance(addr, big.NewInt(1000))
	sm.Commit()

	// Root should change
	root2 := sm.Root()
	assert.NotEqual(t, root1, root2)
}

func TestStateCommit(t *testing.T) {
	sm := NewInMemoryManager()
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	sm.SetBalance(addr, big.NewInt(1000))

	root, err := sm.Commit()

	require.NoError(t, err)
	assert.NotEqual(t, common.Hash{}, root)
}

func TestMultipleAccounts(t *testing.T) {
	sm := NewInMemoryManager()

	accounts := []struct {
		addr    common.Address
		balance *big.Int
		nonce   uint64
	}{
		{common.HexToAddress("0x1111111111111111111111111111111111111111"), big.NewInt(100), 1},
		{common.HexToAddress("0x2222222222222222222222222222222222222222"), big.NewInt(200), 2},
		{common.HexToAddress("0x3333333333333333333333333333333333333333"), big.NewInt(300), 3},
	}

	// Set up all accounts
	for _, acc := range accounts {
		sm.SetBalance(acc.addr, acc.balance)
		sm.SetNonce(acc.addr, acc.nonce)
	}

	// Verify all accounts
	for _, acc := range accounts {
		assert.Equal(t, acc.balance, sm.GetBalance(acc.addr))
		assert.Equal(t, acc.nonce, sm.GetNonce(acc.addr))
	}
}

func TestDump(t *testing.T) {
	sm := NewInMemoryManager()

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	sm.SetBalance(addr, big.NewInt(1000))
	sm.SetNonce(addr, 5)
	sm.SetCode(addr, []byte{0x60, 0x00, 0xf3})
	sm.SetStorageAt(addr, common.HexToHash("0x01"), common.HexToHash("0x42"))

	dump := sm.Dump()

	require.NotNil(t, dump)
	require.NotNil(t, dump.Accounts)
	assert.Len(t, dump.Accounts, 1)

	accDump, exists := dump.Accounts[addr.Hex()]
	require.True(t, exists)
	assert.Equal(t, "0x3e8", accDump.Balance) // 1000 in hex
	assert.Equal(t, uint64(5), accDump.Nonce)
	assert.Equal(t, "0x6000f3", accDump.Code)
	assert.NotEmpty(t, accDump.Storage)
}

func TestDump_EmptyState(t *testing.T) {
	sm := NewInMemoryManager()

	dump := sm.Dump()

	require.NotNil(t, dump)
	assert.Empty(t, dump.Accounts)
}

func TestDump_MultipleAccounts(t *testing.T) {
	sm := NewInMemoryManager()

	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")

	sm.SetBalance(addr1, big.NewInt(100))
	sm.SetBalance(addr2, big.NewInt(200))

	dump := sm.Dump()

	assert.Len(t, dump.Accounts, 2)
	assert.Contains(t, dump.Accounts, addr1.Hex())
	assert.Contains(t, dump.Accounts, addr2.Hex())
}

func TestDumpJSON(t *testing.T) {
	sm := NewInMemoryManager()

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	sm.SetBalance(addr, big.NewInt(1000))
	sm.SetNonce(addr, 5)

	data, err := sm.DumpJSON()

	require.NoError(t, err)
	require.NotEmpty(t, data)
	assert.Contains(t, string(data), "0x1111111111111111111111111111111111111111")
	assert.Contains(t, string(data), "0x3e8") // 1000 in hex
}

func TestLoad(t *testing.T) {
	sm := NewInMemoryManager()

	dump := &StateDump{
		Accounts: map[string]AccountDump{
			"0x1111111111111111111111111111111111111111": {
				Balance: "0x3e8",
				Nonce:   5,
				Code:    "0x6000f3",
				Storage: map[string]string{
					"0x0000000000000000000000000000000000000000000000000000000000000001": "0x0000000000000000000000000000000000000000000000000000000000000042",
				},
			},
		},
	}

	err := sm.Load(dump)
	require.NoError(t, err)

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	assert.Equal(t, big.NewInt(1000), sm.GetBalance(addr))
	assert.Equal(t, uint64(5), sm.GetNonce(addr))
	assert.Equal(t, []byte{0x60, 0x00, 0xf3}, sm.GetCode(addr))
	assert.Equal(t, common.HexToHash("0x42"), sm.GetStorageAt(addr, common.HexToHash("0x01")))
}

func TestLoad_NilDump(t *testing.T) {
	sm := NewInMemoryManager()

	err := sm.Load(nil)
	require.NoError(t, err)
}

func TestLoad_EmptyDump(t *testing.T) {
	sm := NewInMemoryManager()

	dump := &StateDump{
		Accounts: nil,
	}

	err := sm.Load(dump)
	require.NoError(t, err)
}

func TestLoad_InvalidBalance(t *testing.T) {
	sm := NewInMemoryManager()

	dump := &StateDump{
		Accounts: map[string]AccountDump{
			"0x1111111111111111111111111111111111111111": {
				Balance: "invalid",
				Nonce:   0,
			},
		},
	}

	err := sm.Load(dump)
	assert.Error(t, err)
}

func TestLoad_InvalidCode(t *testing.T) {
	sm := NewInMemoryManager()

	dump := &StateDump{
		Accounts: map[string]AccountDump{
			"0x1111111111111111111111111111111111111111": {
				Balance: "0x0",
				Code:    "invalid",
			},
		},
	}

	err := sm.Load(dump)
	assert.Error(t, err)
}

func TestLoadJSON(t *testing.T) {
	sm := NewInMemoryManager()

	jsonData := `{
		"accounts": {
			"0x1111111111111111111111111111111111111111": {
				"balance": "0x3e8",
				"nonce": 5,
				"code": "0x6000f3"
			}
		}
	}`

	err := sm.LoadJSON([]byte(jsonData))
	require.NoError(t, err)

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	assert.Equal(t, big.NewInt(1000), sm.GetBalance(addr))
	assert.Equal(t, uint64(5), sm.GetNonce(addr))
	assert.Equal(t, []byte{0x60, 0x00, 0xf3}, sm.GetCode(addr))
}

func TestLoadJSON_InvalidJSON(t *testing.T) {
	sm := NewInMemoryManager()

	err := sm.LoadJSON([]byte("invalid json"))
	assert.Error(t, err)
}

func TestDumpAndLoad_RoundTrip(t *testing.T) {
	sm1 := NewInMemoryManager()

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	sm1.SetBalance(addr, big.NewInt(1000))
	sm1.SetNonce(addr, 5)
	sm1.SetCode(addr, []byte{0x60, 0x00, 0xf3})
	sm1.SetStorageAt(addr, common.HexToHash("0x01"), common.HexToHash("0x42"))

	// Dump to JSON
	jsonData, err := sm1.DumpJSON()
	require.NoError(t, err)

	// Load into new manager
	sm2 := NewInMemoryManager()
	err = sm2.LoadJSON(jsonData)
	require.NoError(t, err)

	// Verify state matches
	assert.Equal(t, sm1.GetBalance(addr), sm2.GetBalance(addr))
	assert.Equal(t, sm1.GetNonce(addr), sm2.GetNonce(addr))
	assert.Equal(t, sm1.GetCode(addr), sm2.GetCode(addr))
	assert.Equal(t, sm1.GetStorageAt(addr, common.HexToHash("0x01")), sm2.GetStorageAt(addr, common.HexToHash("0x01")))
}

func TestClear(t *testing.T) {
	sm := NewInMemoryManager()

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	sm.SetBalance(addr, big.NewInt(1000))
	sm.SetNonce(addr, 5)
	sm.Snapshot()

	assert.True(t, sm.Exist(addr))
	assert.Greater(t, sm.AccountCount(), 0)

	sm.Clear()

	assert.False(t, sm.Exist(addr))
	assert.Equal(t, 0, sm.AccountCount())
}

func TestAccountCount(t *testing.T) {
	sm := NewInMemoryManager()

	assert.Equal(t, 0, sm.AccountCount())

	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")

	sm.SetBalance(addr1, big.NewInt(100))
	assert.Equal(t, 1, sm.AccountCount())

	sm.SetBalance(addr2, big.NewInt(200))
	assert.Equal(t, 2, sm.AccountCount())

	sm.DeleteAccount(addr1)
	assert.Equal(t, 1, sm.AccountCount())
}
