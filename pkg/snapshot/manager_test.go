package snapshot

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stable-net/anvil-go/pkg/blockchain"
	"github.com/stable-net/anvil-go/pkg/state"
	"github.com/stable-net/anvil-go/pkg/txpool"
)

func setupSnapshot(t *testing.T) (*Manager, *state.InMemoryManager, *blockchain.Chain, *txpool.InMemoryPool) {
	chainID := big.NewInt(31337)
	sm := state.NewInMemoryManager()
	chain := blockchain.NewChain(chainID)
	pool := txpool.NewInMemoryPool(sm, chainID)

	// Set genesis
	genesis := createGenesisBlock()
	err := chain.SetGenesis(genesis)
	require.NoError(t, err)

	manager := NewManager(sm, chain, pool)
	return manager, sm, chain, pool
}

func createGenesisBlock() *types.Block {
	header := &types.Header{
		ParentHash: common.Hash{},
		Number:     big.NewInt(0),
		Time:       uint64(1700000000),
		GasLimit:   30000000,
		Difficulty: big.NewInt(1),
		Coinbase:   common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
	}
	hasher := trie.NewStackTrie(nil)
	return types.NewBlock(header, nil, nil, hasher)
}

func TestNewManager(t *testing.T) {
	manager, _, _, _ := setupSnapshot(t)
	require.NotNil(t, manager)
}

func TestSnapshot_CreateAndRevert(t *testing.T) {
	manager, sm, _, _ := setupSnapshot(t)

	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	initialBalance := big.NewInt(1000)
	sm.SetBalance(addr, initialBalance)

	// Create snapshot
	snapID := manager.Snapshot()
	assert.Greater(t, snapID, uint64(0))

	// Modify state
	newBalance := big.NewInt(9999)
	sm.SetBalance(addr, newBalance)
	assert.Equal(t, newBalance, sm.GetBalance(addr))

	// Revert to snapshot
	success := manager.Revert(snapID)
	assert.True(t, success)

	// State should be restored
	assert.Equal(t, initialBalance, sm.GetBalance(addr))
}

func TestSnapshot_MultipleSnapshots(t *testing.T) {
	manager, sm, _, _ := setupSnapshot(t)

	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// State 1: balance = 100
	sm.SetBalance(addr, big.NewInt(100))
	snap1 := manager.Snapshot()

	// State 2: balance = 200
	sm.SetBalance(addr, big.NewInt(200))
	snap2 := manager.Snapshot()

	// State 3: balance = 300
	sm.SetBalance(addr, big.NewInt(300))

	// Revert to snap2
	success := manager.Revert(snap2)
	assert.True(t, success)
	assert.Equal(t, big.NewInt(200), sm.GetBalance(addr))

	// Revert to snap1
	success = manager.Revert(snap1)
	assert.True(t, success)
	assert.Equal(t, big.NewInt(100), sm.GetBalance(addr))
}

func TestSnapshot_RevertNonExistent(t *testing.T) {
	manager, _, _, _ := setupSnapshot(t)

	success := manager.Revert(9999)
	assert.False(t, success)
}

func TestSnapshot_List(t *testing.T) {
	manager, sm, _, _ := setupSnapshot(t)

	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	sm.SetBalance(addr, big.NewInt(100))

	snap1 := manager.Snapshot()
	sm.SetBalance(addr, big.NewInt(200))
	snap2 := manager.Snapshot()
	sm.SetBalance(addr, big.NewInt(300))
	snap3 := manager.Snapshot()

	snapshots := manager.List()
	assert.Len(t, snapshots, 3)
	assert.Contains(t, snapshots, snap1)
	assert.Contains(t, snapshots, snap2)
	assert.Contains(t, snapshots, snap3)
}

func TestSnapshot_Delete(t *testing.T) {
	manager, sm, _, _ := setupSnapshot(t)

	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	sm.SetBalance(addr, big.NewInt(100))

	snapID := manager.Snapshot()

	// Delete the snapshot
	success := manager.Delete(snapID)
	assert.True(t, success)

	// Reverting should fail
	success = manager.Revert(snapID)
	assert.False(t, success)
}

func TestSnapshot_DeleteNonExistent(t *testing.T) {
	manager, _, _, _ := setupSnapshot(t)

	success := manager.Delete(9999)
	assert.False(t, success)
}

func TestSnapshot_Clear(t *testing.T) {
	manager, sm, _, _ := setupSnapshot(t)

	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	sm.SetBalance(addr, big.NewInt(100))

	manager.Snapshot()
	manager.Snapshot()
	manager.Snapshot()

	assert.Len(t, manager.List(), 3)

	manager.Clear()

	assert.Len(t, manager.List(), 0)
}

func TestSnapshot_BlockNumberTracking(t *testing.T) {
	manager, sm, chain, _ := setupSnapshot(t)

	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	sm.SetBalance(addr, big.NewInt(100))

	// Snapshot at block 0
	snapID := manager.Snapshot()

	// Add a block to the chain (simulate mining)
	header := &types.Header{
		ParentHash: chain.CurrentBlock().Hash(),
		Number:     big.NewInt(1),
		Time:       uint64(1700000001),
		GasLimit:   30000000,
		Difficulty: big.NewInt(1),
		Coinbase:   common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
	}
	hasher := trie.NewStackTrie(nil)
	block := types.NewBlock(header, nil, nil, hasher)
	chain.AddBlock(block)

	assert.Equal(t, uint64(1), chain.BlockNumber())

	// Modify state
	sm.SetBalance(addr, big.NewInt(9999))

	// Revert - block number should also revert
	success := manager.Revert(snapID)
	assert.True(t, success)

	// State should be restored
	assert.Equal(t, big.NewInt(100), sm.GetBalance(addr))
}

func TestSnapshot_Count(t *testing.T) {
	manager, _, _, _ := setupSnapshot(t)

	assert.Equal(t, 0, manager.Count())

	manager.Snapshot()
	assert.Equal(t, 1, manager.Count())

	manager.Snapshot()
	manager.Snapshot()
	assert.Equal(t, 3, manager.Count())
}
