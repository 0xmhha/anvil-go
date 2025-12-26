package miner

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stable-net/anvil-go/pkg/blockchain"
	"github.com/stable-net/anvil-go/pkg/state"
	"github.com/stable-net/anvil-go/pkg/txpool"
)

func setupMiner(t *testing.T) (*SimpleMiner, *blockchain.Chain, *txpool.InMemoryPool, *state.InMemoryManager) {
	chainID := big.NewInt(31337)
	sm := state.NewInMemoryManager()
	chain := blockchain.NewChain(chainID)
	pool := txpool.NewInMemoryPool(sm, chainID)

	// Set genesis
	genesis := createGenesisBlock()
	err := chain.SetGenesis(genesis)
	require.NoError(t, err)

	miner := NewSimpleMiner(chain, pool, sm, chainID)
	return miner, chain, pool, sm
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
	return types.NewBlock(header, nil, nil, nil, hasher)
}

func generateKey(t *testing.T) (*ecdsa.PrivateKey, common.Address) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	addr := crypto.PubkeyToAddress(key.PublicKey)
	return key, addr
}

func createSignedTx(t *testing.T, key *ecdsa.PrivateKey, nonce uint64, to common.Address, value *big.Int) *types.Transaction {
	tx := types.NewTransaction(nonce, to, value, 21000, big.NewInt(1e9), nil)
	signer := types.NewEIP155Signer(big.NewInt(31337))
	signedTx, err := types.SignTx(tx, signer, key)
	require.NoError(t, err)
	return signedTx
}

func TestNewSimpleMiner(t *testing.T) {
	miner, _, _, _ := setupMiner(t)
	require.NotNil(t, miner)
}

func TestMiner_DefaultMode(t *testing.T) {
	miner, _, _, _ := setupMiner(t)
	assert.Equal(t, ModeAutomine, miner.Mode())
}

func TestMiner_SetMode(t *testing.T) {
	miner, _, _, _ := setupMiner(t)

	err := miner.SetMode(ModeManual)
	require.NoError(t, err)
	assert.Equal(t, ModeManual, miner.Mode())

	err = miner.SetMode(ModeInterval)
	require.NoError(t, err)
	assert.Equal(t, ModeInterval, miner.Mode())
}

func TestMiner_MineEmptyBlock(t *testing.T) {
	miner, chain, _, _ := setupMiner(t)

	block, err := miner.MineBlock()
	require.NoError(t, err)
	require.NotNil(t, block)

	assert.Equal(t, uint64(1), block.NumberU64())
	assert.Equal(t, uint64(1), chain.BlockNumber())
}

func TestMiner_MineBlockWithTransaction(t *testing.T) {
	miner, chain, pool, sm := setupMiner(t)

	// Fund account
	key, from := generateKey(t)
	balance := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	sm.SetBalance(from, balance)

	to := common.HexToAddress("0x1234567890123456789012345678901234567890")
	tx := createSignedTx(t, key, 0, to, big.NewInt(1e18))

	err := pool.Add(tx)
	require.NoError(t, err)

	block, err := miner.MineBlock()
	require.NoError(t, err)

	assert.Equal(t, uint64(1), block.NumberU64())
	assert.Equal(t, 1, len(block.Transactions()))
	assert.Equal(t, tx.Hash(), block.Transactions()[0].Hash())
	assert.Equal(t, uint64(1), chain.BlockNumber())

	// Pool should be empty after mining
	assert.Equal(t, 0, pool.Count())
}

func TestMiner_MineMultipleBlocks(t *testing.T) {
	miner, chain, _, _ := setupMiner(t)

	blocks, err := miner.MineBlocks(5)
	require.NoError(t, err)
	assert.Len(t, blocks, 5)

	assert.Equal(t, uint64(5), chain.BlockNumber())

	// Verify block sequence
	for i, block := range blocks {
		assert.Equal(t, uint64(i+1), block.NumberU64())
	}
}

func TestMiner_MineBlockWithTransactions(t *testing.T) {
	miner, chain, _, sm := setupMiner(t)

	key, from := generateKey(t)
	balance := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	sm.SetBalance(from, balance)

	to := common.HexToAddress("0x1234567890123456789012345678901234567890")

	txs := []*types.Transaction{
		createSignedTx(t, key, 0, to, big.NewInt(1e18)),
		createSignedTx(t, key, 1, to, big.NewInt(2e18)),
	}

	block, err := miner.MineBlockWithTransactions(txs)
	require.NoError(t, err)

	assert.Equal(t, uint64(1), block.NumberU64())
	assert.Equal(t, 2, len(block.Transactions()))
	assert.Equal(t, uint64(1), chain.BlockNumber())
}

func TestMiner_SetInterval(t *testing.T) {
	miner, _, _, _ := setupMiner(t)

	err := miner.SetInterval(5 * time.Second)
	require.NoError(t, err)

	assert.Equal(t, 5*time.Second, miner.Interval())
}

func TestMiner_StartStop(t *testing.T) {
	miner, _, _, _ := setupMiner(t)

	// Set manual mode first (can't start in automine mode)
	miner.SetMode(ModeInterval)
	miner.SetInterval(100 * time.Millisecond)

	err := miner.Start()
	require.NoError(t, err)

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	err = miner.Stop()
	require.NoError(t, err)
}

func TestMiner_BlockTimestamp(t *testing.T) {
	miner, chain, _, _ := setupMiner(t)

	// Set next block timestamp
	expectedTime := uint64(1800000000)
	chain.SetNextBlockTimestamp(expectedTime)

	block, err := miner.MineBlock()
	require.NoError(t, err)

	assert.Equal(t, expectedTime, block.Time())
}

func TestMiner_GasLimit(t *testing.T) {
	miner, _, _, _ := setupMiner(t)

	// Default gas limit
	block, err := miner.MineBlock()
	require.NoError(t, err)

	assert.Equal(t, uint64(30000000), block.GasLimit())
}

func TestMiner_ReceiptGeneration(t *testing.T) {
	miner, chain, pool, sm := setupMiner(t)

	key, from := generateKey(t)
	balance := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	sm.SetBalance(from, balance)

	to := common.HexToAddress("0x1234567890123456789012345678901234567890")
	tx := createSignedTx(t, key, 0, to, big.NewInt(1e18))

	pool.Add(tx)

	_, err := miner.MineBlock()
	require.NoError(t, err)

	// Receipt should be stored
	receipt, err := chain.GetReceipt(tx.Hash())
	require.NoError(t, err)
	assert.Equal(t, tx.Hash(), receipt.TxHash)
	assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
}

func TestMiningModeString(t *testing.T) {
	assert.Equal(t, "auto", ModeAutomine.String())
	assert.Equal(t, "interval", ModeInterval.String())
	assert.Equal(t, "manual", ModeManual.String())
}

func TestParseMiningMode(t *testing.T) {
	assert.Equal(t, ModeAutomine, ParseMiningMode("auto"))
	assert.Equal(t, ModeInterval, ParseMiningMode("interval"))
	assert.Equal(t, ModeManual, ParseMiningMode("manual"))
	assert.Equal(t, ModeAutomine, ParseMiningMode("unknown"))
}
