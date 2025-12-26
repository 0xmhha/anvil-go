package blockchain

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewChain(t *testing.T) {
	chain := NewChain(big.NewInt(31337))
	require.NotNil(t, chain)
	assert.Equal(t, big.NewInt(31337), chain.ChainID())
}

func TestChain_GenesisBlock(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	// Set genesis block
	genesis := createTestBlock(t, 0, common.Hash{})
	err := chain.SetGenesis(genesis)
	require.NoError(t, err)

	// Current block should be genesis
	current := chain.CurrentBlock()
	require.NotNil(t, current)
	assert.Equal(t, uint64(0), current.NumberU64())

	// Block number should be 0
	assert.Equal(t, uint64(0), chain.BlockNumber())
}

func TestChain_AddBlock(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	genesis := createTestBlock(t, 0, common.Hash{})
	chain.SetGenesis(genesis)

	// Add block 1
	block1 := createTestBlock(t, 1, genesis.Hash())
	err := chain.AddBlock(block1)
	require.NoError(t, err)

	assert.Equal(t, uint64(1), chain.BlockNumber())
	assert.Equal(t, block1.Hash(), chain.CurrentBlock().Hash())
}

func TestChain_BlockByNumber(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	genesis := createTestBlock(t, 0, common.Hash{})
	chain.SetGenesis(genesis)

	block1 := createTestBlock(t, 1, genesis.Hash())
	chain.AddBlock(block1)

	block2 := createTestBlock(t, 2, block1.Hash())
	chain.AddBlock(block2)

	// Get block by number
	got, err := chain.BlockByNumber(1)
	require.NoError(t, err)
	assert.Equal(t, block1.Hash(), got.Hash())

	got, err = chain.BlockByNumber(2)
	require.NoError(t, err)
	assert.Equal(t, block2.Hash(), got.Hash())
}

func TestChain_BlockByNumber_NotFound(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	genesis := createTestBlock(t, 0, common.Hash{})
	chain.SetGenesis(genesis)

	_, err := chain.BlockByNumber(999)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBlockNotFound)
}

func TestChain_BlockByHash(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	genesis := createTestBlock(t, 0, common.Hash{})
	chain.SetGenesis(genesis)

	block1 := createTestBlock(t, 1, genesis.Hash())
	chain.AddBlock(block1)

	// Get block by hash
	got, err := chain.BlockByHash(block1.Hash())
	require.NoError(t, err)
	assert.Equal(t, block1.NumberU64(), got.NumberU64())
}

func TestChain_BlockByHash_NotFound(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	genesis := createTestBlock(t, 0, common.Hash{})
	chain.SetGenesis(genesis)

	_, err := chain.BlockByHash(common.HexToHash("0x1234"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBlockNotFound)
}

func TestChain_AddReceipt(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	genesis := createTestBlock(t, 0, common.Hash{})
	chain.SetGenesis(genesis)

	txHash := common.HexToHash("0xabcd")
	receipt := &types.Receipt{
		Status:      types.ReceiptStatusSuccessful,
		TxHash:      txHash,
		BlockNumber: big.NewInt(0),
		GasUsed:     21000,
	}

	err := chain.AddReceipt(txHash, receipt)
	require.NoError(t, err)

	// Get receipt
	got, err := chain.GetReceipt(txHash)
	require.NoError(t, err)
	assert.Equal(t, txHash, got.TxHash)
	assert.Equal(t, uint64(21000), got.GasUsed)
}

func TestChain_GetReceipt_NotFound(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	genesis := createTestBlock(t, 0, common.Hash{})
	chain.SetGenesis(genesis)

	_, err := chain.GetReceipt(common.HexToHash("0x1234"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrReceiptNotFound)
}

func TestChain_GetHeader(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	genesis := createTestBlock(t, 0, common.Hash{})
	chain.SetGenesis(genesis)

	header := chain.GetHeader(genesis.Hash())
	require.NotNil(t, header)
	assert.Equal(t, genesis.Hash(), header.Hash())
}

func TestChain_GetHeaderByNumber(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	genesis := createTestBlock(t, 0, common.Hash{})
	chain.SetGenesis(genesis)

	block1 := createTestBlock(t, 1, genesis.Hash())
	chain.AddBlock(block1)

	header := chain.GetHeaderByNumber(1)
	require.NotNil(t, header)
	assert.Equal(t, uint64(1), header.Number.Uint64())
}

func TestChain_HasBlock(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	genesis := createTestBlock(t, 0, common.Hash{})
	chain.SetGenesis(genesis)

	assert.True(t, chain.HasBlock(genesis.Hash()))
	assert.False(t, chain.HasBlock(common.HexToHash("0x1234")))
}

func TestChain_MultipleBlocks(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	genesis := createTestBlock(t, 0, common.Hash{})
	chain.SetGenesis(genesis)

	// Add 10 blocks
	parent := genesis
	for i := uint64(1); i <= 10; i++ {
		block := createTestBlock(t, i, parent.Hash())
		err := chain.AddBlock(block)
		require.NoError(t, err)
		parent = block
	}

	assert.Equal(t, uint64(10), chain.BlockNumber())

	// Verify all blocks are accessible
	for i := uint64(0); i <= 10; i++ {
		block, err := chain.BlockByNumber(i)
		require.NoError(t, err)
		assert.Equal(t, i, block.NumberU64())
	}
}

func TestChain_SetNextBlockTimestamp(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	genesis := createTestBlock(t, 0, common.Hash{})
	chain.SetGenesis(genesis)

	// Set next block timestamp
	expectedTimestamp := uint64(1700000000)
	chain.SetNextBlockTimestamp(expectedTimestamp)

	assert.Equal(t, expectedTimestamp, chain.NextBlockTimestamp())
}

func TestChain_SetNextBlockBaseFee(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	genesis := createTestBlock(t, 0, common.Hash{})
	chain.SetGenesis(genesis)

	// Set next block base fee
	baseFee := big.NewInt(1e9)
	chain.SetNextBlockBaseFee(baseFee)

	assert.Equal(t, baseFee, chain.NextBlockBaseFee())
}

func TestChain_Coinbase(t *testing.T) {
	chain := NewChain(big.NewInt(31337))

	// Default coinbase
	defaultCoinbase := chain.Coinbase()
	assert.NotEqual(t, common.Address{}, defaultCoinbase)

	// Set new coinbase
	newCoinbase := common.HexToAddress("0x1234567890123456789012345678901234567890")
	chain.SetCoinbase(newCoinbase)

	assert.Equal(t, newCoinbase, chain.Coinbase())
}

// Test helpers
func createTestBlock(t *testing.T, number uint64, parentHash common.Hash) *types.Block {
	header := &types.Header{
		ParentHash: parentHash,
		Number:     big.NewInt(int64(number)),
		Time:       1700000000 + number,
		GasLimit:   30000000,
		Difficulty: big.NewInt(1),
		Coinbase:   common.HexToAddress("0x0000000000000000000000000000000000000000"),
	}

	return types.NewBlock(header, nil, nil, nil)
}
