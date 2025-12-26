// Package blockchain provides blockchain management for the simulator.
package blockchain

import (
	"errors"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Common errors.
var (
	ErrBlockNotFound   = errors.New("block not found")
	ErrReceiptNotFound = errors.New("receipt not found")
	ErrNoGenesis       = errors.New("no genesis block set")
	ErrInvalidBlock    = errors.New("invalid block")
)

// pendingTxEntry holds a pending transaction with its sender.
type pendingTxEntry struct {
	tx   *types.Transaction
	from common.Address
}

// Chain manages the blockchain state.
type Chain struct {
	chainID *big.Int

	// Block storage
	blocks       map[common.Hash]*types.Block
	blockNumbers map[uint64]common.Hash
	headers      map[common.Hash]*types.Header

	// Current state
	currentBlock *types.Block
	genesis      *types.Block

	// Receipts
	receipts map[common.Hash]*types.Receipt

	// Pending transactions (not yet mined)
	pendingTxs map[common.Hash]*pendingTxEntry

	// Mining parameters
	coinbase           common.Address
	nextBlockTimestamp uint64
	nextBlockBaseFee   *big.Int

	mu sync.RWMutex
}

// NewChain creates a new blockchain manager.
func NewChain(chainID *big.Int) *Chain {
	// Default coinbase is the first Anvil test account
	defaultCoinbase := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")

	return &Chain{
		chainID:      chainID,
		blocks:       make(map[common.Hash]*types.Block),
		blockNumbers: make(map[uint64]common.Hash),
		headers:      make(map[common.Hash]*types.Header),
		receipts:     make(map[common.Hash]*types.Receipt),
		pendingTxs:   make(map[common.Hash]*pendingTxEntry),
		coinbase:     defaultCoinbase,
	}
}

// ChainID returns the chain ID.
func (c *Chain) ChainID() *big.Int {
	return new(big.Int).Set(c.chainID)
}

// SetGenesis sets the genesis block.
func (c *Chain) SetGenesis(block *types.Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if block.NumberU64() != 0 {
		return ErrInvalidBlock
	}

	c.genesis = block
	c.currentBlock = block
	c.blocks[block.Hash()] = block
	c.blockNumbers[0] = block.Hash()
	c.headers[block.Hash()] = block.Header()

	return nil
}

// CurrentBlock returns the current block.
func (c *Chain) CurrentBlock() *types.Block {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.currentBlock
}

// BlockNumber returns the current block number.
func (c *Chain) BlockNumber() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.currentBlock == nil {
		return 0
	}
	return c.currentBlock.NumberU64()
}

// AddBlock adds a new block to the chain.
func (c *Chain) AddBlock(block *types.Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.genesis == nil {
		return ErrNoGenesis
	}

	// Verify parent exists
	if _, exists := c.blocks[block.ParentHash()]; !exists {
		return ErrInvalidBlock
	}

	// Verify block number is sequential
	expectedNumber := c.currentBlock.NumberU64() + 1
	if block.NumberU64() != expectedNumber {
		return ErrInvalidBlock
	}

	c.blocks[block.Hash()] = block
	c.blockNumbers[block.NumberU64()] = block.Hash()
	c.headers[block.Hash()] = block.Header()
	c.currentBlock = block

	// Reset next block parameters
	c.nextBlockTimestamp = 0
	c.nextBlockBaseFee = nil

	return nil
}

// BlockByNumber retrieves a block by its number.
func (c *Chain) BlockByNumber(number uint64) (*types.Block, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hash, exists := c.blockNumbers[number]
	if !exists {
		return nil, ErrBlockNotFound
	}

	block, exists := c.blocks[hash]
	if !exists {
		return nil, ErrBlockNotFound
	}

	return block, nil
}

// BlockByHash retrieves a block by its hash.
func (c *Chain) BlockByHash(hash common.Hash) (*types.Block, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	block, exists := c.blocks[hash]
	if !exists {
		return nil, ErrBlockNotFound
	}

	return block, nil
}

// HasBlock checks if a block exists.
func (c *Chain) HasBlock(hash common.Hash) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, exists := c.blocks[hash]
	return exists
}

// GetHeader returns the header for a block hash.
func (c *Chain) GetHeader(hash common.Hash) *types.Header {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.headers[hash]
}

// GetHeaderByNumber returns the header for a block number.
func (c *Chain) GetHeaderByNumber(number uint64) *types.Header {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hash, exists := c.blockNumbers[number]
	if !exists {
		return nil
	}
	return c.headers[hash]
}

// AddReceipt adds a transaction receipt.
func (c *Chain) AddReceipt(txHash common.Hash, receipt *types.Receipt) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.receipts[txHash] = receipt
	return nil
}

// GetReceipt retrieves a transaction receipt.
func (c *Chain) GetReceipt(txHash common.Hash) (*types.Receipt, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	receipt, exists := c.receipts[txHash]
	if !exists {
		return nil, ErrReceiptNotFound
	}

	return receipt, nil
}

// SetNextBlockTimestamp sets the timestamp for the next block.
func (c *Chain) SetNextBlockTimestamp(timestamp uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.nextBlockTimestamp = timestamp
}

// NextBlockTimestamp returns the next block's timestamp.
func (c *Chain) NextBlockTimestamp() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.nextBlockTimestamp
}

// SetNextBlockBaseFee sets the base fee for the next block.
func (c *Chain) SetNextBlockBaseFee(baseFee *big.Int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.nextBlockBaseFee = new(big.Int).Set(baseFee)
}

// NextBlockBaseFee returns the next block's base fee.
func (c *Chain) NextBlockBaseFee() *big.Int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.nextBlockBaseFee == nil {
		return nil
	}
	return new(big.Int).Set(c.nextBlockBaseFee)
}

// SetCoinbase sets the coinbase address.
func (c *Chain) SetCoinbase(addr common.Address) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.coinbase = addr
}

// Coinbase returns the coinbase address.
func (c *Chain) Coinbase() common.Address {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.coinbase
}

// Genesis returns the genesis block.
func (c *Chain) Genesis() *types.Block {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.genesis
}

// GetBlockReceipts returns all receipts for a block.
func (c *Chain) GetBlockReceipts(blockHash common.Hash) []*types.Receipt {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var receipts []*types.Receipt
	for _, receipt := range c.receipts {
		if receipt.BlockHash == blockHash {
			receipts = append(receipts, receipt)
		}
	}
	return receipts
}

// Clear removes all blocks except genesis.
func (c *Chain) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.blocks = make(map[common.Hash]*types.Block)
	c.blockNumbers = make(map[uint64]common.Hash)
	c.headers = make(map[common.Hash]*types.Header)
	c.receipts = make(map[common.Hash]*types.Receipt)

	if c.genesis != nil {
		c.blocks[c.genesis.Hash()] = c.genesis
		c.blockNumbers[0] = c.genesis.Hash()
		c.headers[c.genesis.Hash()] = c.genesis.Header()
		c.currentBlock = c.genesis
	}
}

// GetBlockByNumber retrieves a block by its number (returns nil if not found).
func (c *Chain) GetBlockByNumber(number uint64) *types.Block {
	block, _ := c.BlockByNumber(number)
	return block
}

// GetBlockByHash retrieves a block by its hash (returns nil if not found).
func (c *Chain) GetBlockByHash(hash common.Hash) *types.Block {
	block, _ := c.BlockByHash(hash)
	return block
}

// GetTransaction retrieves a transaction by its hash.
// Returns the transaction, block hash, block number, and transaction index.
func (c *Chain) GetTransaction(txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// First check mined transactions in blocks
	for _, block := range c.blocks {
		for i, tx := range block.Transactions() {
			if tx.Hash() == txHash {
				return tx, block.Hash(), block.NumberU64(), uint64(i)
			}
		}
	}

	// Check pending transactions
	if entry, exists := c.pendingTxs[txHash]; exists {
		// Return with empty block hash to indicate pending
		return entry.tx, common.Hash{}, 0, 0
	}

	return nil, common.Hash{}, 0, 0
}

// AddPendingTransaction adds a pending transaction with its sender.
func (c *Chain) AddPendingTransaction(tx *types.Transaction, from common.Address) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pendingTxs[tx.Hash()] = &pendingTxEntry{
		tx:   tx,
		from: from,
	}
}

// GetPendingTransactionSender returns the sender of a pending transaction.
func (c *Chain) GetPendingTransactionSender(txHash common.Hash) (common.Address, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if entry, exists := c.pendingTxs[txHash]; exists {
		return entry.from, true
	}
	return common.Address{}, false
}
