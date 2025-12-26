package miner

import (
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/stable-net/anvil-go/pkg/blockchain"
	"github.com/stable-net/anvil-go/pkg/state"
	"github.com/stable-net/anvil-go/pkg/txpool"
)

// Common errors.
var (
	ErrAlreadyRunning = errors.New("miner already running")
	ErrNotRunning     = errors.New("miner not running")
)

// SimpleMiner implements the Miner interface.
type SimpleMiner struct {
	chain        *blockchain.Chain
	pool         *txpool.InMemoryPool
	stateManager *state.InMemoryManager
	chainID      *big.Int
	signer       types.Signer

	mode     MiningMode
	interval time.Duration
	running  bool
	stopCh   chan struct{}

	gasLimit uint64

	mu sync.Mutex
}

// NewSimpleMiner creates a new simple miner.
func NewSimpleMiner(chain *blockchain.Chain, pool *txpool.InMemoryPool, sm *state.InMemoryManager, chainID *big.Int) *SimpleMiner {
	return &SimpleMiner{
		chain:        chain,
		pool:         pool,
		stateManager: sm,
		chainID:      chainID,
		signer:       types.NewEIP155Signer(chainID),
		mode:         ModeAutomine,
		interval:     time.Second,
		gasLimit:     30000000,
	}
}

// MineBlock mines a single block with pending transactions.
func (m *SimpleMiner) MineBlock() (*types.Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get pending transactions
	pending := m.pool.Pending()

	return m.mineBlockWithTxs(pending)
}

// MineBlocks mines multiple empty blocks.
func (m *SimpleMiner) MineBlocks(count uint64) ([]*types.Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	blocks := make([]*types.Block, 0, count)
	for i := uint64(0); i < count; i++ {
		block, err := m.mineBlockWithTxs(nil)
		if err != nil {
			return blocks, err
		}
		blocks = append(blocks, block)
	}

	return blocks, nil
}

// MineBlockWithTransactions mines a block with specific transactions.
func (m *SimpleMiner) MineBlockWithTransactions(txs []*types.Transaction) (*types.Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.mineBlockWithTxs(txs)
}

// mineBlockWithTxs creates and adds a new block with the given transactions.
func (m *SimpleMiner) mineBlockWithTxs(txs []*types.Transaction) (*types.Block, error) {
	parent := m.chain.CurrentBlock()

	// Determine block timestamp
	timestamp := m.chain.NextBlockTimestamp()
	if timestamp == 0 {
		timestamp = uint64(time.Now().Unix())
		if timestamp <= parent.Time() {
			timestamp = parent.Time() + 1
		}
	}

	// Determine base fee
	baseFee := m.chain.NextBlockBaseFee()
	if baseFee == nil {
		baseFee = big.NewInt(1e9) // Default 1 gwei
	}

	// Create block header
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number(), big.NewInt(1)),
		Time:       timestamp,
		GasLimit:   m.gasLimit,
		Difficulty: big.NewInt(1),
		Coinbase:   m.chain.Coinbase(),
		BaseFee:    baseFee,
	}

	// Execute transactions and create receipts
	var (
		receipts   []*types.Receipt
		usedGas    uint64
		successful []*types.Transaction
	)

	for _, tx := range txs {
		// Simple execution - just transfer value
		receipt := m.executeTx(tx, header, usedGas)
		if receipt != nil {
			receipts = append(receipts, receipt)
			successful = append(successful, tx)
			usedGas += receipt.GasUsed

			// Store receipt
			m.chain.AddReceipt(tx.Hash(), receipt)

			// Remove from pool
			m.pool.Remove(tx.Hash())

			// Update sender nonce in state
			from, _ := types.Sender(m.signer, tx)
			currentNonce := m.stateManager.GetNonce(from)
			if tx.Nonce() >= currentNonce {
				m.stateManager.SetNonce(from, tx.Nonce()+1)
			}
		}
	}

	header.GasUsed = usedGas

	// Create block with trie hasher
	hasher := trie.NewStackTrie(nil)
	block := types.NewBlock(header, successful, nil, receipts, hasher)

	// Add to chain
	if err := m.chain.AddBlock(block); err != nil {
		return nil, err
	}

	return block, nil
}

// executeTx executes a single transaction and returns its receipt.
func (m *SimpleMiner) executeTx(tx *types.Transaction, header *types.Header, cumulativeGas uint64) *types.Receipt {
	from, err := types.Sender(m.signer, tx)
	if err != nil {
		return nil
	}

	// Check balance
	balance := m.stateManager.GetBalance(from)
	cost := tx.Cost()
	if balance.Cmp(cost) < 0 {
		return nil
	}

	// Deduct cost from sender
	newBalance := new(big.Int).Sub(balance, cost)
	m.stateManager.SetBalance(from, newBalance)

	// Add value to recipient
	if tx.To() != nil {
		toBalance := m.stateManager.GetBalance(*tx.To())
		newToBalance := new(big.Int).Add(toBalance, tx.Value())
		m.stateManager.SetBalance(*tx.To(), newToBalance)
	}

	gasUsed := uint64(21000) // Simple transfer

	// Create receipt
	receipt := &types.Receipt{
		Type:              tx.Type(),
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: cumulativeGas + gasUsed,
		TxHash:            tx.Hash(),
		GasUsed:           gasUsed,
		BlockNumber:       header.Number,
		BlockHash:         common.Hash{}, // Will be set after block creation
		TransactionIndex:  0,
	}

	return receipt
}

// Mode returns the current mining mode.
func (m *SimpleMiner) Mode() MiningMode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

// SetMode sets the mining mode.
func (m *SimpleMiner) SetMode(mode MiningMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mode = mode
	return nil
}

// SetInterval sets the interval for interval mining.
func (m *SimpleMiner) SetInterval(d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interval = d
	return nil
}

// Interval returns the current interval.
func (m *SimpleMiner) Interval() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.interval
}

// Start starts the miner (for interval mode).
func (m *SimpleMiner) Start() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return ErrAlreadyRunning
	}
	m.running = true
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	go m.runIntervalMining()
	return nil
}

// Stop stops the miner.
func (m *SimpleMiner) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return ErrNotRunning
	}
	close(m.stopCh)
	m.running = false
	m.mu.Unlock()
	return nil
}

// runIntervalMining runs the interval mining loop.
func (m *SimpleMiner) runIntervalMining() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.MineBlock()
		}
	}
}

// SetGasLimit sets the gas limit for new blocks.
func (m *SimpleMiner) SetGasLimit(gasLimit uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gasLimit = gasLimit
}
