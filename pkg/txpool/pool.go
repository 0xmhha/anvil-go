// Package txpool provides transaction pool management for the simulator.
package txpool

import (
	"errors"
	"math/big"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stable-net/anvil-go/pkg/state"
)

// Common errors.
var (
	ErrNonceTooLow       = errors.New("nonce too low")
	ErrNonceTooHigh      = errors.New("nonce too high")
	ErrInsufficientFunds = errors.New("insufficient funds")
	ErrGasLimitExceeded  = errors.New("gas limit exceeded")
	ErrTxAlreadyKnown    = errors.New("transaction already known")
	ErrTxNotFound        = errors.New("transaction not found")
	ErrInvalidSender     = errors.New("invalid sender")
)

// Pool manages pending transactions.
type Pool interface {
	Add(tx *types.Transaction) error
	AddWithImpersonation(tx *types.Transaction, from common.Address) error
	Remove(hash common.Hash) error
	Get(hash common.Hash) *types.Transaction
	Pending() []*types.Transaction
	PendingFrom(addr common.Address) []*types.Transaction
	PendingNonce(addr common.Address) uint64
	Count() int
	Clear()
	EnableImpersonation(addr common.Address)
	DisableImpersonation(addr common.Address)
	IsImpersonating(addr common.Address) bool
	SetAutoImpersonate(enabled bool)
	IsAutoImpersonate() bool
}

// txEntry holds a transaction with its metadata.
type txEntry struct {
	tx   *types.Transaction
	from common.Address
}

// InMemoryPool implements Pool with in-memory storage.
type InMemoryPool struct {
	stateManager    state.Reader
	chainID         *big.Int
	signer          types.Signer
	pending         map[common.Hash]*txEntry
	byAddress       map[common.Address][]*txEntry
	impersonated    map[common.Address]bool
	autoImpersonate bool
	pendingNonces   map[common.Address]uint64 // Next expected nonce per address
	mu              sync.RWMutex
}

// NewInMemoryPool creates a new in-memory transaction pool.
func NewInMemoryPool(stateManager state.Reader, chainID *big.Int) *InMemoryPool {
	return &InMemoryPool{
		stateManager:  stateManager,
		chainID:       chainID,
		signer:        types.NewEIP155Signer(chainID),
		pending:       make(map[common.Hash]*txEntry),
		byAddress:     make(map[common.Address][]*txEntry),
		impersonated:  make(map[common.Address]bool),
		pendingNonces: make(map[common.Address]uint64),
	}
}

// Add adds a signed transaction to the pool after validation.
func (p *InMemoryPool) Add(tx *types.Transaction) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Extract sender from signature
	from, err := types.Sender(p.signer, tx)
	if err != nil {
		return ErrInvalidSender
	}

	return p.addLocked(tx, from)
}

// AddWithImpersonation adds a transaction with a specified sender.
func (p *InMemoryPool) AddWithImpersonation(tx *types.Transaction, from common.Address) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.addLocked(tx, from)
}

// addLocked adds a transaction to the pool (caller must hold lock).
func (p *InMemoryPool) addLocked(tx *types.Transaction, from common.Address) error {
	// Check if tx already exists
	if _, exists := p.pending[tx.Hash()]; exists {
		return ErrTxAlreadyKnown
	}

	// Validate transaction
	if err := p.validateTx(tx, from); err != nil {
		return err
	}

	// Add to pool
	entry := &txEntry{tx: tx, from: from}
	p.pending[tx.Hash()] = entry
	p.byAddress[from] = append(p.byAddress[from], entry)

	// Update pending nonce
	nextNonce := tx.Nonce() + 1
	if nextNonce > p.pendingNonces[from] {
		p.pendingNonces[from] = nextNonce
	}

	return nil
}

// validateTx validates a transaction before adding to pool.
func (p *InMemoryPool) validateTx(tx *types.Transaction, from common.Address) error {
	// Get current state
	currentNonce := p.stateManager.GetNonce(from)
	balance := p.stateManager.GetBalance(from)

	// Check nonce
	txNonce := tx.Nonce()

	// Get pending nonce (including pending txs)
	pendingNonce := currentNonce
	if pn, ok := p.pendingNonces[from]; ok && pn > pendingNonce {
		pendingNonce = pn
	}

	if txNonce < currentNonce {
		return ErrNonceTooLow
	}

	// Allow nonce to be current nonce or pending nonce (for sequential txs)
	if txNonce > pendingNonce {
		return ErrNonceTooHigh
	}

	// Check balance
	cost := tx.Cost() // value + gas * gasPrice
	if balance.Cmp(cost) < 0 {
		return ErrInsufficientFunds
	}

	return nil
}

// Remove removes a transaction from the pool.
func (p *InMemoryPool) Remove(hash common.Hash) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	entry, exists := p.pending[hash]
	if !exists {
		return ErrTxNotFound
	}

	// Remove from pending
	delete(p.pending, hash)

	// Remove from byAddress
	txs := p.byAddress[entry.from]
	for i, e := range txs {
		if e.tx.Hash() == hash {
			p.byAddress[entry.from] = append(txs[:i], txs[i+1:]...)
			break
		}
	}

	// Clean up empty address entry
	if len(p.byAddress[entry.from]) == 0 {
		delete(p.byAddress, entry.from)
	}

	return nil
}

// Get retrieves a transaction by hash.
func (p *InMemoryPool) Get(hash common.Hash) *types.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if entry, exists := p.pending[hash]; exists {
		return entry.tx
	}
	return nil
}

// Pending returns all pending transactions ordered by nonce.
func (p *InMemoryPool) Pending() []*types.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var txs []*types.Transaction
	for _, entry := range p.pending {
		txs = append(txs, entry.tx)
	}

	// Sort by sender address, then by nonce
	sort.Slice(txs, func(i, j int) bool {
		fromI, _ := types.Sender(p.signer, txs[i])
		fromJ, _ := types.Sender(p.signer, txs[j])

		if fromI == fromJ {
			return txs[i].Nonce() < txs[j].Nonce()
		}
		return fromI.Hex() < fromJ.Hex()
	})

	return txs
}

// PendingFrom returns pending transactions from a specific address.
func (p *InMemoryPool) PendingFrom(addr common.Address) []*types.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entries := p.byAddress[addr]
	txs := make([]*types.Transaction, len(entries))
	for i, entry := range entries {
		txs[i] = entry.tx
	}

	// Sort by nonce
	sort.Slice(txs, func(i, j int) bool {
		return txs[i].Nonce() < txs[j].Nonce()
	})

	return txs
}

// PendingNonce returns the next expected nonce for an address.
func (p *InMemoryPool) PendingNonce(addr common.Address) uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if nonce, ok := p.pendingNonces[addr]; ok {
		return nonce
	}
	return p.stateManager.GetNonce(addr)
}

// Count returns the number of pending transactions.
func (p *InMemoryPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return len(p.pending)
}

// Clear removes all transactions from the pool.
func (p *InMemoryPool) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.pending = make(map[common.Hash]*txEntry)
	p.byAddress = make(map[common.Address][]*txEntry)
	p.pendingNonces = make(map[common.Address]uint64)
}

// EnableImpersonation enables impersonation for an address.
func (p *InMemoryPool) EnableImpersonation(addr common.Address) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.impersonated[addr] = true
}

// DisableImpersonation disables impersonation for an address.
func (p *InMemoryPool) DisableImpersonation(addr common.Address) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.impersonated, addr)
}

// IsImpersonating returns true if the address is being impersonated.
func (p *InMemoryPool) IsImpersonating(addr common.Address) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.impersonated[addr] || p.autoImpersonate
}

// SetAutoImpersonate enables or disables auto-impersonation for all addresses.
func (p *InMemoryPool) SetAutoImpersonate(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.autoImpersonate = enabled
}

// IsAutoImpersonate returns true if auto-impersonation is enabled.
func (p *InMemoryPool) IsAutoImpersonate() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.autoImpersonate
}

// RemoveByAddress removes all transactions from an address.
func (p *InMemoryPool) RemoveByAddress(addr common.Address) {
	p.mu.Lock()
	defer p.mu.Unlock()

	entries := p.byAddress[addr]
	for _, entry := range entries {
		delete(p.pending, entry.tx.Hash())
	}
	delete(p.byAddress, addr)
	delete(p.pendingNonces, addr)
}

// UpdatePendingNonce updates the pending nonce after a transaction is mined.
func (p *InMemoryPool) UpdatePendingNonce(addr common.Address, nonce uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Remove transactions with nonce less than the new nonce
	entries := p.byAddress[addr]
	remaining := make([]*txEntry, 0)

	for _, entry := range entries {
		if entry.tx.Nonce() < nonce {
			delete(p.pending, entry.tx.Hash())
		} else {
			remaining = append(remaining, entry)
		}
	}

	if len(remaining) > 0 {
		p.byAddress[addr] = remaining
	} else {
		delete(p.byAddress, addr)
	}

	// Update pending nonce
	if nonce > p.pendingNonces[addr] {
		p.pendingNonces[addr] = nonce
	}
}
