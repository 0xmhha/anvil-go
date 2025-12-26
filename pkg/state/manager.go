// Package state provides state management for the simulator.
package state

import (
	"encoding/json"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// Reader provides read-only state access.
// Follows Interface Segregation Principle (ISP).
type Reader interface {
	GetBalance(addr common.Address) *big.Int
	GetNonce(addr common.Address) uint64
	GetCode(addr common.Address) []byte
	GetCodeHash(addr common.Address) common.Hash
	GetStorageAt(addr common.Address, slot common.Hash) common.Hash
	Exist(addr common.Address) bool
}

// Writer provides state modification.
// Follows Interface Segregation Principle (ISP).
type Writer interface {
	SetBalance(addr common.Address, balance *big.Int) error
	SetNonce(addr common.Address, nonce uint64) error
	SetCode(addr common.Address, code []byte) error
	SetStorageAt(addr common.Address, slot, value common.Hash) error
	CreateAccount(addr common.Address) error
	DeleteAccount(addr common.Address) error
}

// Manager combines read and write operations.
type Manager interface {
	Reader
	Writer
	Root() common.Hash
	Commit() (common.Hash, error)
	Copy() Manager
	Snapshot() int
	RevertToSnapshot(id int)
}

// accountState holds the state of a single account.
type accountState struct {
	Balance  *big.Int
	Nonce    uint64
	Code     []byte
	CodeHash common.Hash
	Storage  map[common.Hash]common.Hash
}

// copyAccountState creates a deep copy of an account state.
func (a *accountState) copy() *accountState {
	copied := &accountState{
		Nonce:    a.Nonce,
		CodeHash: a.CodeHash,
	}

	if a.Balance != nil {
		copied.Balance = new(big.Int).Set(a.Balance)
	}

	if a.Code != nil {
		copied.Code = make([]byte, len(a.Code))
		copy(copied.Code, a.Code)
	}

	if a.Storage != nil {
		copied.Storage = make(map[common.Hash]common.Hash)
		for k, v := range a.Storage {
			copied.Storage[k] = v
		}
	}

	return copied
}

// snapshot holds a point-in-time state capture.
type snapshot struct {
	id       int
	accounts map[common.Address]*accountState
}

// InMemoryManager implements Manager using in-memory storage.
type InMemoryManager struct {
	accounts   map[common.Address]*accountState
	snapshots  []*snapshot
	nextSnapID int
	stateRoot  common.Hash
	mu         sync.RWMutex
}

// NewInMemoryManager creates a new in-memory state manager.
func NewInMemoryManager() *InMemoryManager {
	return &InMemoryManager{
		accounts:  make(map[common.Address]*accountState),
		snapshots: make([]*snapshot, 0),
		stateRoot: common.Hash{}, // Empty state root
	}
}

// getOrCreateAccount gets an existing account or creates a new one.
func (m *InMemoryManager) getOrCreateAccount(addr common.Address) *accountState {
	if acc, exists := m.accounts[addr]; exists {
		return acc
	}
	acc := &accountState{
		Balance: big.NewInt(0),
		Storage: make(map[common.Hash]common.Hash),
	}
	m.accounts[addr] = acc
	return acc
}

// GetBalance returns the balance of an account.
func (m *InMemoryManager) GetBalance(addr common.Address) *big.Int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if acc, exists := m.accounts[addr]; exists && acc.Balance != nil {
		return new(big.Int).Set(acc.Balance)
	}
	return big.NewInt(0)
}

// GetNonce returns the nonce of an account.
func (m *InMemoryManager) GetNonce(addr common.Address) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if acc, exists := m.accounts[addr]; exists {
		return acc.Nonce
	}
	return 0
}

// GetCode returns the code of an account.
func (m *InMemoryManager) GetCode(addr common.Address) []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if acc, exists := m.accounts[addr]; exists {
		return acc.Code
	}
	return nil
}

// GetCodeHash returns the code hash of an account.
func (m *InMemoryManager) GetCodeHash(addr common.Address) common.Hash {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if acc, exists := m.accounts[addr]; exists {
		return acc.CodeHash
	}
	return common.Hash{}
}

// GetStorageAt returns the storage value at a slot.
func (m *InMemoryManager) GetStorageAt(addr common.Address, slot common.Hash) common.Hash {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if acc, exists := m.accounts[addr]; exists && acc.Storage != nil {
		if value, ok := acc.Storage[slot]; ok {
			return value
		}
	}
	return common.Hash{}
}

// Exist returns true if the account exists.
func (m *InMemoryManager) Exist(addr common.Address) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.accounts[addr]
	return exists
}

// SetBalance sets the balance of an account.
func (m *InMemoryManager) SetBalance(addr common.Address, balance *big.Int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	acc := m.getOrCreateAccount(addr)
	acc.Balance = new(big.Int).Set(balance)
	return nil
}

// SetNonce sets the nonce of an account.
func (m *InMemoryManager) SetNonce(addr common.Address, nonce uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	acc := m.getOrCreateAccount(addr)
	acc.Nonce = nonce
	return nil
}

// SetCode sets the code of an account.
func (m *InMemoryManager) SetCode(addr common.Address, code []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	acc := m.getOrCreateAccount(addr)
	acc.Code = make([]byte, len(code))
	copy(acc.Code, code)
	acc.CodeHash = crypto.Keccak256Hash(code)
	return nil
}

// SetStorageAt sets the storage value at a slot.
func (m *InMemoryManager) SetStorageAt(addr common.Address, slot, value common.Hash) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	acc := m.getOrCreateAccount(addr)
	if acc.Storage == nil {
		acc.Storage = make(map[common.Hash]common.Hash)
	}
	acc.Storage[slot] = value
	return nil
}

// CreateAccount creates a new account.
func (m *InMemoryManager) CreateAccount(addr common.Address) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.accounts[addr] = &accountState{
		Balance: big.NewInt(0),
		Storage: make(map[common.Hash]common.Hash),
	}
	return nil
}

// DeleteAccount removes an account.
func (m *InMemoryManager) DeleteAccount(addr common.Address) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.accounts, addr)
	return nil
}

// Root returns the current state root.
func (m *InMemoryManager) Root() common.Hash {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.stateRoot
}

// Commit commits pending changes and returns the new root.
func (m *InMemoryManager) Commit() (common.Hash, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Calculate a simple state root by hashing all account data
	// In production, this would use a Merkle Patricia Trie
	m.stateRoot = m.calculateRoot()
	return m.stateRoot, nil
}

// calculateRoot calculates a simple state root.
func (m *InMemoryManager) calculateRoot() common.Hash {
	// Simple hash of all account addresses for now
	// Real implementation would use MPT
	var data []byte
	for addr, acc := range m.accounts {
		data = append(data, addr.Bytes()...)
		if acc.Balance != nil {
			data = append(data, acc.Balance.Bytes()...)
		}
		data = append(data, byte(acc.Nonce>>56), byte(acc.Nonce>>48),
			byte(acc.Nonce>>40), byte(acc.Nonce>>32),
			byte(acc.Nonce>>24), byte(acc.Nonce>>16),
			byte(acc.Nonce>>8), byte(acc.Nonce))
		data = append(data, acc.CodeHash.Bytes()...)
	}

	if len(data) == 0 {
		return common.Hash{}
	}
	return crypto.Keccak256Hash(data)
}

// Copy creates a deep copy of the state.
func (m *InMemoryManager) Copy() Manager {
	m.mu.RLock()
	defer m.mu.RUnlock()

	copied := &InMemoryManager{
		accounts:   make(map[common.Address]*accountState),
		snapshots:  make([]*snapshot, 0),
		nextSnapID: 0,
		stateRoot:  m.stateRoot,
	}

	for addr, acc := range m.accounts {
		copied.accounts[addr] = acc.copy()
	}

	return copied
}

// Snapshot creates an in-memory snapshot for revert.
func (m *InMemoryManager) Snapshot() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Copy current state
	accounts := make(map[common.Address]*accountState)
	for addr, acc := range m.accounts {
		accounts[addr] = acc.copy()
	}

	snap := &snapshot{
		id:       m.nextSnapID,
		accounts: accounts,
	}

	m.snapshots = append(m.snapshots, snap)
	m.nextSnapID++

	return snap.id
}

// RevertToSnapshot reverts to a previous snapshot.
func (m *InMemoryManager) RevertToSnapshot(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find the snapshot
	var snapIdx int = -1
	for i, snap := range m.snapshots {
		if snap.id == id {
			snapIdx = i
			break
		}
	}

	if snapIdx == -1 {
		return // Snapshot not found
	}

	// Restore state from snapshot
	snap := m.snapshots[snapIdx]
	m.accounts = make(map[common.Address]*accountState)
	for addr, acc := range snap.accounts {
		m.accounts[addr] = acc.copy()
	}

	// Remove this and all subsequent snapshots
	m.snapshots = m.snapshots[:snapIdx]
}

// AccountDump represents an account in the state dump.
type AccountDump struct {
	Balance string            `json:"balance"`
	Nonce   uint64            `json:"nonce"`
	Code    string            `json:"code,omitempty"`
	Storage map[string]string `json:"storage,omitempty"`
}

// StateDump represents a complete state dump.
type StateDump struct {
	Accounts map[string]AccountDump `json:"accounts"`
}

// Dump exports the current state as a serializable structure.
func (m *InMemoryManager) Dump() *StateDump {
	m.mu.RLock()
	defer m.mu.RUnlock()

	dump := &StateDump{
		Accounts: make(map[string]AccountDump),
	}

	for addr, acc := range m.accounts {
		accountDump := AccountDump{
			Balance: "0x0",
			Nonce:   acc.Nonce,
		}

		if acc.Balance != nil {
			accountDump.Balance = hexutil.EncodeBig(acc.Balance)
		}

		if len(acc.Code) > 0 {
			accountDump.Code = hexutil.Encode(acc.Code)
		}

		if len(acc.Storage) > 0 {
			accountDump.Storage = make(map[string]string)
			for slot, value := range acc.Storage {
				if value != (common.Hash{}) {
					accountDump.Storage[slot.Hex()] = value.Hex()
				}
			}
		}

		dump.Accounts[addr.Hex()] = accountDump
	}

	return dump
}

// DumpJSON exports the current state as JSON.
func (m *InMemoryManager) DumpJSON() ([]byte, error) {
	dump := m.Dump()
	return json.Marshal(dump)
}

// Load imports state from a dump structure.
func (m *InMemoryManager) Load(dump *StateDump) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if dump == nil || dump.Accounts == nil {
		return nil
	}

	for addrHex, accDump := range dump.Accounts {
		addr := common.HexToAddress(addrHex)

		acc := &accountState{
			Nonce:   accDump.Nonce,
			Storage: make(map[common.Hash]common.Hash),
		}

		// Parse balance
		if accDump.Balance != "" {
			balance, err := hexutil.DecodeBig(accDump.Balance)
			if err != nil {
				return err
			}
			acc.Balance = balance
		} else {
			acc.Balance = big.NewInt(0)
		}

		// Parse code
		if accDump.Code != "" {
			code, err := hexutil.Decode(accDump.Code)
			if err != nil {
				return err
			}
			acc.Code = code
			acc.CodeHash = crypto.Keccak256Hash(code)
		}

		// Parse storage
		for slotHex, valueHex := range accDump.Storage {
			slot := common.HexToHash(slotHex)
			value := common.HexToHash(valueHex)
			acc.Storage[slot] = value
		}

		m.accounts[addr] = acc
	}

	return nil
}

// LoadJSON imports state from JSON.
func (m *InMemoryManager) LoadJSON(data []byte) error {
	var dump StateDump
	if err := json.Unmarshal(data, &dump); err != nil {
		return err
	}
	return m.Load(&dump)
}

// Clear removes all accounts from the state.
func (m *InMemoryManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.accounts = make(map[common.Address]*accountState)
	m.snapshots = make([]*snapshot, 0)
	m.nextSnapID = 0
	m.stateRoot = common.Hash{}
}

// AccountCount returns the number of accounts in the state.
func (m *InMemoryManager) AccountCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.accounts)
}
