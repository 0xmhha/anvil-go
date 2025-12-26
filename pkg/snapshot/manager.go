// Package snapshot provides snapshot management for the simulator.
package snapshot

import (
	"sync"

	"github.com/stable-net/anvil-go/pkg/blockchain"
	"github.com/stable-net/anvil-go/pkg/state"
	"github.com/stable-net/anvil-go/pkg/txpool"
)

// Snapshot holds a point-in-time state capture.
type Snapshot struct {
	ID          uint64
	StateSnapID int
	BlockNumber uint64
}

// Manager manages state snapshots.
type Manager struct {
	stateManager *state.InMemoryManager
	chain        *blockchain.Chain
	pool         *txpool.InMemoryPool

	snapshots map[uint64]*Snapshot
	nextID    uint64

	mu sync.RWMutex
}

// NewManager creates a new snapshot manager.
func NewManager(sm *state.InMemoryManager, chain *blockchain.Chain, pool *txpool.InMemoryPool) *Manager {
	return &Manager{
		stateManager: sm,
		chain:        chain,
		pool:         pool,
		snapshots:    make(map[uint64]*Snapshot),
		nextID:       1,
	}
}

// Snapshot creates a new snapshot and returns its ID.
func (m *Manager) Snapshot() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Take state snapshot
	stateSnapID := m.stateManager.Snapshot()

	// Record current block number
	blockNumber := m.chain.BlockNumber()

	snap := &Snapshot{
		ID:          m.nextID,
		StateSnapID: stateSnapID,
		BlockNumber: blockNumber,
	}

	m.snapshots[m.nextID] = snap
	m.nextID++

	return snap.ID
}

// Revert reverts to a previous snapshot.
func (m *Manager) Revert(id uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	snap, exists := m.snapshots[id]
	if !exists {
		return false
	}

	// Revert state
	m.stateManager.RevertToSnapshot(snap.StateSnapID)

	// Clear transaction pool
	m.pool.Clear()

	// Remove all snapshots with ID >= this one
	for snapID := range m.snapshots {
		if snapID >= id {
			delete(m.snapshots, snapID)
		}
	}

	return true
}

// Delete removes a snapshot.
func (m *Manager) Delete(id uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.snapshots[id]; !exists {
		return false
	}

	delete(m.snapshots, id)
	return true
}

// List returns all snapshot IDs.
func (m *Manager) List() []uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]uint64, 0, len(m.snapshots))
	for id := range m.snapshots {
		ids = append(ids, id)
	}
	return ids
}

// Clear removes all snapshots.
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.snapshots = make(map[uint64]*Snapshot)
}

// Count returns the number of snapshots.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.snapshots)
}

// Get retrieves a snapshot by ID.
func (m *Manager) Get(id uint64) (*Snapshot, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	snap, exists := m.snapshots[id]
	return snap, exists
}
