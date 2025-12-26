// Package fork provides functionality for forking from remote Ethereum nodes.
package fork

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

// Common errors.
var (
	ErrNoForkURL    = errors.New("no fork URL configured")
	ErrForkFailed   = errors.New("failed to fetch from fork")
	ErrInvalidBlock = errors.New("invalid block number")
	ErrNotConnected = errors.New("not connected to fork")
)

// RPCClient is an interface for making JSON-RPC calls.
type RPCClient interface {
	Call(ctx context.Context, result interface{}, method string, args ...interface{}) error
	Close()
}

// Config holds fork configuration.
type Config struct {
	URL         string   // RPC URL to fork from
	BlockNumber *big.Int // Block number to fork at (nil for latest)
	ChainID     *big.Int // Chain ID (fetched from remote if nil)
}

// Provider manages forking from a remote node.
type Provider struct {
	config      *Config
	client      RPCClient
	blockNumber *big.Int
	chainID     *big.Int

	// State cache
	balances map[common.Address]*big.Int
	nonces   map[common.Address]uint64
	codes    map[common.Address][]byte
	storage  map[common.Address]map[common.Hash]common.Hash

	connected bool
	mu        sync.RWMutex
}

// NewProvider creates a new fork provider.
func NewProvider(config *Config) *Provider {
	return &Provider{
		config:   config,
		balances: make(map[common.Address]*big.Int),
		nonces:   make(map[common.Address]uint64),
		codes:    make(map[common.Address][]byte),
		storage:  make(map[common.Address]map[common.Hash]common.Hash),
	}
}

// SetClient sets the RPC client.
func (p *Provider) SetClient(client RPCClient) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.client = client
}

// Connect connects to the fork URL and fetches initial data.
func (p *Provider) Connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.config == nil || p.config.URL == "" {
		return ErrNoForkURL
	}

	if p.client == nil {
		return ErrNotConnected
	}

	// Fetch chain ID if not specified
	if p.config.ChainID == nil {
		var chainIDHex string
		if err := p.client.Call(ctx, &chainIDHex, "eth_chainId"); err != nil {
			return fmt.Errorf("failed to fetch chain ID: %w", err)
		}
		chainID, err := hexutil.DecodeBig(chainIDHex)
		if err != nil {
			return fmt.Errorf("invalid chain ID: %w", err)
		}
		p.chainID = chainID
	} else {
		p.chainID = p.config.ChainID
	}

	// Fetch block number if not specified
	if p.config.BlockNumber == nil {
		var blockNumHex string
		if err := p.client.Call(ctx, &blockNumHex, "eth_blockNumber"); err != nil {
			return fmt.Errorf("failed to fetch block number: %w", err)
		}
		blockNum, err := hexutil.DecodeBig(blockNumHex)
		if err != nil {
			return fmt.Errorf("invalid block number: %w", err)
		}
		p.blockNumber = blockNum
	} else {
		p.blockNumber = p.config.BlockNumber
	}

	p.connected = true
	return nil
}

// Disconnect closes the connection to the fork.
func (p *Provider) Disconnect() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client != nil {
		p.client.Close()
		p.client = nil
	}
	p.connected = false
}

// IsConnected returns whether the provider is connected.
func (p *Provider) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.connected
}

// ChainID returns the chain ID.
func (p *Provider) ChainID() *big.Int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.chainID == nil {
		return nil
	}
	return new(big.Int).Set(p.chainID)
}

// BlockNumber returns the fork block number.
func (p *Provider) BlockNumber() *big.Int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.blockNumber == nil {
		return nil
	}
	return new(big.Int).Set(p.blockNumber)
}

// GetBalance fetches the balance for an address from the cache or remote.
func (p *Provider) GetBalance(ctx context.Context, addr common.Address) (*big.Int, error) {
	p.mu.RLock()
	if balance, exists := p.balances[addr]; exists {
		p.mu.RUnlock()
		return new(big.Int).Set(balance), nil
	}
	p.mu.RUnlock()

	// Fetch from remote
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if balance, exists := p.balances[addr]; exists {
		return new(big.Int).Set(balance), nil
	}

	if !p.connected || p.client == nil {
		return big.NewInt(0), nil
	}

	blockTag := hexutil.EncodeBig(p.blockNumber)
	var balanceHex string
	if err := p.client.Call(ctx, &balanceHex, "eth_getBalance", addr.Hex(), blockTag); err != nil {
		return nil, fmt.Errorf("failed to fetch balance: %w", err)
	}

	balance, err := hexutil.DecodeBig(balanceHex)
	if err != nil {
		return nil, fmt.Errorf("invalid balance: %w", err)
	}

	p.balances[addr] = balance
	return new(big.Int).Set(balance), nil
}

// GetNonce fetches the nonce for an address from the cache or remote.
func (p *Provider) GetNonce(ctx context.Context, addr common.Address) (uint64, error) {
	p.mu.RLock()
	if nonce, exists := p.nonces[addr]; exists {
		p.mu.RUnlock()
		return nonce, nil
	}
	p.mu.RUnlock()

	// Fetch from remote
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if nonce, exists := p.nonces[addr]; exists {
		return nonce, nil
	}

	if !p.connected || p.client == nil {
		return 0, nil
	}

	blockTag := hexutil.EncodeBig(p.blockNumber)
	var nonceHex string
	if err := p.client.Call(ctx, &nonceHex, "eth_getTransactionCount", addr.Hex(), blockTag); err != nil {
		return 0, fmt.Errorf("failed to fetch nonce: %w", err)
	}

	nonce, err := hexutil.DecodeUint64(nonceHex)
	if err != nil {
		return 0, fmt.Errorf("invalid nonce: %w", err)
	}

	p.nonces[addr] = nonce
	return nonce, nil
}

// GetCode fetches the code for an address from the cache or remote.
func (p *Provider) GetCode(ctx context.Context, addr common.Address) ([]byte, error) {
	p.mu.RLock()
	if code, exists := p.codes[addr]; exists {
		p.mu.RUnlock()
		return code, nil
	}
	p.mu.RUnlock()

	// Fetch from remote
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if code, exists := p.codes[addr]; exists {
		return code, nil
	}

	if !p.connected || p.client == nil {
		return nil, nil
	}

	blockTag := hexutil.EncodeBig(p.blockNumber)
	var codeHex string
	if err := p.client.Call(ctx, &codeHex, "eth_getCode", addr.Hex(), blockTag); err != nil {
		return nil, fmt.Errorf("failed to fetch code: %w", err)
	}

	code := common.FromHex(codeHex)
	p.codes[addr] = code
	return code, nil
}

// GetStorageAt fetches the storage value for an address and slot from cache or remote.
func (p *Provider) GetStorageAt(ctx context.Context, addr common.Address, slot common.Hash) (common.Hash, error) {
	p.mu.RLock()
	if addrStorage, exists := p.storage[addr]; exists {
		if value, exists := addrStorage[slot]; exists {
			p.mu.RUnlock()
			return value, nil
		}
	}
	p.mu.RUnlock()

	// Fetch from remote
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if addrStorage, exists := p.storage[addr]; exists {
		if value, exists := addrStorage[slot]; exists {
			return value, nil
		}
	}

	if !p.connected || p.client == nil {
		return common.Hash{}, nil
	}

	blockTag := hexutil.EncodeBig(p.blockNumber)
	var valueHex string
	if err := p.client.Call(ctx, &valueHex, "eth_getStorageAt", addr.Hex(), slot.Hex(), blockTag); err != nil {
		return common.Hash{}, fmt.Errorf("failed to fetch storage: %w", err)
	}

	value := common.HexToHash(valueHex)

	if p.storage[addr] == nil {
		p.storage[addr] = make(map[common.Hash]common.Hash)
	}
	p.storage[addr][slot] = value

	return value, nil
}

// GetBlock fetches a block by number from the remote.
func (p *Provider) GetBlock(ctx context.Context, blockNum *big.Int) (*types.Block, error) {
	if !p.IsConnected() || p.client == nil {
		return nil, ErrNotConnected
	}

	blockTag := hexutil.EncodeBig(blockNum)
	var result json.RawMessage
	if err := p.client.Call(ctx, &result, "eth_getBlockByNumber", blockTag, true); err != nil {
		return nil, fmt.Errorf("failed to fetch block: %w", err)
	}

	if result == nil || string(result) == "null" {
		return nil, ErrInvalidBlock
	}

	// Note: Full block parsing would require more complex handling
	// This is a simplified version that returns nil for now
	return nil, nil
}

// ClearCache clears the state cache.
func (p *Provider) ClearCache() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.balances = make(map[common.Address]*big.Int)
	p.nonces = make(map[common.Address]uint64)
	p.codes = make(map[common.Address][]byte)
	p.storage = make(map[common.Address]map[common.Hash]common.Hash)
}

// CacheSize returns the number of cached entries.
func (p *Provider) CacheSize() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return len(p.balances) + len(p.nonces) + len(p.codes) + len(p.storage)
}

// SetCachedBalance sets a cached balance value.
func (p *Provider) SetCachedBalance(addr common.Address, balance *big.Int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.balances[addr] = new(big.Int).Set(balance)
}

// SetCachedNonce sets a cached nonce value.
func (p *Provider) SetCachedNonce(addr common.Address, nonce uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nonces[addr] = nonce
}

// SetCachedCode sets a cached code value.
func (p *Provider) SetCachedCode(addr common.Address, code []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.codes[addr] = code
}

// SetCachedStorage sets a cached storage value.
func (p *Provider) SetCachedStorage(addr common.Address, slot, value common.Hash) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.storage[addr] == nil {
		p.storage[addr] = make(map[common.Hash]common.Hash)
	}
	p.storage[addr][slot] = value
}

// URL returns the fork URL.
func (p *Provider) URL() string {
	if p.config == nil {
		return ""
	}
	return p.config.URL
}
