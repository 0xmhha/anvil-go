// Package benchmark provides performance benchmarks for anvil-go.
package benchmark

import (
	"bytes"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stable-net/anvil-go/pkg/blockchain"
	"github.com/stable-net/anvil-go/pkg/miner"
	"github.com/stable-net/anvil-go/pkg/rpc"
	"github.com/stable-net/anvil-go/pkg/state"
	"github.com/stable-net/anvil-go/pkg/txpool"
)

type benchBackend struct {
	server       *rpc.Server
	chain        *blockchain.Chain
	pool         *txpool.InMemoryPool
	stateManager *state.InMemoryManager
	miner        *miner.SimpleMiner
	chainID      *big.Int
}

func setupBenchBackend(b *testing.B) *benchBackend {
	chainID := big.NewInt(31337)
	sm := state.NewInMemoryManager()
	chain := blockchain.NewChain(chainID)
	pool := txpool.NewInMemoryPool(sm, chainID)

	genesis := createGenesisBlock()
	if err := chain.SetGenesis(genesis); err != nil {
		b.Fatal(err)
	}

	m := miner.NewSimpleMiner(chain, pool, sm, chainID)
	server := rpc.NewServer(chain, pool, sm, m, chainID)

	return &benchBackend{
		server:       server,
		chain:        chain,
		pool:         pool,
		stateManager: sm,
		miner:        m,
		chainID:      chainID,
	}
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

func makeRPCRequest(server *rpc.Server, method string, params interface{}) *httptest.ResponseRecorder {
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	return w
}

// BenchmarkRPC_eth_chainId benchmarks eth_chainId requests.
func BenchmarkRPC_eth_chainId(b *testing.B) {
	backend := setupBenchBackend(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		makeRPCRequest(backend.server, "eth_chainId", []interface{}{})
	}
}

// BenchmarkRPC_eth_blockNumber benchmarks eth_blockNumber requests.
func BenchmarkRPC_eth_blockNumber(b *testing.B) {
	backend := setupBenchBackend(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		makeRPCRequest(backend.server, "eth_blockNumber", []interface{}{})
	}
}

// BenchmarkRPC_eth_getBalance benchmarks eth_getBalance requests.
func BenchmarkRPC_eth_getBalance(b *testing.B) {
	backend := setupBenchBackend(b)
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Setup balance
	backend.stateManager.SetBalance(addr, big.NewInt(1000))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		makeRPCRequest(backend.server, "eth_getBalance", []interface{}{addr.Hex(), "latest"})
	}
}

// BenchmarkRPC_eth_getCode benchmarks eth_getCode requests.
func BenchmarkRPC_eth_getCode(b *testing.B) {
	backend := setupBenchBackend(b)
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Setup code
	code := make([]byte, 1000) // 1KB code
	for i := range code {
		code[i] = byte(i % 256)
	}
	backend.stateManager.SetCode(addr, code)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		makeRPCRequest(backend.server, "eth_getCode", []interface{}{addr.Hex(), "latest"})
	}
}

// BenchmarkRPC_eth_getStorageAt benchmarks eth_getStorageAt requests.
func BenchmarkRPC_eth_getStorageAt(b *testing.B) {
	backend := setupBenchBackend(b)
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	slot := common.HexToHash("0x01")
	value := common.HexToHash("0x42")

	// Setup storage
	backend.stateManager.SetStorageAt(addr, slot, value)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		makeRPCRequest(backend.server, "eth_getStorageAt", []interface{}{addr.Hex(), slot.Hex(), "latest"})
	}
}

// BenchmarkRPC_anvil_setBalance benchmarks anvil_setBalance requests.
func BenchmarkRPC_anvil_setBalance(b *testing.B) {
	backend := setupBenchBackend(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr := common.BigToAddress(big.NewInt(int64(i)))
		makeRPCRequest(backend.server, "anvil_setBalance", []interface{}{addr.Hex(), "0x1000"})
	}
}

// BenchmarkRPC_anvil_mine benchmarks anvil_mine requests.
func BenchmarkRPC_anvil_mine(b *testing.B) {
	backend := setupBenchBackend(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		makeRPCRequest(backend.server, "anvil_mine", []interface{}{"0x1"})
	}
}

// BenchmarkRPC_anvil_snapshot benchmarks anvil_snapshot requests.
func BenchmarkRPC_anvil_snapshot(b *testing.B) {
	backend := setupBenchBackend(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		makeRPCRequest(backend.server, "anvil_snapshot", []interface{}{})
	}
}

// BenchmarkState_SetBalance benchmarks direct state SetBalance calls.
func BenchmarkState_SetBalance(b *testing.B) {
	sm := state.NewInMemoryManager()
	balance := big.NewInt(1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr := common.BigToAddress(big.NewInt(int64(i)))
		sm.SetBalance(addr, balance)
	}
}

// BenchmarkState_GetBalance benchmarks direct state GetBalance calls.
func BenchmarkState_GetBalance(b *testing.B) {
	sm := state.NewInMemoryManager()
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	sm.SetBalance(addr, big.NewInt(1000))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.GetBalance(addr)
	}
}

// BenchmarkState_SetStorageAt benchmarks direct state SetStorageAt calls.
func BenchmarkState_SetStorageAt(b *testing.B) {
	sm := state.NewInMemoryManager()
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	value := common.HexToHash("0x42")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		slot := common.BigToHash(big.NewInt(int64(i)))
		sm.SetStorageAt(addr, slot, value)
	}
}

// BenchmarkState_GetStorageAt benchmarks direct state GetStorageAt calls.
func BenchmarkState_GetStorageAt(b *testing.B) {
	sm := state.NewInMemoryManager()
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	slot := common.HexToHash("0x01")
	sm.SetStorageAt(addr, slot, common.HexToHash("0x42"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.GetStorageAt(addr, slot)
	}
}

// BenchmarkState_Snapshot benchmarks state snapshot creation.
func BenchmarkState_Snapshot(b *testing.B) {
	sm := state.NewInMemoryManager()

	// Setup some state
	for i := 0; i < 100; i++ {
		addr := common.BigToAddress(big.NewInt(int64(i)))
		sm.SetBalance(addr, big.NewInt(1000))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.Snapshot()
	}
}

// BenchmarkState_Copy benchmarks state copy.
func BenchmarkState_Copy(b *testing.B) {
	sm := state.NewInMemoryManager()

	// Setup some state
	for i := 0; i < 100; i++ {
		addr := common.BigToAddress(big.NewInt(int64(i)))
		sm.SetBalance(addr, big.NewInt(1000))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.Copy()
	}
}

// BenchmarkState_Dump benchmarks state dump.
func BenchmarkState_Dump(b *testing.B) {
	sm := state.NewInMemoryManager()

	// Setup some state
	for i := 0; i < 100; i++ {
		addr := common.BigToAddress(big.NewInt(int64(i)))
		sm.SetBalance(addr, big.NewInt(1000))
		sm.SetNonce(addr, uint64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.Dump()
	}
}

// BenchmarkState_DumpJSON benchmarks state dump to JSON.
func BenchmarkState_DumpJSON(b *testing.B) {
	sm := state.NewInMemoryManager()

	// Setup some state
	for i := 0; i < 100; i++ {
		addr := common.BigToAddress(big.NewInt(int64(i)))
		sm.SetBalance(addr, big.NewInt(1000))
		sm.SetNonce(addr, uint64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.DumpJSON()
	}
}

// BenchmarkMiner_MineBlock benchmarks block mining.
func BenchmarkMiner_MineBlock(b *testing.B) {
	chainID := big.NewInt(31337)
	sm := state.NewInMemoryManager()
	chain := blockchain.NewChain(chainID)
	pool := txpool.NewInMemoryPool(sm, chainID)

	genesis := createGenesisBlock()
	chain.SetGenesis(genesis)

	m := miner.NewSimpleMiner(chain, pool, sm, chainID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.MineBlock()
	}
}

// BenchmarkChain_BlockByNumber benchmarks block retrieval by number.
func BenchmarkChain_BlockByNumber(b *testing.B) {
	chainID := big.NewInt(31337)
	sm := state.NewInMemoryManager()
	chain := blockchain.NewChain(chainID)
	pool := txpool.NewInMemoryPool(sm, chainID)

	genesis := createGenesisBlock()
	chain.SetGenesis(genesis)

	m := miner.NewSimpleMiner(chain, pool, sm, chainID)

	// Mine some blocks
	for i := 0; i < 100; i++ {
		m.MineBlock()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chain.BlockByNumber(uint64(i % 100))
	}
}

// BenchmarkRPC_eth_getBlockByNumber benchmarks eth_getBlockByNumber requests.
func BenchmarkRPC_eth_getBlockByNumber(b *testing.B) {
	backend := setupBenchBackend(b)

	// Mine some blocks
	for i := 0; i < 10; i++ {
		makeRPCRequest(backend.server, "anvil_mine", []interface{}{"0x1"})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blockNum := hexutil.EncodeUint64(uint64(i % 10))
		makeRPCRequest(backend.server, "eth_getBlockByNumber", []interface{}{blockNum, false})
	}
}

// BenchmarkValidator_AddValidator benchmarks adding validators.
func BenchmarkValidator_AddValidator(b *testing.B) {
	backend := setupBenchBackend(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr := common.BigToAddress(big.NewInt(int64(i)))
		operator := common.BigToAddress(big.NewInt(int64(i + 1000000)))
		makeRPCRequest(backend.server, "stablenet_addValidator", []interface{}{addr.Hex(), operator.Hex()})
	}
}

// BenchmarkValidator_GetProposer benchmarks getting proposer.
func BenchmarkValidator_GetProposer(b *testing.B) {
	backend := setupBenchBackend(b)

	// Add some validators
	for i := 0; i < 10; i++ {
		addr := common.BigToAddress(big.NewInt(int64(i)))
		operator := common.BigToAddress(big.NewInt(int64(i + 1000000)))
		makeRPCRequest(backend.server, "stablenet_addValidator", []interface{}{addr.Hex(), operator.Hex()})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blockNum := hexutil.EncodeUint64(uint64(i))
		makeRPCRequest(backend.server, "stablenet_getProposer", []interface{}{blockNum})
	}
}

// BenchmarkRPCParallel_eth_chainId benchmarks parallel eth_chainId requests.
func BenchmarkRPCParallel_eth_chainId(b *testing.B) {
	backend := setupBenchBackend(b)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			makeRPCRequest(backend.server, "eth_chainId", []interface{}{})
		}
	})
}

// BenchmarkRPCParallel_eth_getBalance benchmarks parallel eth_getBalance requests.
func BenchmarkRPCParallel_eth_getBalance(b *testing.B) {
	backend := setupBenchBackend(b)
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	backend.stateManager.SetBalance(addr, big.NewInt(1000))

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			makeRPCRequest(backend.server, "eth_getBalance", []interface{}{addr.Hex(), "latest"})
		}
	})
}
