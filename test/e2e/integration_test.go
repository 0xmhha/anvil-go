// Package e2e provides end-to-end integration tests for anvil-go.
package e2e

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stable-net/anvil-go/pkg/blockchain"
	"github.com/stable-net/anvil-go/pkg/miner"
	"github.com/stable-net/anvil-go/pkg/rpc"
	"github.com/stable-net/anvil-go/pkg/state"
	"github.com/stable-net/anvil-go/pkg/txpool"
)

// testBackend holds all components for E2E testing.
type testBackend struct {
	server       *rpc.Server
	chain        *blockchain.Chain
	pool         *txpool.InMemoryPool
	stateManager *state.InMemoryManager
	miner        *miner.SimpleMiner
	chainID      *big.Int
}

func setupTestBackend(t *testing.T) *testBackend {
	chainID := big.NewInt(31337)
	sm := state.NewInMemoryManager()
	chain := blockchain.NewChain(chainID)
	pool := txpool.NewInMemoryPool(sm, chainID)

	genesis := createGenesisBlock()
	err := chain.SetGenesis(genesis)
	require.NoError(t, err)

	m := miner.NewSimpleMiner(chain, pool, sm, chainID)
	server := rpc.NewServer(chain, pool, sm, m, chainID)

	return &testBackend{
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

func makeRPCRequest(t *testing.T, server *rpc.Server, method string, params interface{}) map[string]interface{} {
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	return resp
}

// TestE2E_FullTransactionFlow tests complete transaction lifecycle.
func TestE2E_FullTransactionFlow(t *testing.T) {
	backend := setupTestBackend(t)

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	receiver := common.HexToAddress("0x2222222222222222222222222222222222222222")
	initialBalance := new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)) // 10 ETH

	// Step 1: Set initial balance for sender
	resp := makeRPCRequest(t, backend.server, "anvil_setBalance", []interface{}{
		sender.Hex(),
		hexutil.EncodeBig(initialBalance),
	})
	require.Nil(t, resp["error"])

	// Verify sender balance
	resp = makeRPCRequest(t, backend.server, "eth_getBalance", []interface{}{
		sender.Hex(),
		"latest",
	})
	require.Nil(t, resp["error"])
	assert.Equal(t, hexutil.EncodeBig(initialBalance), resp["result"])

	// Step 2: Verify receiver has zero balance initially
	resp = makeRPCRequest(t, backend.server, "eth_getBalance", []interface{}{
		receiver.Hex(),
		"latest",
	})
	require.Nil(t, resp["error"])
	assert.Equal(t, "0x0", resp["result"])

	// Step 3: Mine a block
	resp = makeRPCRequest(t, backend.server, "anvil_mine", []interface{}{"0x1"})
	require.Nil(t, resp["error"])

	// Step 4: Verify block number increased
	resp = makeRPCRequest(t, backend.server, "eth_blockNumber", []interface{}{})
	require.Nil(t, resp["error"])
	assert.Equal(t, "0x1", resp["result"])
}

// TestE2E_SnapshotAndRevert tests snapshot/revert functionality.
func TestE2E_SnapshotAndRevert(t *testing.T) {
	backend := setupTestBackend(t)

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	balance1 := big.NewInt(1000)
	balance2 := big.NewInt(2000)

	// Step 1: Set initial balance
	makeRPCRequest(t, backend.server, "anvil_setBalance", []interface{}{
		addr.Hex(),
		hexutil.EncodeBig(balance1),
	})

	// Step 2: Take snapshot
	resp := makeRPCRequest(t, backend.server, "anvil_snapshot", []interface{}{})
	require.Nil(t, resp["error"])
	snapshotID := resp["result"].(string)

	// Step 3: Change balance
	makeRPCRequest(t, backend.server, "anvil_setBalance", []interface{}{
		addr.Hex(),
		hexutil.EncodeBig(balance2),
	})

	// Verify balance changed
	resp = makeRPCRequest(t, backend.server, "eth_getBalance", []interface{}{
		addr.Hex(),
		"latest",
	})
	assert.Equal(t, hexutil.EncodeBig(balance2), resp["result"])

	// Step 4: Revert to snapshot
	resp = makeRPCRequest(t, backend.server, "anvil_revert", []interface{}{snapshotID})
	require.Nil(t, resp["error"])
	assert.Equal(t, true, resp["result"])

	// Step 5: Verify balance restored
	resp = makeRPCRequest(t, backend.server, "eth_getBalance", []interface{}{
		addr.Hex(),
		"latest",
	})
	assert.Equal(t, hexutil.EncodeBig(balance1), resp["result"])
}

// TestE2E_StateDumpAndLoad tests state dump/load roundtrip.
func TestE2E_StateDumpAndLoad(t *testing.T) {
	backend1 := setupTestBackend(t)

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	balance := big.NewInt(5000)
	nonce := uint64(10)

	// Step 1: Setup state in backend1
	makeRPCRequest(t, backend1.server, "anvil_setBalance", []interface{}{
		addr.Hex(),
		hexutil.EncodeBig(balance),
	})
	makeRPCRequest(t, backend1.server, "anvil_setNonce", []interface{}{
		addr.Hex(),
		hexutil.EncodeUint64(nonce),
	})
	makeRPCRequest(t, backend1.server, "anvil_setCode", []interface{}{
		addr.Hex(),
		"0x6080604052",
	})

	// Step 2: Dump state
	resp := makeRPCRequest(t, backend1.server, "anvil_dumpState", []interface{}{})
	require.Nil(t, resp["error"])
	stateDump := resp["result"]

	// Step 3: Create new backend and load state
	backend2 := setupTestBackend(t)
	resp = makeRPCRequest(t, backend2.server, "anvil_loadState", []interface{}{stateDump})
	require.Nil(t, resp["error"])

	// Step 4: Verify state was loaded
	resp = makeRPCRequest(t, backend2.server, "eth_getBalance", []interface{}{
		addr.Hex(),
		"latest",
	})
	assert.Equal(t, hexutil.EncodeBig(balance), resp["result"])

	resp = makeRPCRequest(t, backend2.server, "eth_getTransactionCount", []interface{}{
		addr.Hex(),
		"latest",
	})
	assert.Equal(t, hexutil.EncodeUint64(nonce), resp["result"])

	resp = makeRPCRequest(t, backend2.server, "eth_getCode", []interface{}{
		addr.Hex(),
		"latest",
	})
	assert.Equal(t, "0x6080604052", resp["result"])
}

// TestE2E_ValidatorManagement tests validator add/remove/get.
func TestE2E_ValidatorManagement(t *testing.T) {
	backend := setupTestBackend(t)

	validator1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	operator1 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	validator2 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	operator2 := common.HexToAddress("0x4444444444444444444444444444444444444444")

	// Step 1: Add first validator
	resp := makeRPCRequest(t, backend.server, "stablenet_addValidator", []interface{}{
		validator1.Hex(),
		operator1.Hex(),
	})
	require.Nil(t, resp["error"])

	// Step 2: Add second validator
	resp = makeRPCRequest(t, backend.server, "stablenet_addValidator", []interface{}{
		validator2.Hex(),
		operator2.Hex(),
	})
	require.Nil(t, resp["error"])

	// Step 3: Get validators
	resp = makeRPCRequest(t, backend.server, "stablenet_getValidators", []interface{}{})
	require.Nil(t, resp["error"])
	validators := resp["result"].([]interface{})
	assert.Len(t, validators, 2)

	// Step 4: Get proposer for block 0
	resp = makeRPCRequest(t, backend.server, "stablenet_getProposer", []interface{}{"0x0"})
	require.Nil(t, resp["error"])
	proposer0 := resp["result"].(string)
	assert.Equal(t, validator1.Hex(), proposer0)

	// Step 5: Get proposer for block 1 (round-robin)
	resp = makeRPCRequest(t, backend.server, "stablenet_getProposer", []interface{}{"0x1"})
	require.Nil(t, resp["error"])
	proposer1 := resp["result"].(string)
	assert.Equal(t, validator2.Hex(), proposer1)

	// Step 6: Remove validator
	resp = makeRPCRequest(t, backend.server, "stablenet_removeValidator", []interface{}{
		validator1.Hex(),
	})
	require.Nil(t, resp["error"])

	// Step 7: Verify validator removed
	resp = makeRPCRequest(t, backend.server, "stablenet_getValidators", []interface{}{})
	require.Nil(t, resp["error"])
	validators = resp["result"].([]interface{})
	assert.Len(t, validators, 1)
}

// TestE2E_TimeManipulation tests time control functionality.
func TestE2E_TimeManipulation(t *testing.T) {
	backend := setupTestBackend(t)

	// Step 1: Test setNextBlockTimestamp API works
	resp := makeRPCRequest(t, backend.server, "anvil_setNextBlockTimestamp", []interface{}{
		"0x65000000", // Some future timestamp
	})
	require.Nil(t, resp["error"])
	assert.Equal(t, true, resp["result"])

	// Step 2: Test increaseTime API works
	resp = makeRPCRequest(t, backend.server, "anvil_increaseTime", []interface{}{"0xe10"}) // +3600s
	require.Nil(t, resp["error"])
	// increaseTime returns the new time
	require.NotNil(t, resp["result"])

	// Step 3: Mine blocks and verify they have increasing timestamps
	makeRPCRequest(t, backend.server, "anvil_mine", []interface{}{"0x1"})

	resp = makeRPCRequest(t, backend.server, "eth_getBlockByNumber", []interface{}{
		"latest",
		false,
	})
	require.Nil(t, resp["error"])
	block1 := resp["result"].(map[string]interface{})
	time1Hex := block1["timestamp"].(string)
	time1, _ := hexutil.DecodeUint64(time1Hex)

	// Mine another block
	makeRPCRequest(t, backend.server, "anvil_mine", []interface{}{"0x1"})

	resp = makeRPCRequest(t, backend.server, "eth_getBlockByNumber", []interface{}{
		"latest",
		false,
	})
	require.Nil(t, resp["error"])
	block2 := resp["result"].(map[string]interface{})
	time2Hex := block2["timestamp"].(string)
	time2, _ := hexutil.DecodeUint64(time2Hex)

	// Timestamps should be non-decreasing
	assert.GreaterOrEqual(t, time2, time1)
}

// TestE2E_ImpersonationFlow tests account impersonation.
func TestE2E_ImpersonationFlow(t *testing.T) {
	backend := setupTestBackend(t)

	impersonated := common.HexToAddress("0xdead000000000000000000000000000000000001")

	// Step 1: Setup balance for impersonated account
	makeRPCRequest(t, backend.server, "anvil_setBalance", []interface{}{
		impersonated.Hex(),
		"0xDE0B6B3A7640000", // 1 ETH
	})

	// Step 2: Enable impersonation
	resp := makeRPCRequest(t, backend.server, "anvil_impersonateAccount", []interface{}{
		impersonated.Hex(),
	})
	require.Nil(t, resp["error"])
	assert.Equal(t, true, resp["result"])

	// Step 3: Verify impersonation is active (can check via stop)
	resp = makeRPCRequest(t, backend.server, "anvil_stopImpersonatingAccount", []interface{}{
		impersonated.Hex(),
	})
	require.Nil(t, resp["error"])

	// Step 4: Enable auto-impersonation
	resp = makeRPCRequest(t, backend.server, "anvil_autoImpersonateAccount", []interface{}{true})
	require.Nil(t, resp["error"])
	assert.Equal(t, true, resp["result"])

	// Step 5: Disable auto-impersonation
	resp = makeRPCRequest(t, backend.server, "anvil_autoImpersonateAccount", []interface{}{false})
	require.Nil(t, resp["error"])
	assert.Equal(t, true, resp["result"])
}

// TestE2E_ChainReset tests anvil_reset functionality.
func TestE2E_ChainReset(t *testing.T) {
	backend := setupTestBackend(t)

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Step 1: Setup some state
	makeRPCRequest(t, backend.server, "anvil_setBalance", []interface{}{
		addr.Hex(),
		"0x1000",
	})

	// Add validator
	makeRPCRequest(t, backend.server, "stablenet_addValidator", []interface{}{
		addr.Hex(),
		addr.Hex(),
	})

	// Verify state exists
	resp := makeRPCRequest(t, backend.server, "eth_getBalance", []interface{}{
		addr.Hex(),
		"latest",
	})
	assert.Equal(t, "0x1000", resp["result"])

	resp = makeRPCRequest(t, backend.server, "stablenet_getValidators", []interface{}{})
	validators := resp["result"].([]interface{})
	assert.Len(t, validators, 1)

	// Step 2: Reset
	resp = makeRPCRequest(t, backend.server, "anvil_reset", []interface{}{})
	require.Nil(t, resp["error"])

	// Step 3: Verify validators cleared
	resp = makeRPCRequest(t, backend.server, "stablenet_getValidators", []interface{}{})
	validators = resp["result"].([]interface{})
	assert.Len(t, validators, 0)
}

// TestE2E_GasTipManagement tests gas tip functionality.
func TestE2E_GasTipManagement(t *testing.T) {
	backend := setupTestBackend(t)

	// Step 1: Get initial gas tip (should be 0)
	resp := makeRPCRequest(t, backend.server, "stablenet_getGasTip", []interface{}{})
	require.Nil(t, resp["error"])
	assert.Equal(t, "0x0", resp["result"])

	// Step 2: Set gas tip
	gasTip := big.NewInt(1e9) // 1 gwei
	resp = makeRPCRequest(t, backend.server, "stablenet_setGasTip", []interface{}{
		hexutil.EncodeBig(gasTip),
	})
	require.Nil(t, resp["error"])

	// Step 3: Verify gas tip
	resp = makeRPCRequest(t, backend.server, "stablenet_getGasTip", []interface{}{})
	require.Nil(t, resp["error"])
	assert.Equal(t, hexutil.EncodeBig(gasTip), resp["result"])
}

// TestE2E_MultipleBlockMining tests mining multiple blocks.
func TestE2E_MultipleBlockMining(t *testing.T) {
	backend := setupTestBackend(t)

	// Step 1: Get initial block number
	resp := makeRPCRequest(t, backend.server, "eth_blockNumber", []interface{}{})
	require.Nil(t, resp["error"])
	assert.Equal(t, "0x0", resp["result"])

	// Step 2: Mine 5 blocks
	resp = makeRPCRequest(t, backend.server, "anvil_mine", []interface{}{"0x5"})
	require.Nil(t, resp["error"])

	// Step 3: Verify block number
	resp = makeRPCRequest(t, backend.server, "eth_blockNumber", []interface{}{})
	require.Nil(t, resp["error"])
	assert.Equal(t, "0x5", resp["result"])

	// Step 4: Verify each block exists
	for i := uint64(0); i <= 5; i++ {
		resp = makeRPCRequest(t, backend.server, "eth_getBlockByNumber", []interface{}{
			hexutil.EncodeUint64(i),
			false,
		})
		require.Nil(t, resp["error"])
		require.NotNil(t, resp["result"])

		block := resp["result"].(map[string]interface{})
		blockNum := block["number"].(string)
		assert.Equal(t, hexutil.EncodeUint64(i), blockNum)
	}
}

// TestE2E_StorageManipulation tests storage read/write.
func TestE2E_StorageManipulation(t *testing.T) {
	backend := setupTestBackend(t)

	contract := common.HexToAddress("0x1111111111111111111111111111111111111111")
	slot := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	value := common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000002a") // 42

	// Step 1: Set storage
	resp := makeRPCRequest(t, backend.server, "anvil_setStorageAt", []interface{}{
		contract.Hex(),
		slot.Hex(),
		value.Hex(),
	})
	require.Nil(t, resp["error"])

	// Step 2: Read storage
	resp = makeRPCRequest(t, backend.server, "eth_getStorageAt", []interface{}{
		contract.Hex(),
		slot.Hex(),
		"latest",
	})
	require.Nil(t, resp["error"])
	assert.Equal(t, value.Hex(), resp["result"])

	// Step 3: Set multiple storage slots
	for i := 2; i <= 5; i++ {
		slotI := common.BigToHash(big.NewInt(int64(i)))
		valueI := common.BigToHash(big.NewInt(int64(i * 10)))

		makeRPCRequest(t, backend.server, "anvil_setStorageAt", []interface{}{
			contract.Hex(),
			slotI.Hex(),
			valueI.Hex(),
		})
	}

	// Step 4: Verify all slots
	for i := 2; i <= 5; i++ {
		slotI := common.BigToHash(big.NewInt(int64(i)))
		expectedValue := common.BigToHash(big.NewInt(int64(i * 10)))

		resp = makeRPCRequest(t, backend.server, "eth_getStorageAt", []interface{}{
			contract.Hex(),
			slotI.Hex(),
			"latest",
		})
		assert.Equal(t, expectedValue.Hex(), resp["result"])
	}
}

// TestE2E_CoinbaseAndBaseFee tests coinbase and base fee manipulation APIs.
func TestE2E_CoinbaseAndBaseFee(t *testing.T) {
	backend := setupTestBackend(t)

	newCoinbase := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	newBaseFee := big.NewInt(2e9) // 2 gwei

	// Step 1: Set coinbase - verify API works
	resp := makeRPCRequest(t, backend.server, "anvil_setCoinbase", []interface{}{
		newCoinbase.Hex(),
	})
	require.Nil(t, resp["error"])
	assert.Equal(t, true, resp["result"])

	// Step 2: Set next block base fee - verify API works
	resp = makeRPCRequest(t, backend.server, "anvil_setNextBlockBaseFee", []interface{}{
		hexutil.EncodeBig(newBaseFee),
	})
	require.Nil(t, resp["error"])
	assert.Equal(t, true, resp["result"])

	// Step 3: Mine block
	resp = makeRPCRequest(t, backend.server, "anvil_mine", []interface{}{"0x1"})
	require.Nil(t, resp["error"])

	// Step 4: Verify block was mined
	resp = makeRPCRequest(t, backend.server, "eth_getBlockByNumber", []interface{}{
		"latest",
		false,
	})
	require.Nil(t, resp["error"])
	block := resp["result"].(map[string]interface{})
	require.NotNil(t, block["number"])
	require.NotNil(t, block["miner"])
}

// TestE2E_EVMMethodAliases tests that evm_* methods work as aliases.
func TestE2E_EVMMethodAliases(t *testing.T) {
	backend := setupTestBackend(t)

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Setup
	makeRPCRequest(t, backend.server, "anvil_setBalance", []interface{}{
		addr.Hex(),
		"0x1000",
	})

	// Test evm_snapshot (alias for anvil_snapshot)
	resp := makeRPCRequest(t, backend.server, "evm_snapshot", []interface{}{})
	require.Nil(t, resp["error"])
	snapshotID := resp["result"].(string)

	// Change state
	makeRPCRequest(t, backend.server, "anvil_setBalance", []interface{}{
		addr.Hex(),
		"0x2000",
	})

	// Test evm_revert (alias for anvil_revert)
	resp = makeRPCRequest(t, backend.server, "evm_revert", []interface{}{snapshotID})
	require.Nil(t, resp["error"])

	// Verify reverted
	resp = makeRPCRequest(t, backend.server, "eth_getBalance", []interface{}{
		addr.Hex(),
		"latest",
	})
	assert.Equal(t, "0x1000", resp["result"])

	// Test evm_mine (alias for anvil_mine)
	resp = makeRPCRequest(t, backend.server, "evm_mine", []interface{}{"0x1"})
	require.Nil(t, resp["error"])

	// Test evm_increaseTime (alias for anvil_increaseTime)
	resp = makeRPCRequest(t, backend.server, "evm_increaseTime", []interface{}{"0x3c"}) // 60s
	require.Nil(t, resp["error"])

	// Test evm_setNextBlockTimestamp
	resp = makeRPCRequest(t, backend.server, "evm_setNextBlockTimestamp", []interface{}{"0x65000000"})
	require.Nil(t, resp["error"])
}
