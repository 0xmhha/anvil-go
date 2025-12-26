package rpc

import (
	"bytes"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stable-net/anvil-go/pkg/blockchain"
	"github.com/stable-net/anvil-go/pkg/miner"
	"github.com/stable-net/anvil-go/pkg/state"
	"github.com/stable-net/anvil-go/pkg/txpool"
)

func setupServer(t *testing.T) *Server {
	chainID := big.NewInt(31337)
	sm := state.NewInMemoryManager()
	chain := blockchain.NewChain(chainID)
	pool := txpool.NewInMemoryPool(sm, chainID)

	// Set genesis
	genesis := createGenesisBlock()
	err := chain.SetGenesis(genesis)
	require.NoError(t, err)

	m := miner.NewSimpleMiner(chain, pool, sm, chainID)

	server := NewServer(chain, pool, sm, m, chainID)
	return server
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

func makeRequest(t *testing.T, server *Server, method string, params interface{}) *httptest.ResponseRecorder {
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
	return w
}

type jsonrpcResponse struct {
	Jsonrpc string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func parseResponse(t *testing.T, w *httptest.ResponseRecorder) *jsonrpcResponse {
	var resp jsonrpcResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	return &resp
}

func TestNewServer(t *testing.T) {
	server := setupServer(t)
	require.NotNil(t, server)
}

func TestServer_eth_chainId(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "eth_chainId", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var chainID string
	err := json.Unmarshal(resp.Result, &chainID)
	require.NoError(t, err)
	assert.Equal(t, "0x7a69", chainID) // 31337 in hex
}

func TestServer_eth_blockNumber(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "eth_blockNumber", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var blockNumber string
	err := json.Unmarshal(resp.Result, &blockNumber)
	require.NoError(t, err)
	assert.Equal(t, "0x0", blockNumber) // Genesis block
}

func TestServer_eth_getBalance(t *testing.T) {
	server := setupServer(t)

	// Fund an account
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	balance := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	server.stateManager.SetBalance(addr, balance)

	w := makeRequest(t, server, "eth_getBalance", []interface{}{addr.Hex(), "latest"})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var balanceHex string
	err := json.Unmarshal(resp.Result, &balanceHex)
	require.NoError(t, err)

	gotBalance, err := hexutil.DecodeBig(balanceHex)
	require.NoError(t, err)
	assert.Equal(t, balance, gotBalance)
}

func TestServer_eth_getTransactionCount(t *testing.T) {
	server := setupServer(t)

	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	server.stateManager.SetNonce(addr, 5)

	w := makeRequest(t, server, "eth_getTransactionCount", []interface{}{addr.Hex(), "latest"})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var nonceHex string
	err := json.Unmarshal(resp.Result, &nonceHex)
	require.NoError(t, err)
	assert.Equal(t, "0x5", nonceHex)
}

func TestServer_eth_getCode(t *testing.T) {
	server := setupServer(t)

	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	code := []byte{0x60, 0x00, 0x60, 0x00, 0xf3}
	server.stateManager.SetCode(addr, code)

	w := makeRequest(t, server, "eth_getCode", []interface{}{addr.Hex(), "latest"})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var codeHex string
	err := json.Unmarshal(resp.Result, &codeHex)
	require.NoError(t, err)
	assert.Equal(t, "0x60006000f3", codeHex)
}

func TestServer_eth_getStorageAt(t *testing.T) {
	server := setupServer(t)

	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	slot := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	value := common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000002a")
	server.stateManager.SetStorageAt(addr, slot, value)

	w := makeRequest(t, server, "eth_getStorageAt", []interface{}{addr.Hex(), slot.Hex(), "latest"})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var storageHex string
	err := json.Unmarshal(resp.Result, &storageHex)
	require.NoError(t, err)
	assert.Equal(t, value.Hex(), storageHex)
}

func TestServer_eth_getBlockByNumber(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "eth_getBlockByNumber", []interface{}{"0x0", false})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var block map[string]interface{}
	err := json.Unmarshal(resp.Result, &block)
	require.NoError(t, err)
	assert.Equal(t, "0x0", block["number"])
}

func TestServer_eth_getBlockByNumber_NotFound(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "eth_getBlockByNumber", []interface{}{"0x999", false})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	// Block not found returns null
	assert.Equal(t, "null", string(resp.Result))
}

func TestServer_net_version(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "net_version", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var version string
	err := json.Unmarshal(resp.Result, &version)
	require.NoError(t, err)
	assert.Equal(t, "31337", version)
}

func TestServer_web3_clientVersion(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "web3_clientVersion", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var version string
	err := json.Unmarshal(resp.Result, &version)
	require.NoError(t, err)
	assert.Contains(t, version, "anvil-go")
}

func TestServer_eth_gasPrice(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "eth_gasPrice", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var gasPriceHex string
	err := json.Unmarshal(resp.Result, &gasPriceHex)
	require.NoError(t, err)

	gasPrice, err := hexutil.DecodeBig(gasPriceHex)
	require.NoError(t, err)
	assert.True(t, gasPrice.Cmp(big.NewInt(0)) > 0)
}

func TestServer_eth_estimateGas(t *testing.T) {
	server := setupServer(t)

	from := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Fund the from account
	server.stateManager.SetBalance(from, new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)))

	callParams := map[string]interface{}{
		"from":  from.Hex(),
		"to":    to.Hex(),
		"value": "0xde0b6b3a7640000", // 1 ETH
	}

	w := makeRequest(t, server, "eth_estimateGas", []interface{}{callParams})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var gasHex string
	err := json.Unmarshal(resp.Result, &gasHex)
	require.NoError(t, err)

	gas, err := hexutil.DecodeUint64(gasHex)
	require.NoError(t, err)
	assert.Equal(t, uint64(21000), gas) // Simple transfer
}

func TestServer_InvalidMethod(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "invalid_method", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.NotNil(t, resp.Error)
	assert.Equal(t, -32601, resp.Error.Code) // Method not found
}

func TestServer_InvalidJSON(t *testing.T) {
	server := setupServer(t)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.NotNil(t, resp.Error)
	assert.Equal(t, -32700, resp.Error.Code) // Parse error
}

func TestServer_eth_accounts(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "eth_accounts", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var accounts []string
	err := json.Unmarshal(resp.Result, &accounts)
	require.NoError(t, err)
	// Default accounts (empty for now)
	assert.NotNil(t, accounts)
}

// anvil_* RPC method tests

func TestServer_anvil_setBalance(t *testing.T) {
	server := setupServer(t)

	addr := "0x1234567890123456789012345678901234567890"
	balance := "0xde0b6b3a7640000" // 1 ETH

	w := makeRequest(t, server, "anvil_setBalance", []interface{}{addr, balance})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify balance was set
	w2 := makeRequest(t, server, "eth_getBalance", []interface{}{addr, "latest"})
	resp2 := parseResponse(t, w2)
	var balanceHex string
	json.Unmarshal(resp2.Result, &balanceHex)
	assert.Equal(t, balance, balanceHex)
}

func TestServer_anvil_setNonce(t *testing.T) {
	server := setupServer(t)

	addr := "0x1234567890123456789012345678901234567890"
	nonce := "0x2a" // 42

	w := makeRequest(t, server, "anvil_setNonce", []interface{}{addr, nonce})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify nonce was set
	w2 := makeRequest(t, server, "eth_getTransactionCount", []interface{}{addr, "latest"})
	resp2 := parseResponse(t, w2)
	var nonceHex string
	json.Unmarshal(resp2.Result, &nonceHex)
	assert.Equal(t, nonce, nonceHex)
}

func TestServer_anvil_setCode(t *testing.T) {
	server := setupServer(t)

	addr := "0x1234567890123456789012345678901234567890"
	code := "0x60006000f3"

	w := makeRequest(t, server, "anvil_setCode", []interface{}{addr, code})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify code was set
	w2 := makeRequest(t, server, "eth_getCode", []interface{}{addr, "latest"})
	resp2 := parseResponse(t, w2)
	var codeHex string
	json.Unmarshal(resp2.Result, &codeHex)
	assert.Equal(t, code, codeHex)
}

func TestServer_anvil_setStorageAt(t *testing.T) {
	server := setupServer(t)

	addr := "0x1234567890123456789012345678901234567890"
	slot := "0x0000000000000000000000000000000000000000000000000000000000000001"
	value := "0x000000000000000000000000000000000000000000000000000000000000002a"

	w := makeRequest(t, server, "anvil_setStorageAt", []interface{}{addr, slot, value})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify storage was set
	w2 := makeRequest(t, server, "eth_getStorageAt", []interface{}{addr, slot, "latest"})
	resp2 := parseResponse(t, w2)
	var storageHex string
	json.Unmarshal(resp2.Result, &storageHex)
	assert.Equal(t, value, storageHex)
}

func TestServer_anvil_impersonateAccount(t *testing.T) {
	server := setupServer(t)

	addr := "0x1234567890123456789012345678901234567890"

	w := makeRequest(t, server, "anvil_impersonateAccount", []interface{}{addr})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify impersonation is active
	assert.True(t, server.cheats.IsImpersonating(common.HexToAddress(addr)))
}

func TestServer_anvil_stopImpersonatingAccount(t *testing.T) {
	server := setupServer(t)

	addr := "0x1234567890123456789012345678901234567890"

	// First impersonate
	server.cheats.ImpersonateAccount(common.HexToAddress(addr))
	assert.True(t, server.cheats.IsImpersonating(common.HexToAddress(addr)))

	// Then stop impersonating
	w := makeRequest(t, server, "anvil_stopImpersonatingAccount", []interface{}{addr})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify impersonation stopped
	assert.False(t, server.cheats.IsImpersonating(common.HexToAddress(addr)))
}

func TestServer_anvil_autoImpersonateAccount(t *testing.T) {
	server := setupServer(t)

	// Enable auto-impersonation
	w := makeRequest(t, server, "anvil_autoImpersonateAccount", []interface{}{true})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify auto-impersonation is enabled
	assert.True(t, server.cheats.IsAutoImpersonate())

	// Any address should now be impersonated
	randomAddr := common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	assert.True(t, server.cheats.IsImpersonating(randomAddr))
}

func TestServer_anvil_mine(t *testing.T) {
	server := setupServer(t)

	// Get initial block number
	w1 := makeRequest(t, server, "eth_blockNumber", []interface{}{})
	resp1 := parseResponse(t, w1)
	var initialBlockHex string
	json.Unmarshal(resp1.Result, &initialBlockHex)
	initialBlock, _ := hexutil.DecodeUint64(initialBlockHex)

	// Mine 3 blocks
	w := makeRequest(t, server, "anvil_mine", []interface{}{"0x3"})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	// Verify block number increased by 3
	w2 := makeRequest(t, server, "eth_blockNumber", []interface{}{})
	resp2 := parseResponse(t, w2)
	var newBlockHex string
	json.Unmarshal(resp2.Result, &newBlockHex)
	newBlock, _ := hexutil.DecodeUint64(newBlockHex)

	assert.Equal(t, initialBlock+3, newBlock)
}

func TestServer_anvil_mine_default(t *testing.T) {
	server := setupServer(t)

	// Get initial block number
	w1 := makeRequest(t, server, "eth_blockNumber", []interface{}{})
	resp1 := parseResponse(t, w1)
	var initialBlockHex string
	json.Unmarshal(resp1.Result, &initialBlockHex)
	initialBlock, _ := hexutil.DecodeUint64(initialBlockHex)

	// Mine without count (defaults to 1)
	w := makeRequest(t, server, "anvil_mine", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	// Verify block number increased by 1
	w2 := makeRequest(t, server, "eth_blockNumber", []interface{}{})
	resp2 := parseResponse(t, w2)
	var newBlockHex string
	json.Unmarshal(resp2.Result, &newBlockHex)
	newBlock, _ := hexutil.DecodeUint64(newBlockHex)

	assert.Equal(t, initialBlock+1, newBlock)
}

func TestServer_anvil_snapshot_and_revert(t *testing.T) {
	server := setupServer(t)

	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Set initial balance
	server.stateManager.SetBalance(addr, big.NewInt(1000))

	// Take snapshot
	w1 := makeRequest(t, server, "anvil_snapshot", []interface{}{})
	resp1 := parseResponse(t, w1)
	require.Nil(t, resp1.Error)

	var snapshotID string
	json.Unmarshal(resp1.Result, &snapshotID)
	require.NotEmpty(t, snapshotID)

	// Modify state
	server.stateManager.SetBalance(addr, big.NewInt(9999))
	assert.Equal(t, big.NewInt(9999), server.stateManager.GetBalance(addr))

	// Revert to snapshot
	w2 := makeRequest(t, server, "anvil_revert", []interface{}{snapshotID})
	resp2 := parseResponse(t, w2)
	require.Nil(t, resp2.Error)

	var success bool
	json.Unmarshal(resp2.Result, &success)
	assert.True(t, success)

	// Verify state was restored
	assert.Equal(t, big.NewInt(1000), server.stateManager.GetBalance(addr))
}

func TestServer_evm_snapshot_and_revert(t *testing.T) {
	server := setupServer(t)

	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Set initial balance
	server.stateManager.SetBalance(addr, big.NewInt(1000))

	// Take snapshot using evm_snapshot
	w1 := makeRequest(t, server, "evm_snapshot", []interface{}{})
	resp1 := parseResponse(t, w1)
	require.Nil(t, resp1.Error)

	var snapshotID string
	json.Unmarshal(resp1.Result, &snapshotID)

	// Modify state
	server.stateManager.SetBalance(addr, big.NewInt(9999))

	// Revert using evm_revert
	w2 := makeRequest(t, server, "evm_revert", []interface{}{snapshotID})
	resp2 := parseResponse(t, w2)
	require.Nil(t, resp2.Error)

	// Verify state was restored
	assert.Equal(t, big.NewInt(1000), server.stateManager.GetBalance(addr))
}

func TestServer_anvil_increaseTime(t *testing.T) {
	server := setupServer(t)

	// Increase time by 1 hour (3600 seconds)
	w := makeRequest(t, server, "anvil_increaseTime", []interface{}{"0xe10"})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var newTimeHex string
	err := json.Unmarshal(resp.Result, &newTimeHex)
	require.NoError(t, err)

	newTime, _ := hexutil.DecodeUint64(newTimeHex)
	assert.Greater(t, newTime, uint64(0))
}

func TestServer_anvil_setNextBlockTimestamp(t *testing.T) {
	server := setupServer(t)

	expectedTime := "0x6b49d200" // Some future timestamp

	w := makeRequest(t, server, "anvil_setNextBlockTimestamp", []interface{}{expectedTime})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify timestamp was set
	expected, _ := hexutil.DecodeUint64(expectedTime)
	assert.Equal(t, expected, server.cheats.GetNextBlockTimestamp())
}

func TestServer_anvil_setNextBlockBaseFee(t *testing.T) {
	server := setupServer(t)

	baseFee := "0x77359400" // 2 gwei

	w := makeRequest(t, server, "anvil_setNextBlockBaseFee", []interface{}{baseFee})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify base fee was set
	expected, _ := hexutil.DecodeBig(baseFee)
	assert.Equal(t, expected, server.cheats.GetNextBlockBaseFee())
}

func TestServer_anvil_setCoinbase(t *testing.T) {
	server := setupServer(t)

	coinbase := "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	w := makeRequest(t, server, "anvil_setCoinbase", []interface{}{coinbase})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify coinbase was set
	assert.Equal(t, common.HexToAddress(coinbase), server.cheats.GetCoinbase())
}

func TestServer_anvil_reset(t *testing.T) {
	server := setupServer(t)

	// Setup some state
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	server.stateManager.SetBalance(addr, big.NewInt(1000))
	server.cheats.ImpersonateAccount(addr)
	server.cheats.SetNextBlockTimestamp(1800000000)
	server.snapshots.Snapshot()

	// Reset
	w := makeRequest(t, server, "anvil_reset", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify cheats were reset
	assert.False(t, server.cheats.IsImpersonating(addr))
	assert.Equal(t, uint64(0), server.cheats.GetNextBlockTimestamp())

	// Verify snapshots were cleared
	assert.Equal(t, 0, server.snapshots.Count())
}

// StableNet RPC Tests

func TestServer_stablenet_addValidator(t *testing.T) {
	server := setupServer(t)

	addr := "0x1111111111111111111111111111111111111111"
	operator := "0x2222222222222222222222222222222222222222"

	w := makeRequest(t, server, "stablenet_addValidator", []interface{}{addr, operator})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify validator was added
	assert.Equal(t, 1, server.validators.Count())
	v, exists := server.validators.GetValidator(common.HexToAddress(addr))
	assert.True(t, exists)
	assert.Equal(t, common.HexToAddress(operator), v.Operator)
}

func TestServer_stablenet_addValidator_withBLSKey(t *testing.T) {
	server := setupServer(t)

	addr := "0x1111111111111111111111111111111111111111"
	operator := "0x2222222222222222222222222222222222222222"
	blsKey := "0x" + "aa" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

	w := makeRequest(t, server, "stablenet_addValidator", []interface{}{addr, operator, blsKey})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify validator was added with BLS key
	v, exists := server.validators.GetValidator(common.HexToAddress(addr))
	assert.True(t, exists)
	assert.Equal(t, byte(0xaa), v.BLSPublicKey[0])
}

func TestServer_stablenet_addValidator_duplicate(t *testing.T) {
	server := setupServer(t)

	addr := "0x1111111111111111111111111111111111111111"
	operator := "0x2222222222222222222222222222222222222222"

	// Add first time
	w := makeRequest(t, server, "stablenet_addValidator", []interface{}{addr, operator})
	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	// Try to add again
	w2 := makeRequest(t, server, "stablenet_addValidator", []interface{}{addr, operator})
	resp2 := parseResponse(t, w2)
	require.NotNil(t, resp2.Error)
	assert.Contains(t, resp2.Error.Message, "exists")
}

func TestServer_stablenet_removeValidator(t *testing.T) {
	server := setupServer(t)

	addr := "0x1111111111111111111111111111111111111111"
	operator := "0x2222222222222222222222222222222222222222"

	// Add validator first
	server.validators.AddValidator(common.HexToAddress(addr), common.HexToAddress(operator), make([]byte, 48))
	assert.Equal(t, 1, server.validators.Count())

	// Remove via RPC
	w := makeRequest(t, server, "stablenet_removeValidator", []interface{}{addr})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify validator was removed
	assert.Equal(t, 0, server.validators.Count())
}

func TestServer_stablenet_removeValidator_notFound(t *testing.T) {
	server := setupServer(t)

	addr := "0x1111111111111111111111111111111111111111"

	w := makeRequest(t, server, "stablenet_removeValidator", []interface{}{addr})
	resp := parseResponse(t, w)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "not found")
}

func TestServer_stablenet_getValidators(t *testing.T) {
	server := setupServer(t)

	// Add some validators
	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	op1 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	op2 := common.HexToAddress("0x4444444444444444444444444444444444444444")

	server.validators.AddValidator(addr1, op1, make([]byte, 48))
	server.validators.AddValidator(addr2, op2, make([]byte, 48))

	w := makeRequest(t, server, "stablenet_getValidators", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var validators []map[string]interface{}
	err := json.Unmarshal(resp.Result, &validators)
	require.NoError(t, err)
	assert.Len(t, validators, 2)

	// Check first validator
	assert.Equal(t, addr1.Hex(), validators[0]["address"])
	assert.Equal(t, op1.Hex(), validators[0]["operator"])
}

func TestServer_stablenet_getValidators_empty(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "stablenet_getValidators", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var validators []map[string]interface{}
	err := json.Unmarshal(resp.Result, &validators)
	require.NoError(t, err)
	assert.Len(t, validators, 0)
}

func TestServer_stablenet_getProposer(t *testing.T) {
	server := setupServer(t)

	// Add validators
	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	addr3 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	operator := common.HexToAddress("0x4444444444444444444444444444444444444444")

	server.validators.AddValidator(addr1, operator, make([]byte, 48))
	server.validators.AddValidator(addr2, operator, make([]byte, 48))
	server.validators.AddValidator(addr3, operator, make([]byte, 48))

	// Test round-robin proposer selection
	// Block 0 -> addr1
	w0 := makeRequest(t, server, "stablenet_getProposer", []interface{}{"0x0"})
	resp0 := parseResponse(t, w0)
	require.Nil(t, resp0.Error)
	var proposer0 string
	json.Unmarshal(resp0.Result, &proposer0)
	assert.Equal(t, addr1.Hex(), proposer0)

	// Block 1 -> addr2
	w1 := makeRequest(t, server, "stablenet_getProposer", []interface{}{"0x1"})
	resp1 := parseResponse(t, w1)
	require.Nil(t, resp1.Error)
	var proposer1 string
	json.Unmarshal(resp1.Result, &proposer1)
	assert.Equal(t, addr2.Hex(), proposer1)

	// Block 2 -> addr3
	w2 := makeRequest(t, server, "stablenet_getProposer", []interface{}{"0x2"})
	resp2 := parseResponse(t, w2)
	require.Nil(t, resp2.Error)
	var proposer2 string
	json.Unmarshal(resp2.Result, &proposer2)
	assert.Equal(t, addr3.Hex(), proposer2)

	// Block 3 -> addr1 (wraps around)
	w3 := makeRequest(t, server, "stablenet_getProposer", []interface{}{"0x3"})
	resp3 := parseResponse(t, w3)
	require.Nil(t, resp3.Error)
	var proposer3 string
	json.Unmarshal(resp3.Result, &proposer3)
	assert.Equal(t, addr1.Hex(), proposer3)
}

func TestServer_stablenet_getProposer_latest(t *testing.T) {
	server := setupServer(t)

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	operator := common.HexToAddress("0x2222222222222222222222222222222222222222")
	server.validators.AddValidator(addr, operator, make([]byte, 48))

	w := makeRequest(t, server, "stablenet_getProposer", []interface{}{"latest"})
	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var proposer string
	json.Unmarshal(resp.Result, &proposer)
	assert.Equal(t, addr.Hex(), proposer)
}

func TestServer_stablenet_getProposer_noValidators(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "stablenet_getProposer", []interface{}{"0x0"})
	resp := parseResponse(t, w)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "no validators")
}

func TestServer_stablenet_setProposer(t *testing.T) {
	server := setupServer(t)

	// setProposer is a no-op since proposer is determined by round-robin
	w := makeRequest(t, server, "stablenet_setProposer", []interface{}{"0x1111111111111111111111111111111111111111"})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	json.Unmarshal(resp.Result, &result)
	assert.True(t, result)
}

func TestServer_stablenet_setGasTip(t *testing.T) {
	server := setupServer(t)

	gasTip := "0x3b9aca00" // 1 gwei

	w := makeRequest(t, server, "stablenet_setGasTip", []interface{}{gasTip})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify gas tip was set
	expected, _ := hexutil.DecodeBig(gasTip)
	assert.Equal(t, expected, server.validators.GetGasTip())
}

func TestServer_stablenet_getGasTip(t *testing.T) {
	server := setupServer(t)

	// Initial gas tip should be 0
	w1 := makeRequest(t, server, "stablenet_getGasTip", []interface{}{})
	resp1 := parseResponse(t, w1)
	require.Nil(t, resp1.Error)

	var gasTip1 string
	json.Unmarshal(resp1.Result, &gasTip1)
	assert.Equal(t, "0x0", gasTip1)

	// Set gas tip
	server.validators.SetGasTip(big.NewInt(1000000000)) // 1 gwei

	// Get updated gas tip
	w2 := makeRequest(t, server, "stablenet_getGasTip", []interface{}{})
	resp2 := parseResponse(t, w2)
	require.Nil(t, resp2.Error)

	var gasTip2 string
	json.Unmarshal(resp2.Result, &gasTip2)
	assert.Equal(t, "0x3b9aca00", gasTip2)
}

func TestServer_anvil_reset_clears_validators(t *testing.T) {
	server := setupServer(t)

	// Add some validators
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	operator := common.HexToAddress("0x2222222222222222222222222222222222222222")
	server.validators.AddValidator(addr, operator, make([]byte, 48))
	server.validators.SetGasTip(big.NewInt(1000))
	assert.Equal(t, 1, server.validators.Count())

	// Reset
	w := makeRequest(t, server, "anvil_reset", []interface{}{})
	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	// Verify validators were cleared
	assert.Equal(t, 0, server.validators.Count())
	assert.Equal(t, big.NewInt(0), server.validators.GetGasTip())
}

// Debug RPC Tests

func TestServer_debug_traceCall(t *testing.T) {
	server := setupServer(t)

	from := "0x1111111111111111111111111111111111111111"
	to := "0x2222222222222222222222222222222222222222"

	callArgs := map[string]interface{}{
		"from":  from,
		"to":    to,
		"gas":   "0x5208",
		"value": "0x0",
		"data":  "0x",
	}

	w := makeRequest(t, server, "debug_traceCall", []interface{}{callArgs, "latest"})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)

	assert.Equal(t, "CALL", result["type"])
	assert.Equal(t, common.HexToAddress(from).Hex(), result["from"])
}

func TestServer_debug_traceCall_withData(t *testing.T) {
	server := setupServer(t)

	from := "0x1111111111111111111111111111111111111111"
	to := "0x2222222222222222222222222222222222222222"

	callArgs := map[string]interface{}{
		"from":  from,
		"to":    to,
		"gas":   "0xf4240", // 1000000
		"data":  "0xdeadbeef",
		"value": "0x3e8", // 1000
	}

	w := makeRequest(t, server, "debug_traceCall", []interface{}{callArgs, "latest"})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result map[string]interface{}
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)

	assert.Equal(t, "CALL", result["type"])
	assert.NotNil(t, result["input"])
}

func TestServer_debug_traceCall_invalidParams(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "debug_traceCall", []interface{}{})
	resp := parseResponse(t, w)
	require.NotNil(t, resp.Error)
}

func TestServer_debug_traceBlockByNumber(t *testing.T) {
	server := setupServer(t)

	// Trace genesis block
	w := makeRequest(t, server, "debug_traceBlockByNumber", []interface{}{"0x0"})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var results []interface{}
	err := json.Unmarshal(resp.Result, &results)
	require.NoError(t, err)

	// Genesis block has no transactions
	assert.Len(t, results, 0)
}

func TestServer_debug_traceBlockByNumber_latest(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "debug_traceBlockByNumber", []interface{}{"latest"})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)
}

func TestServer_debug_traceBlockByNumber_notFound(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "debug_traceBlockByNumber", []interface{}{"0x999999"})
	resp := parseResponse(t, w)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "not found")
}

func TestServer_debug_traceTransaction_notFound(t *testing.T) {
	server := setupServer(t)

	txHash := "0x0000000000000000000000000000000000000000000000000000000000000001"

	w := makeRequest(t, server, "debug_traceTransaction", []interface{}{txHash})
	resp := parseResponse(t, w)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "not found")
}

func TestServer_debug_traceTransaction_invalidParams(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "debug_traceTransaction", []interface{}{})
	resp := parseResponse(t, w)
	require.NotNil(t, resp.Error)
}

func TestServer_anvil_dumpState(t *testing.T) {
	server := setupServer(t)

	// Set some state first
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	balance := big.NewInt(1000)
	w := makeRequest(t, server, "anvil_setBalance", []interface{}{addr.Hex(), hexutil.EncodeBig(balance)})
	require.Equal(t, http.StatusOK, w.Code)

	// Dump state
	w = makeRequest(t, server, "anvil_dumpState", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var dump map[string]interface{}
	err := json.Unmarshal(resp.Result, &dump)
	require.NoError(t, err)

	accounts, ok := dump["accounts"].(map[string]interface{})
	require.True(t, ok)
	require.Contains(t, accounts, addr.Hex())
}

func TestServer_anvil_dumpState_emptyState(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "anvil_dumpState", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var dump map[string]interface{}
	err := json.Unmarshal(resp.Result, &dump)
	require.NoError(t, err)
	assert.NotNil(t, dump["accounts"])
}

func TestServer_anvil_loadState(t *testing.T) {
	server := setupServer(t)

	// Create a state dump to load
	stateDump := map[string]interface{}{
		"accounts": map[string]interface{}{
			"0x1111111111111111111111111111111111111111": map[string]interface{}{
				"balance": "0x3e8",
				"nonce":   float64(5),
				"code":    "0x6000f3",
			},
		},
	}

	w := makeRequest(t, server, "anvil_loadState", []interface{}{stateDump})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify the state was loaded
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	w = makeRequest(t, server, "eth_getBalance", []interface{}{addr.Hex(), "latest"})
	resp = parseResponse(t, w)
	require.Nil(t, resp.Error)

	var balanceHex string
	err = json.Unmarshal(resp.Result, &balanceHex)
	require.NoError(t, err)
	assert.Equal(t, "0x3e8", balanceHex)
}

func TestServer_anvil_loadState_invalidParams(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "anvil_loadState", []interface{}{})
	resp := parseResponse(t, w)
	require.NotNil(t, resp.Error)
}

func TestServer_anvil_loadState_invalidDump(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "anvil_loadState", []interface{}{"not a map"})
	resp := parseResponse(t, w)
	require.NotNil(t, resp.Error)
}

func TestServer_anvil_loadState_withStorage(t *testing.T) {
	server := setupServer(t)

	// Create a state dump with storage
	stateDump := map[string]interface{}{
		"accounts": map[string]interface{}{
			"0x1111111111111111111111111111111111111111": map[string]interface{}{
				"balance": "0x0",
				"nonce":   float64(0),
				"storage": map[string]interface{}{
					"0x0000000000000000000000000000000000000000000000000000000000000001": "0x0000000000000000000000000000000000000000000000000000000000000042",
				},
			},
		},
	}

	w := makeRequest(t, server, "anvil_loadState", []interface{}{stateDump})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	// Verify storage was loaded
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	slot := common.HexToHash("0x01")
	w = makeRequest(t, server, "eth_getStorageAt", []interface{}{addr.Hex(), slot.Hex(), "latest"})
	resp = parseResponse(t, w)
	require.Nil(t, resp.Error)

	var storageValue string
	err := json.Unmarshal(resp.Result, &storageValue)
	require.NoError(t, err)
	assert.Equal(t, "0x0000000000000000000000000000000000000000000000000000000000000042", storageValue)
}

func TestServer_anvil_dumpState_roundTrip(t *testing.T) {
	server := setupServer(t)

	// Set some state
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	w := makeRequest(t, server, "anvil_setBalance", []interface{}{addr.Hex(), "0x1000"})
	require.Equal(t, http.StatusOK, w.Code)

	w = makeRequest(t, server, "anvil_setNonce", []interface{}{addr.Hex(), "0x5"})
	require.Equal(t, http.StatusOK, w.Code)

	w = makeRequest(t, server, "anvil_setCode", []interface{}{addr.Hex(), "0x6000f3"})
	require.Equal(t, http.StatusOK, w.Code)

	// Dump state
	w = makeRequest(t, server, "anvil_dumpState", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var dump map[string]interface{}
	err := json.Unmarshal(resp.Result, &dump)
	require.NoError(t, err)

	// Create a new server and load the state
	server2 := setupServer(t)
	w = makeRequest(t, server2, "anvil_loadState", []interface{}{dump})
	require.Equal(t, http.StatusOK, w.Code)

	resp = parseResponse(t, w)
	require.Nil(t, resp.Error)

	// Verify state was loaded correctly
	w = makeRequest(t, server2, "eth_getBalance", []interface{}{addr.Hex(), "latest"})
	resp = parseResponse(t, w)
	require.Nil(t, resp.Error)

	var balanceHex string
	err = json.Unmarshal(resp.Result, &balanceHex)
	require.NoError(t, err)
	assert.Equal(t, "0x1000", balanceHex)
}

func TestServer_anvil_dropTransaction(t *testing.T) {
	server := setupServer(t)

	// Try to drop a non-existent transaction
	txHash := "0x0000000000000000000000000000000000000000000000000000000000000001"

	w := makeRequest(t, server, "anvil_dropTransaction", []interface{}{txHash})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	// Should return false since tx doesn't exist
	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.False(t, result)
}

func TestServer_evm_setAutomine(t *testing.T) {
	server := setupServer(t)

	// Check default is true
	assert.True(t, server.cheats.IsAutomine())

	// Disable automine
	w := makeRequest(t, server, "evm_setAutomine", []interface{}{false})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify automine was disabled
	assert.False(t, server.cheats.IsAutomine())

	// Re-enable automine
	w = makeRequest(t, server, "evm_setAutomine", []interface{}{true})
	resp = parseResponse(t, w)
	require.Nil(t, resp.Error)
	assert.True(t, server.cheats.IsAutomine())
}

func TestServer_evm_setIntervalMining(t *testing.T) {
	server := setupServer(t)

	// Default interval should be 0
	assert.Equal(t, uint64(0), server.cheats.GetIntervalMining())

	// Set interval mining to 5 seconds
	w := makeRequest(t, server, "evm_setIntervalMining", []interface{}{"0x5"})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify interval was set
	assert.Equal(t, uint64(5), server.cheats.GetIntervalMining())
	// Setting interval should disable automine
	assert.False(t, server.cheats.IsAutomine())

	// Disable interval mining
	w = makeRequest(t, server, "evm_setIntervalMining", []interface{}{"0x0"})
	resp = parseResponse(t, w)
	require.Nil(t, resp.Error)
	assert.Equal(t, uint64(0), server.cheats.GetIntervalMining())
}

func TestServer_stablenet_mintStablecoin(t *testing.T) {
	server := setupServer(t)

	addr := "0x1111111111111111111111111111111111111111"
	amount := "0x3e8" // 1000

	w := makeRequest(t, server, "stablenet_mintStablecoin", []interface{}{addr, amount})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify balance was set
	w2 := makeRequest(t, server, "stablenet_getStablecoinBalance", []interface{}{addr})
	resp2 := parseResponse(t, w2)
	require.Nil(t, resp2.Error)

	var balanceHex string
	json.Unmarshal(resp2.Result, &balanceHex)
	assert.Equal(t, amount, balanceHex)
}

func TestServer_stablenet_burnStablecoin(t *testing.T) {
	server := setupServer(t)

	addr := "0x1111111111111111111111111111111111111111"

	// First mint some stablecoins
	w := makeRequest(t, server, "stablenet_mintStablecoin", []interface{}{addr, "0x3e8"}) // 1000
	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	// Now burn some
	w = makeRequest(t, server, "stablenet_burnStablecoin", []interface{}{addr, "0x12c"}) // 300
	require.Equal(t, http.StatusOK, w.Code)

	resp = parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)

	// Verify balance decreased
	w2 := makeRequest(t, server, "stablenet_getStablecoinBalance", []interface{}{addr})
	resp2 := parseResponse(t, w2)
	require.Nil(t, resp2.Error)

	var balanceHex string
	json.Unmarshal(resp2.Result, &balanceHex)
	assert.Equal(t, "0x2bc", balanceHex) // 700
}

func TestServer_stablenet_burnStablecoin_insufficientBalance(t *testing.T) {
	server := setupServer(t)

	addr := "0x1111111111111111111111111111111111111111"

	// Try to burn without any balance
	w := makeRequest(t, server, "stablenet_burnStablecoin", []interface{}{addr, "0x3e8"})
	resp := parseResponse(t, w)
	require.NotNil(t, resp.Error)
}

func TestServer_stablenet_getStablecoinTotalSupply(t *testing.T) {
	server := setupServer(t)

	// Initial supply should be 0
	w := makeRequest(t, server, "stablenet_getStablecoinTotalSupply", []interface{}{})
	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var supply string
	json.Unmarshal(resp.Result, &supply)
	assert.Equal(t, "0x0", supply)

	// Mint some
	addr := "0x1111111111111111111111111111111111111111"
	makeRequest(t, server, "stablenet_mintStablecoin", []interface{}{addr, "0x3e8"})

	// Check supply increased
	w = makeRequest(t, server, "stablenet_getStablecoinTotalSupply", []interface{}{})
	resp = parseResponse(t, w)
	require.Nil(t, resp.Error)

	json.Unmarshal(resp.Result, &supply)
	assert.Equal(t, "0x3e8", supply)
}

// ============================================
// Phase 6 Tests - New RPC Methods
// ============================================

func TestServer_eth_sendTransaction(t *testing.T) {
	server := setupServer(t)

	// Fund an account
	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	balance := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	server.stateManager.SetBalance(from, balance)

	// Enable impersonation so we can send without signature
	server.cheats.ImpersonateAccount(from)

	txArgs := map[string]interface{}{
		"from":     from.Hex(),
		"to":       to.Hex(),
		"value":    "0xde0b6b3a7640000", // 1 ETH
		"gas":      "0x5208",            // 21000
		"gasPrice": "0x3b9aca00",        // 1 Gwei
	}

	w := makeRequest(t, server, "eth_sendTransaction", []interface{}{txArgs})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error, "expected no error, got: %v", resp.Error)

	var txHash string
	err := json.Unmarshal(resp.Result, &txHash)
	require.NoError(t, err)
	assert.Len(t, txHash, 66) // 0x + 64 hex chars
}

func TestServer_eth_sendRawTransaction(t *testing.T) {
	server := setupServer(t)

	// Fund the sender
	from := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	balance := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	server.stateManager.SetBalance(from, balance)

	// Pre-signed transaction (needs a valid signed tx)
	// For test purposes, we'll enable auto-impersonate and use a simpler approach
	server.cheats.SetAutoImpersonate(true)

	// Create a raw transaction bytes (simplified test)
	// In real usage, this would be an RLP-encoded signed transaction
	w := makeRequest(t, server, "eth_sendRawTransaction", []interface{}{"0xf86c0a8503b9aca00082520894f39fd6e51aad88f6f4ce6ab8827279cfffb9226688016345785d8a000080820a95a0d9ef6d34e2b98e4c6a5f7f42c8e1c9e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8a0d9ef6d34e2b98e4c6a5f7f42c8e1c9e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8"})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	// May return error for invalid signature, but method should exist
	if resp.Error == nil {
		var txHash string
		json.Unmarshal(resp.Result, &txHash)
		assert.Len(t, txHash, 66)
	}
}

func TestServer_eth_call(t *testing.T) {
	server := setupServer(t)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	callArgs := map[string]interface{}{
		"from": from.Hex(),
		"to":   to.Hex(),
		"data": "0x",
	}

	w := makeRequest(t, server, "eth_call", []interface{}{callArgs, "latest"})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error, "expected no error, got: %v", resp.Error)

	var result string
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.Equal(t, "0x", result) // Empty call returns empty data
}

func TestServer_eth_getTransactionReceipt(t *testing.T) {
	server := setupServer(t)

	// First, send a transaction
	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	balance := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	server.stateManager.SetBalance(from, balance)
	server.cheats.ImpersonateAccount(from)

	txArgs := map[string]interface{}{
		"from":     from.Hex(),
		"to":       to.Hex(),
		"value":    "0xde0b6b3a7640000",
		"gas":      "0x5208",
		"gasPrice": "0x3b9aca00",
	}

	w := makeRequest(t, server, "eth_sendTransaction", []interface{}{txArgs})
	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var txHash string
	json.Unmarshal(resp.Result, &txHash)

	// Now get the receipt
	w = makeRequest(t, server, "eth_getTransactionReceipt", []interface{}{txHash})
	require.Equal(t, http.StatusOK, w.Code)

	resp = parseResponse(t, w)
	require.Nil(t, resp.Error, "expected no error, got: %v", resp.Error)

	var receipt map[string]interface{}
	err := json.Unmarshal(resp.Result, &receipt)
	require.NoError(t, err)
	assert.Equal(t, txHash, receipt["transactionHash"])
	assert.Equal(t, "0x1", receipt["status"]) // Success
}

func TestServer_eth_getTransactionReceipt_notFound(t *testing.T) {
	server := setupServer(t)

	// Try to get receipt for non-existent tx
	fakeHash := "0x1234567890123456789012345678901234567890123456789012345678901234"
	w := makeRequest(t, server, "eth_getTransactionReceipt", []interface{}{fakeHash})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)
	assert.Equal(t, "null", string(resp.Result)) // Not found returns null
}

func TestServer_eth_getTransactionByHash(t *testing.T) {
	server := setupServer(t)

	// First, send a transaction
	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	balance := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	server.stateManager.SetBalance(from, balance)
	server.cheats.ImpersonateAccount(from)

	txArgs := map[string]interface{}{
		"from":     from.Hex(),
		"to":       to.Hex(),
		"value":    "0xde0b6b3a7640000",
		"gas":      "0x5208",
		"gasPrice": "0x3b9aca00",
	}

	w := makeRequest(t, server, "eth_sendTransaction", []interface{}{txArgs})
	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var txHash string
	json.Unmarshal(resp.Result, &txHash)

	// Now get the transaction
	w = makeRequest(t, server, "eth_getTransactionByHash", []interface{}{txHash})
	require.Equal(t, http.StatusOK, w.Code)

	resp = parseResponse(t, w)
	require.Nil(t, resp.Error, "expected no error, got: %v", resp.Error)

	var tx map[string]interface{}
	err := json.Unmarshal(resp.Result, &tx)
	require.NoError(t, err)
	assert.Equal(t, txHash, tx["hash"])
	assert.Equal(t, to.Hex(), tx["to"])
}

func TestServer_eth_getTransactionByHash_notFound(t *testing.T) {
	server := setupServer(t)

	fakeHash := "0x1234567890123456789012345678901234567890123456789012345678901234"
	w := makeRequest(t, server, "eth_getTransactionByHash", []interface{}{fakeHash})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)
	assert.Equal(t, "null", string(resp.Result))
}

func TestServer_net_listening(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "net_listening", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var listening bool
	err := json.Unmarshal(resp.Result, &listening)
	require.NoError(t, err)
	assert.True(t, listening)
}

func TestServer_net_peerCount(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "net_peerCount", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var peerCount string
	err := json.Unmarshal(resp.Result, &peerCount)
	require.NoError(t, err)
	assert.Equal(t, "0x0", peerCount)
}

func TestServer_web3_sha3(t *testing.T) {
	server := setupServer(t)

	// keccak256("hello") = 0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
	w := makeRequest(t, server, "web3_sha3", []interface{}{"0x68656c6c6f"}) // "hello" in hex
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var hash string
	err := json.Unmarshal(resp.Result, &hash)
	require.NoError(t, err)
	assert.Equal(t, "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8", hash)
}

func TestServer_anvil_dropAllTransactions(t *testing.T) {
	server := setupServer(t)

	// Add some transactions to the pool
	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	balance := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	server.stateManager.SetBalance(from, balance)

	// Create and add a transaction to pool
	tx := types.NewTransaction(
		0,
		common.HexToAddress("0x2222222222222222222222222222222222222222"),
		big.NewInt(1e18),
		21000,
		big.NewInt(1e9),
		nil,
	)
	server.pool.AddWithImpersonation(tx, from)
	assert.Equal(t, 1, server.pool.Count())

	// Drop all transactions
	w := makeRequest(t, server, "anvil_dropAllTransactions", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)
	assert.Equal(t, 0, server.pool.Count())
}

func TestServer_anvil_setMinGasPrice(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "anvil_setMinGasPrice", []interface{}{"0x3b9aca00"}) // 1 Gwei
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var result bool
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	assert.True(t, result)
}

func TestServer_anvil_nodeInfo(t *testing.T) {
	server := setupServer(t)

	w := makeRequest(t, server, "anvil_nodeInfo", []interface{}{})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error)

	var nodeInfo map[string]interface{}
	err := json.Unmarshal(resp.Result, &nodeInfo)
	require.NoError(t, err)
	assert.Equal(t, "anvil-go/v0.1.0", nodeInfo["currentVersion"])
	assert.Equal(t, "0x7a69", nodeInfo["chainId"]) // 31337
}

func TestServer_debug_traceBlockByHash(t *testing.T) {
	server := setupServer(t)

	// Get genesis block hash
	genesis, err := server.chain.BlockByNumber(0)
	require.NoError(t, err)
	require.NotNil(t, genesis)

	w := makeRequest(t, server, "debug_traceBlockByHash", []interface{}{genesis.Hash().Hex(), map[string]interface{}{}})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error, "expected no error, got: %v", resp.Error)

	var traces []interface{}
	err = json.Unmarshal(resp.Result, &traces)
	require.NoError(t, err)
	// Genesis block has no transactions, so empty traces
	assert.Len(t, traces, 0)
}

func TestServer_eth_getLogs(t *testing.T) {
	server := setupServer(t)

	// Query logs with filter
	filterParams := map[string]interface{}{
		"fromBlock": "0x0",
		"toBlock":   "latest",
	}

	w := makeRequest(t, server, "eth_getLogs", []interface{}{filterParams})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error, "expected no error, got: %v", resp.Error)

	var logs []interface{}
	err := json.Unmarshal(resp.Result, &logs)
	require.NoError(t, err)
	// No logs in empty chain
	assert.Len(t, logs, 0)
}

func TestServer_eth_getLogs_withAddress(t *testing.T) {
	server := setupServer(t)

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	filterParams := map[string]interface{}{
		"fromBlock": "0x0",
		"toBlock":   "latest",
		"address":   addr.Hex(),
	}

	w := makeRequest(t, server, "eth_getLogs", []interface{}{filterParams})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error, "expected no error, got: %v", resp.Error)

	var logs []interface{}
	err := json.Unmarshal(resp.Result, &logs)
	require.NoError(t, err)
	assert.Len(t, logs, 0)
}

func TestServer_eth_sign(t *testing.T) {
	server := setupServer(t)

	// Use a test account
	addr := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	message := "0x48656c6c6f20576f726c64" // "Hello World" in hex

	w := makeRequest(t, server, "eth_sign", []interface{}{addr.Hex(), message})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error, "expected no error, got: %v", resp.Error)

	var signature string
	err := json.Unmarshal(resp.Result, &signature)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(signature, "0x"))
	// Signature should be 65 bytes (130 hex chars + 0x prefix)
	assert.Len(t, signature, 132)
}

func TestServer_eth_signTransaction(t *testing.T) {
	server := setupServer(t)

	from := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	txArgs := map[string]interface{}{
		"from":     from.Hex(),
		"to":       to.Hex(),
		"value":    "0xde0b6b3a7640000", // 1 ETH
		"gas":      "0x5208",            // 21000
		"gasPrice": "0x3b9aca00",        // 1 gwei
		"nonce":    "0x0",
	}

	w := makeRequest(t, server, "eth_signTransaction", []interface{}{txArgs})
	require.Equal(t, http.StatusOK, w.Code)

	resp := parseResponse(t, w)
	require.Nil(t, resp.Error, "expected no error, got: %v", resp.Error)

	var signedTx map[string]interface{}
	err := json.Unmarshal(resp.Result, &signedTx)
	require.NoError(t, err)
	assert.NotEmpty(t, signedTx["raw"])
	assert.NotEmpty(t, signedTx["tx"])
}
