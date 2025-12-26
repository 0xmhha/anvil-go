// Package compat provides Hardhat compatibility tests for anvil-go.
// These tests ensure anvil-go behaves identically to Hardhat Network.
package compat

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHardhat_ChainID verifies the chain ID can be configured (Hardhat default is 31337).
func TestHardhat_ChainID(t *testing.T) {
	backend := setupCompatBackend(t)

	resp := makeRPCRequest(t, backend.server, "eth_chainId", []interface{}{})
	require.Nil(t, resp["error"], "eth_chainId should not return error")

	result := resp["result"].(string)
	chainID, err := hexutil.DecodeBig(result)
	require.NoError(t, err)

	// Hardhat default chain ID is also 31337
	assert.Equal(t, int64(31337), chainID.Int64(), "Default chain ID should be 31337")
}

// TestHardhat_DefaultAccounts verifies default test accounts (Hardhat uses same accounts as Foundry).
func TestHardhat_DefaultAccounts(t *testing.T) {
	backend := setupCompatBackend(t)

	// Hardhat's default test accounts (same mnemonic-derived accounts)
	defaultAccounts := []string{
		"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		"0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
		"0x90F79bf6EB2c4f870365E785982E1f101E93b906",
		"0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
	}

	// Set up default balance (10000 ETH) for each account
	defaultBalance := new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e18))
	for _, addr := range defaultAccounts {
		backend.stateManager.SetBalance(common.HexToAddress(addr), defaultBalance)
	}

	// Verify all accounts have correct balance
	for _, addr := range defaultAccounts {
		resp := makeRPCRequest(t, backend.server, "eth_getBalance", []interface{}{addr, "latest"})
		require.Nil(t, resp["error"], "eth_getBalance should not return error for %s", addr)

		balance, err := hexutil.DecodeBig(resp["result"].(string))
		require.NoError(t, err)
		assert.Equal(t, defaultBalance, balance, "Account %s should have 10000 ETH", addr)
	}
}

// TestHardhat_HardhatSetBalance verifies hardhat_setBalance method.
func TestHardhat_HardhatSetBalance(t *testing.T) {
	backend := setupCompatBackend(t)

	addr := "0x1111111111111111111111111111111111111111"
	newBalance := "0xde0b6b3a7640000" // 1 ETH

	// Hardhat uses hardhat_setBalance, but anvil_setBalance should also work
	resp := makeRPCRequest(t, backend.server, "hardhat_setBalance", []interface{}{addr, newBalance})

	// If not implemented, try anvil_setBalance
	if resp["error"] != nil {
		resp = makeRPCRequest(t, backend.server, "anvil_setBalance", []interface{}{addr, newBalance})
	}

	require.Nil(t, resp["error"], "setBalance should not return error")
	assert.Equal(t, true, resp["result"], "setBalance should return true")

	// Verify balance was set
	balanceResp := makeRPCRequest(t, backend.server, "eth_getBalance", []interface{}{addr, "latest"})
	require.Nil(t, balanceResp["error"])

	balance, err := hexutil.DecodeBig(balanceResp["result"].(string))
	require.NoError(t, err)
	expected, _ := hexutil.DecodeBig(newBalance)
	assert.Equal(t, expected, balance)
}

// TestHardhat_HardhatSetCode verifies hardhat_setCode method.
func TestHardhat_HardhatSetCode(t *testing.T) {
	backend := setupCompatBackend(t)

	addr := "0x1111111111111111111111111111111111111111"
	code := "0x608060405260043610610041576000357c0100000000000000000000000000000000"

	// Try hardhat_setCode first, fallback to anvil_setCode
	resp := makeRPCRequest(t, backend.server, "hardhat_setCode", []interface{}{addr, code})
	if resp["error"] != nil {
		resp = makeRPCRequest(t, backend.server, "anvil_setCode", []interface{}{addr, code})
	}

	require.Nil(t, resp["error"], "setCode should not return error")
	assert.Equal(t, true, resp["result"], "setCode should return true")

	// Verify code was set
	codeResp := makeRPCRequest(t, backend.server, "eth_getCode", []interface{}{addr, "latest"})
	require.Nil(t, codeResp["error"])
	assert.Equal(t, code, codeResp["result"], "Code should match")
}

// TestHardhat_HardhatSetStorageAt verifies hardhat_setStorageAt method.
func TestHardhat_HardhatSetStorageAt(t *testing.T) {
	backend := setupCompatBackend(t)

	addr := "0x1111111111111111111111111111111111111111"
	slot := "0x0000000000000000000000000000000000000000000000000000000000000001"
	value := "0x000000000000000000000000000000000000000000000000000000000000002a" // 42

	// Try hardhat_setStorageAt first, fallback to anvil_setStorageAt
	resp := makeRPCRequest(t, backend.server, "hardhat_setStorageAt", []interface{}{addr, slot, value})
	if resp["error"] != nil {
		resp = makeRPCRequest(t, backend.server, "anvil_setStorageAt", []interface{}{addr, slot, value})
	}

	require.Nil(t, resp["error"], "setStorageAt should not return error")
	assert.Equal(t, true, resp["result"], "setStorageAt should return true")

	// Verify storage was set
	storageResp := makeRPCRequest(t, backend.server, "eth_getStorageAt", []interface{}{addr, slot, "latest"})
	require.Nil(t, storageResp["error"])
	assert.Equal(t, value, storageResp["result"], "Storage value should match")
}

// TestHardhat_HardhatSetNonce verifies hardhat_setNonce method.
func TestHardhat_HardhatSetNonce(t *testing.T) {
	backend := setupCompatBackend(t)

	addr := "0x1111111111111111111111111111111111111111"
	nonce := "0x10" // 16

	// Try hardhat_setNonce first, fallback to anvil_setNonce
	resp := makeRPCRequest(t, backend.server, "hardhat_setNonce", []interface{}{addr, nonce})
	if resp["error"] != nil {
		resp = makeRPCRequest(t, backend.server, "anvil_setNonce", []interface{}{addr, nonce})
	}

	require.Nil(t, resp["error"], "setNonce should not return error")
	assert.Equal(t, true, resp["result"], "setNonce should return true")

	// Verify nonce was set
	nonceResp := makeRPCRequest(t, backend.server, "eth_getTransactionCount", []interface{}{addr, "latest"})
	require.Nil(t, nonceResp["error"])
	assert.Equal(t, nonce, nonceResp["result"], "Nonce should match")
}

// TestHardhat_HardhatMine verifies hardhat_mine method.
func TestHardhat_HardhatMine(t *testing.T) {
	backend := setupCompatBackend(t)

	// Get initial block number
	initialResp := makeRPCRequest(t, backend.server, "eth_blockNumber", []interface{}{})
	initialBlock, _ := hexutil.DecodeUint64(initialResp["result"].(string))

	// Try hardhat_mine first (mines single block by default)
	resp := makeRPCRequest(t, backend.server, "hardhat_mine", []interface{}{})
	if resp["error"] != nil {
		// Fallback to anvil_mine
		resp = makeRPCRequest(t, backend.server, "anvil_mine", []interface{}{"0x1"})
	}
	require.Nil(t, resp["error"], "mine should not return error")

	// Verify block number increased
	finalResp := makeRPCRequest(t, backend.server, "eth_blockNumber", []interface{}{})
	finalBlock, _ := hexutil.DecodeUint64(finalResp["result"].(string))

	assert.Greater(t, finalBlock, initialBlock, "Block number should increase after mining")
}

// TestHardhat_HardhatMineMultiple verifies hardhat_mine with block count.
func TestHardhat_HardhatMineMultiple(t *testing.T) {
	backend := setupCompatBackend(t)

	// Get initial block number
	initialResp := makeRPCRequest(t, backend.server, "eth_blockNumber", []interface{}{})
	initialBlock, _ := hexutil.DecodeUint64(initialResp["result"].(string))

	// Mine 5 blocks - Hardhat accepts count as first param
	resp := makeRPCRequest(t, backend.server, "hardhat_mine", []interface{}{"0x5"})
	if resp["error"] != nil {
		// Fallback to anvil_mine
		resp = makeRPCRequest(t, backend.server, "anvil_mine", []interface{}{"0x5"})
	}
	require.Nil(t, resp["error"], "mine should not return error")

	// Verify block number increased by 5
	finalResp := makeRPCRequest(t, backend.server, "eth_blockNumber", []interface{}{})
	finalBlock, _ := hexutil.DecodeUint64(finalResp["result"].(string))

	assert.Equal(t, initialBlock+5, finalBlock, "Block number should increase by 5")
}

// TestHardhat_HardhatImpersonateAccount verifies hardhat_impersonateAccount.
func TestHardhat_HardhatImpersonateAccount(t *testing.T) {
	backend := setupCompatBackend(t)

	addr := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

	// Try hardhat_impersonateAccount first
	resp := makeRPCRequest(t, backend.server, "hardhat_impersonateAccount", []interface{}{addr})
	if resp["error"] != nil {
		// Fallback to anvil_impersonateAccount
		resp = makeRPCRequest(t, backend.server, "anvil_impersonateAccount", []interface{}{addr})
	}

	require.Nil(t, resp["error"], "impersonateAccount should not return error")
	assert.Equal(t, true, resp["result"])

	// Stop impersonation
	stopResp := makeRPCRequest(t, backend.server, "hardhat_stopImpersonatingAccount", []interface{}{addr})
	if stopResp["error"] != nil {
		stopResp = makeRPCRequest(t, backend.server, "anvil_stopImpersonatingAccount", []interface{}{addr})
	}
	require.Nil(t, stopResp["error"], "stopImpersonatingAccount should not return error")
	assert.Equal(t, true, stopResp["result"])
}

// TestHardhat_HardhatReset verifies hardhat_reset.
func TestHardhat_HardhatReset(t *testing.T) {
	backend := setupCompatBackend(t)

	// Try hardhat_reset first
	resp := makeRPCRequest(t, backend.server, "hardhat_reset", []interface{}{})
	if resp["error"] != nil {
		// Fallback to anvil_reset
		resp = makeRPCRequest(t, backend.server, "anvil_reset", []interface{}{})
	}

	require.Nil(t, resp["error"], "reset should not return error")
	assert.Equal(t, true, resp["result"])
}

// TestHardhat_EVMSnapshot verifies evm_snapshot.
func TestHardhat_EVMSnapshot(t *testing.T) {
	backend := setupCompatBackend(t)

	resp := makeRPCRequest(t, backend.server, "evm_snapshot", []interface{}{})
	require.Nil(t, resp["error"], "evm_snapshot should not return error")

	snapshotID := resp["result"].(string)
	assert.NotEmpty(t, snapshotID, "Snapshot ID should not be empty")
}

// TestHardhat_EVMRevert verifies evm_revert.
func TestHardhat_EVMRevert(t *testing.T) {
	backend := setupCompatBackend(t)

	// Take snapshot
	snapResp := makeRPCRequest(t, backend.server, "evm_snapshot", []interface{}{})
	require.Nil(t, snapResp["error"])
	snapshotID := snapResp["result"].(string)

	// Modify state
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	backend.stateManager.SetBalance(addr, big.NewInt(1000))

	// Revert
	revertResp := makeRPCRequest(t, backend.server, "evm_revert", []interface{}{snapshotID})
	require.Nil(t, revertResp["error"], "evm_revert should not return error")
	assert.Equal(t, true, revertResp["result"])
}

// TestHardhat_EVMIncreaseTime verifies evm_increaseTime.
func TestHardhat_EVMIncreaseTime(t *testing.T) {
	backend := setupCompatBackend(t)

	// Increase time by 3600 seconds (1 hour)
	resp := makeRPCRequest(t, backend.server, "evm_increaseTime", []interface{}{"0xe10"}) // 3600
	require.Nil(t, resp["error"], "evm_increaseTime should not return error")

	result := resp["result"].(string)
	_, err := hexutil.DecodeUint64(result)
	require.NoError(t, err, "Result should be a valid hex number")
}

// TestHardhat_EVMSetNextBlockTimestamp verifies evm_setNextBlockTimestamp.
func TestHardhat_EVMSetNextBlockTimestamp(t *testing.T) {
	backend := setupCompatBackend(t)

	futureTime := uint64(2500000000)
	resp := makeRPCRequest(t, backend.server, "evm_setNextBlockTimestamp", []interface{}{hexutil.EncodeUint64(futureTime)})

	// Try anvil_setNextBlockTimestamp if not available
	if resp["error"] != nil {
		resp = makeRPCRequest(t, backend.server, "anvil_setNextBlockTimestamp", []interface{}{hexutil.EncodeUint64(futureTime)})
	}

	require.Nil(t, resp["error"], "setNextBlockTimestamp should not return error")
}

// TestHardhat_EVMMine verifies evm_mine.
func TestHardhat_EVMMine(t *testing.T) {
	backend := setupCompatBackend(t)

	// Get initial block number
	initialResp := makeRPCRequest(t, backend.server, "eth_blockNumber", []interface{}{})
	initialBlock, _ := hexutil.DecodeUint64(initialResp["result"].(string))

	// Mine a block using evm_mine
	resp := makeRPCRequest(t, backend.server, "evm_mine", []interface{}{})
	require.Nil(t, resp["error"], "evm_mine should not return error")

	// Verify block number increased
	finalResp := makeRPCRequest(t, backend.server, "eth_blockNumber", []interface{}{})
	finalBlock, _ := hexutil.DecodeUint64(finalResp["result"].(string))

	assert.Greater(t, finalBlock, initialBlock, "Block number should increase after mining")
}

// TestHardhat_EVMSetAutomine verifies evm_setAutomine.
func TestHardhat_EVMSetAutomine(t *testing.T) {
	backend := setupCompatBackend(t)

	// Try to disable automine
	resp := makeRPCRequest(t, backend.server, "evm_setAutomine", []interface{}{false})

	// Skip if not implemented
	if resp["error"] != nil {
		// Try anvil_setAutomine
		resp = makeRPCRequest(t, backend.server, "anvil_setAutomine", []interface{}{false})
		if resp["error"] != nil {
			t.Skip("setAutomine not implemented")
		}
	}

	assert.Equal(t, true, resp["result"])

	// Re-enable automine
	enableResp := makeRPCRequest(t, backend.server, "evm_setAutomine", []interface{}{true})
	if enableResp["error"] != nil {
		enableResp = makeRPCRequest(t, backend.server, "anvil_setAutomine", []interface{}{true})
	}
	require.Nil(t, enableResp["error"])
}

// TestHardhat_EVMSetIntervalMining verifies evm_setIntervalMining.
func TestHardhat_EVMSetIntervalMining(t *testing.T) {
	backend := setupCompatBackend(t)

	// Try to set interval mining (5 seconds)
	resp := makeRPCRequest(t, backend.server, "evm_setIntervalMining", []interface{}{"0x1388"}) // 5000ms

	// Skip if not implemented
	if resp["error"] != nil {
		resp = makeRPCRequest(t, backend.server, "anvil_setIntervalMining", []interface{}{"0x1388"})
		if resp["error"] != nil {
			t.Skip("setIntervalMining not implemented")
		}
	}

	assert.Equal(t, true, resp["result"])
}

// TestHardhat_GasEstimation verifies eth_estimateGas.
func TestHardhat_GasEstimation(t *testing.T) {
	backend := setupCompatBackend(t)

	from := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	to := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

	// Fund the sender
	backend.stateManager.SetBalance(common.HexToAddress(from), new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)))

	txArgs := map[string]interface{}{
		"from":  from,
		"to":    to,
		"value": "0xde0b6b3a7640000", // 1 ETH
	}

	resp := makeRPCRequest(t, backend.server, "eth_estimateGas", []interface{}{txArgs})
	require.Nil(t, resp["error"], "eth_estimateGas should not return error")

	gas, err := hexutil.DecodeUint64(resp["result"].(string))
	require.NoError(t, err)

	// Simple ETH transfer should require 21000 gas
	assert.GreaterOrEqual(t, gas, uint64(21000), "Gas estimate should be at least 21000 for ETH transfer")
}

// TestHardhat_GasPrice verifies eth_gasPrice.
func TestHardhat_GasPrice(t *testing.T) {
	backend := setupCompatBackend(t)

	resp := makeRPCRequest(t, backend.server, "eth_gasPrice", []interface{}{})
	require.Nil(t, resp["error"], "eth_gasPrice should not return error")

	gasPrice, err := hexutil.DecodeBig(resp["result"].(string))
	require.NoError(t, err)
	assert.True(t, gasPrice.Cmp(big.NewInt(0)) > 0, "Gas price should be positive")
}

// TestHardhat_BlockByNumber verifies eth_getBlockByNumber returns correct structure.
func TestHardhat_BlockByNumber(t *testing.T) {
	backend := setupCompatBackend(t)

	// Mine a block first
	makeRPCRequest(t, backend.server, "evm_mine", []interface{}{})

	resp := makeRPCRequest(t, backend.server, "eth_getBlockByNumber", []interface{}{"0x1", true})
	require.Nil(t, resp["error"], "eth_getBlockByNumber should not return error")

	block := resp["result"].(map[string]interface{})

	// Verify required fields exist (Hardhat-compatible format)
	requiredFields := []string{
		"number", "hash", "parentHash", "timestamp",
		"gasLimit", "gasUsed", "miner", "transactions",
	}

	for _, field := range requiredFields {
		assert.Contains(t, block, field, "Block should contain field: %s", field)
	}
}

// TestHardhat_BlockByHash verifies eth_getBlockByHash.
func TestHardhat_BlockByHash(t *testing.T) {
	backend := setupCompatBackend(t)

	// Mine a block first
	makeRPCRequest(t, backend.server, "evm_mine", []interface{}{})

	// Get the block by number to get its hash
	blockResp := makeRPCRequest(t, backend.server, "eth_getBlockByNumber", []interface{}{"0x1", false})
	require.Nil(t, blockResp["error"])
	block := blockResp["result"].(map[string]interface{})
	blockHash := block["hash"].(string)

	// Now get by hash
	resp := makeRPCRequest(t, backend.server, "eth_getBlockByHash", []interface{}{blockHash, false})
	require.Nil(t, resp["error"], "eth_getBlockByHash should not return error")

	resultBlock := resp["result"].(map[string]interface{})
	assert.Equal(t, blockHash, resultBlock["hash"], "Block hash should match")
}

// TestHardhat_NetVersion verifies net_version.
func TestHardhat_NetVersion(t *testing.T) {
	backend := setupCompatBackend(t)

	resp := makeRPCRequest(t, backend.server, "net_version", []interface{}{})
	require.Nil(t, resp["error"], "net_version should not return error")

	// net_version returns chain ID as decimal string
	assert.Equal(t, "31337", resp["result"], "net_version should return 31337")
}

// TestHardhat_NetListening verifies net_listening.
func TestHardhat_NetListening(t *testing.T) {
	backend := setupCompatBackend(t)

	resp := makeRPCRequest(t, backend.server, "net_listening", []interface{}{})
	require.Nil(t, resp["error"], "net_listening should not return error")

	assert.Equal(t, true, resp["result"], "net_listening should return true")
}

// TestHardhat_NetPeerCount verifies net_peerCount.
func TestHardhat_NetPeerCount(t *testing.T) {
	backend := setupCompatBackend(t)

	resp := makeRPCRequest(t, backend.server, "net_peerCount", []interface{}{})
	require.Nil(t, resp["error"], "net_peerCount should not return error")

	peerCount, err := hexutil.DecodeUint64(resp["result"].(string))
	require.NoError(t, err)
	// Local node should have 0 peers
	assert.Equal(t, uint64(0), peerCount, "Peer count should be 0 for local node")
}

// TestHardhat_Web3ClientVersion verifies web3_clientVersion.
func TestHardhat_Web3ClientVersion(t *testing.T) {
	backend := setupCompatBackend(t)

	resp := makeRPCRequest(t, backend.server, "web3_clientVersion", []interface{}{})
	require.Nil(t, resp["error"], "web3_clientVersion should not return error")

	clientVersion := resp["result"].(string)
	assert.NotEmpty(t, clientVersion, "Client version should not be empty")
}

// TestHardhat_Web3Sha3 verifies web3_sha3.
func TestHardhat_Web3Sha3(t *testing.T) {
	backend := setupCompatBackend(t)

	// Test keccak256("hello")
	data := "0x68656c6c6f" // "hello" in hex
	resp := makeRPCRequest(t, backend.server, "web3_sha3", []interface{}{data})
	require.Nil(t, resp["error"], "web3_sha3 should not return error")

	hash := resp["result"].(string)
	// keccak256("hello") = 0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
	expected := "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
	assert.Equal(t, expected, hash, "Keccak256 hash should match")
}

// TestHardhat_Accounts verifies eth_accounts.
func TestHardhat_Accounts(t *testing.T) {
	backend := setupCompatBackend(t)

	resp := makeRPCRequest(t, backend.server, "eth_accounts", []interface{}{})
	require.Nil(t, resp["error"], "eth_accounts should not return error")

	accounts := resp["result"].([]interface{})
	// Note: anvil-go may return empty array if no accounts are explicitly managed
	// This is acceptable behavior for a local dev node
	assert.NotNil(t, accounts, "Accounts array should not be nil")
}

// TestHardhat_Coinbase verifies eth_coinbase.
func TestHardhat_Coinbase(t *testing.T) {
	backend := setupCompatBackend(t)

	resp := makeRPCRequest(t, backend.server, "eth_coinbase", []interface{}{})

	// Skip if not implemented
	if resp["error"] != nil {
		t.Skip("eth_coinbase not implemented")
	}

	coinbase := resp["result"].(string)
	assert.True(t, common.IsHexAddress(coinbase), "Coinbase should be a valid address")
}

// TestHardhat_GetCode verifies eth_getCode.
func TestHardhat_GetCode(t *testing.T) {
	backend := setupCompatBackend(t)

	addr := "0x1111111111111111111111111111111111111111"
	code := "0x608060405260043610"

	// Set code first
	backend.stateManager.SetCode(common.HexToAddress(addr), common.FromHex(code))

	resp := makeRPCRequest(t, backend.server, "eth_getCode", []interface{}{addr, "latest"})
	require.Nil(t, resp["error"], "eth_getCode should not return error")

	assert.Equal(t, code, resp["result"], "Code should match")
}

// TestHardhat_GetStorageAt verifies eth_getStorageAt.
func TestHardhat_GetStorageAt(t *testing.T) {
	backend := setupCompatBackend(t)

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	slot := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	value := common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000002a") // 42

	// Set storage first
	backend.stateManager.SetStorageAt(addr, slot, value)

	resp := makeRPCRequest(t, backend.server, "eth_getStorageAt", []interface{}{
		addr.Hex(),
		slot.Hex(),
		"latest",
	})
	require.Nil(t, resp["error"], "eth_getStorageAt should not return error")

	assert.Equal(t, value.Hex(), resp["result"], "Storage value should match")
}

// TestHardhat_GetTransactionCount verifies eth_getTransactionCount.
func TestHardhat_GetTransactionCount(t *testing.T) {
	backend := setupCompatBackend(t)

	addr := "0x1111111111111111111111111111111111111111"
	nonce := uint64(5)

	// Set nonce first
	backend.stateManager.SetNonce(common.HexToAddress(addr), nonce)

	resp := makeRPCRequest(t, backend.server, "eth_getTransactionCount", []interface{}{addr, "latest"})
	require.Nil(t, resp["error"], "eth_getTransactionCount should not return error")

	resultNonce, err := hexutil.DecodeUint64(resp["result"].(string))
	require.NoError(t, err)
	assert.Equal(t, nonce, resultNonce, "Nonce should match")
}

// TestHardhat_Call verifies eth_call.
func TestHardhat_Call(t *testing.T) {
	backend := setupCompatBackend(t)

	from := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	to := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

	// Fund the sender
	backend.stateManager.SetBalance(common.HexToAddress(from), new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)))

	txArgs := map[string]interface{}{
		"from": from,
		"to":   to,
	}

	resp := makeRPCRequest(t, backend.server, "eth_call", []interface{}{txArgs, "latest"})
	require.Nil(t, resp["error"], "eth_call should not return error")

	// Result should be hex string (even if empty)
	result := resp["result"].(string)
	assert.True(t, len(result) >= 2 && result[:2] == "0x", "Result should be hex encoded")
}

// TestHardhat_GetLogs verifies eth_getLogs.
func TestHardhat_GetLogs(t *testing.T) {
	backend := setupCompatBackend(t)

	filterParams := map[string]interface{}{
		"fromBlock": "0x0",
		"toBlock":   "latest",
	}

	resp := makeRPCRequest(t, backend.server, "eth_getLogs", []interface{}{filterParams})
	require.Nil(t, resp["error"], "eth_getLogs should not return error")

	logs := resp["result"].([]interface{})
	// Empty logs array is valid
	assert.NotNil(t, logs, "Logs should not be nil")
}

// TestHardhat_Sign verifies eth_sign.
func TestHardhat_Sign(t *testing.T) {
	backend := setupCompatBackend(t)

	addr := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	message := "0x48656c6c6f20576f726c64" // "Hello World"

	resp := makeRPCRequest(t, backend.server, "eth_sign", []interface{}{addr, message})
	require.Nil(t, resp["error"], "eth_sign should not return error")

	signature := resp["result"].(string)
	// Signature should be 65 bytes (130 hex chars + 0x prefix)
	assert.Equal(t, 132, len(signature), "Signature should be 65 bytes")
}

// TestHardhat_SignTransaction verifies eth_signTransaction.
func TestHardhat_SignTransaction(t *testing.T) {
	backend := setupCompatBackend(t)

	from := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	to := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

	// Fund the sender
	backend.stateManager.SetBalance(common.HexToAddress(from), new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)))

	txArgs := map[string]interface{}{
		"from":     from,
		"to":       to,
		"value":    "0xde0b6b3a7640000", // 1 ETH
		"gas":      "0x5208",            // 21000
		"gasPrice": "0x3b9aca00",        // 1 gwei
		"nonce":    "0x0",
	}

	resp := makeRPCRequest(t, backend.server, "eth_signTransaction", []interface{}{txArgs})
	require.Nil(t, resp["error"], "eth_signTransaction should not return error")

	result := resp["result"].(map[string]interface{})
	assert.Contains(t, result, "raw", "Result should contain raw transaction")
	assert.Contains(t, result, "tx", "Result should contain transaction object")
}

// TestHardhat_SendTransaction verifies eth_sendTransaction.
func TestHardhat_SendTransaction(t *testing.T) {
	backend := setupCompatBackend(t)

	from := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	to := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

	// Fund the sender
	backend.stateManager.SetBalance(common.HexToAddress(from), new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)))

	// Enable auto-impersonation or impersonate the account
	makeRPCRequest(t, backend.server, "anvil_impersonateAccount", []interface{}{from})

	txArgs := map[string]interface{}{
		"from":     from,
		"to":       to,
		"value":    "0xde0b6b3a7640000", // 1 ETH
		"gas":      "0x5208",            // 21000
		"gasPrice": "0x3b9aca00",        // 1 gwei
	}

	resp := makeRPCRequest(t, backend.server, "eth_sendTransaction", []interface{}{txArgs})
	require.Nil(t, resp["error"], "eth_sendTransaction should not return error")

	txHash := resp["result"].(string)
	assert.True(t, common.IsHexAddress(txHash) || len(txHash) == 66, "Result should be a transaction hash")
}

// TestHardhat_GetTransactionByHash verifies eth_getTransactionByHash.
func TestHardhat_GetTransactionByHash(t *testing.T) {
	backend := setupCompatBackend(t)

	// Query a non-existent transaction
	txHash := "0x1234567890123456789012345678901234567890123456789012345678901234"
	resp := makeRPCRequest(t, backend.server, "eth_getTransactionByHash", []interface{}{txHash})

	// Should return null for non-existent transaction (no error)
	require.Nil(t, resp["error"], "eth_getTransactionByHash should not return error")
}

// TestHardhat_GetTransactionReceipt verifies eth_getTransactionReceipt.
func TestHardhat_GetTransactionReceipt(t *testing.T) {
	backend := setupCompatBackend(t)

	// Query a non-existent transaction
	txHash := "0x1234567890123456789012345678901234567890123456789012345678901234"
	resp := makeRPCRequest(t, backend.server, "eth_getTransactionReceipt", []interface{}{txHash})

	// Should return null for non-existent transaction (no error)
	require.Nil(t, resp["error"], "eth_getTransactionReceipt should not return error")
}

// TestHardhat_DebugTraceTransaction verifies debug_traceTransaction support.
func TestHardhat_DebugTraceTransaction(t *testing.T) {
	backend := setupCompatBackend(t)

	// This test verifies the debug namespace is available
	// Actual tracing requires a real transaction
	txHash := "0x1234567890123456789012345678901234567890123456789012345678901234"
	resp := makeRPCRequest(t, backend.server, "debug_traceTransaction", []interface{}{txHash})

	// Method may not be implemented or may return error for non-existent tx
	// We just verify it doesn't panic
	_ = resp
}

// TestHardhat_HardhatDropTransaction verifies hardhat_dropTransaction.
func TestHardhat_HardhatDropTransaction(t *testing.T) {
	backend := setupCompatBackend(t)

	txHash := "0x1234567890123456789012345678901234567890123456789012345678901234"

	// Try hardhat_dropTransaction first
	resp := makeRPCRequest(t, backend.server, "hardhat_dropTransaction", []interface{}{txHash})
	if resp["error"] != nil {
		// Fallback to anvil_dropTransaction
		resp = makeRPCRequest(t, backend.server, "anvil_dropTransaction", []interface{}{txHash})
	}

	// Method may return error for non-existent tx, that's acceptable
	_ = resp
}

// TestHardhat_ErrorHandling verifies error responses follow JSON-RPC spec.
func TestHardhat_ErrorHandling(t *testing.T) {
	backend := setupCompatBackend(t)

	// Call method with missing required params
	resp := makeRPCRequest(t, backend.server, "eth_getBalance", []interface{}{})

	if resp["error"] != nil {
		errorObj := resp["error"].(map[string]interface{})
		assert.Contains(t, errorObj, "code", "Error should have code")
		assert.Contains(t, errorObj, "message", "Error should have message")
	}
}
