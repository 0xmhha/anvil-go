// Package rpc provides JSON-RPC server implementation.
package rpc

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/stable-net/anvil-go/pkg/blockchain"
	"github.com/stable-net/anvil-go/pkg/cheats"
	"github.com/stable-net/anvil-go/pkg/miner"
	"github.com/stable-net/anvil-go/pkg/snapshot"
	"github.com/stable-net/anvil-go/pkg/stablenet"
	"github.com/stable-net/anvil-go/pkg/state"
	"github.com/stable-net/anvil-go/pkg/tracing"
	"github.com/stable-net/anvil-go/pkg/txpool"
)

// JSON-RPC error codes.
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternal       = -32603
)

// Version information.
const (
	ClientVersion = "anvil-go/v0.1.0"
)

// Request represents a JSON-RPC request.
type Request struct {
	Jsonrpc string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// Response represents a JSON-RPC response.
type Response struct {
	Jsonrpc string       `json:"jsonrpc"`
	ID      interface{}  `json:"id"`
	Result  interface{}  `json:"result,omitempty"`
	Error   *ErrorObject `json:"error,omitempty"`
}

// ErrorObject represents a JSON-RPC error.
type ErrorObject struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Server implements an Ethereum JSON-RPC server.
type Server struct {
	chain        *blockchain.Chain
	pool         *txpool.InMemoryPool
	stateManager *state.InMemoryManager
	miner        *miner.SimpleMiner
	cheats       *cheats.Manager
	snapshots    *snapshot.Manager
	validators   *stablenet.ValidatorManager
	stablecoin   *stablenet.StablecoinManager
	chainID      *big.Int

	accounts    []common.Address
	privateKeys map[common.Address][]byte

	mu sync.RWMutex
}

// NewServer creates a new RPC server.
func NewServer(
	chain *blockchain.Chain,
	pool *txpool.InMemoryPool,
	stateManager *state.InMemoryManager,
	m *miner.SimpleMiner,
	chainID *big.Int,
) *Server {
	cheatsManager := cheats.NewManager(stateManager)
	snapshotManager := snapshot.NewManager(stateManager, chain, pool)
	validatorManager := stablenet.NewValidatorManager()
	stablecoinManager := stablenet.NewStablecoinManager()

	return &Server{
		chain:        chain,
		pool:         pool,
		stateManager: stateManager,
		miner:        m,
		cheats:       cheatsManager,
		snapshots:    snapshotManager,
		validators:   validatorManager,
		stablecoin:   stablecoinManager,
		chainID:      chainID,
		accounts:     []common.Address{},
		privateKeys:  make(map[common.Address][]byte),
	}
}

// ServeHTTP handles HTTP requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, nil, ErrCodeParseError, "Failed to read request body")
		return
	}

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, nil, ErrCodeParseError, "Parse error")
		return
	}

	result, rpcErr := s.handleMethod(req.Method, req.Params)
	if rpcErr != nil {
		s.writeError(w, req.ID, rpcErr.Code, rpcErr.Message)
		return
	}

	// Handle nil result specially to output "null" instead of omitting
	var resp interface{}
	if result == nil {
		resp = struct {
			Jsonrpc string      `json:"jsonrpc"`
			ID      interface{} `json:"id"`
			Result  interface{} `json:"result"`
		}{
			Jsonrpc: "2.0",
			ID:      req.ID,
			Result:  nil,
		}
	} else {
		resp = Response{
			Jsonrpc: "2.0",
			ID:      req.ID,
			Result:  result,
		}
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *Server) writeError(w http.ResponseWriter, id interface{}, code int, message string) {
	resp := Response{
		Jsonrpc: "2.0",
		ID:      id,
		Error: &ErrorObject{
			Code:    code,
			Message: message,
		},
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleMethod(method string, params json.RawMessage) (interface{}, *ErrorObject) {
	switch method {
	// eth_* methods
	case "eth_chainId":
		return s.ethChainID()
	case "eth_blockNumber":
		return s.ethBlockNumber()
	case "eth_getBalance":
		return s.ethGetBalance(params)
	case "eth_getTransactionCount":
		return s.ethGetTransactionCount(params)
	case "eth_getCode":
		return s.ethGetCode(params)
	case "eth_getStorageAt":
		return s.ethGetStorageAt(params)
	case "eth_getBlockByNumber":
		return s.ethGetBlockByNumber(params)
	case "eth_getBlockByHash":
		return s.ethGetBlockByHash(params)
	case "eth_gasPrice":
		return s.ethGasPrice()
	case "eth_estimateGas":
		return s.ethEstimateGas(params)
	case "eth_accounts":
		return s.ethAccounts()
	case "net_version":
		return s.netVersion()
	case "net_listening":
		return s.netListening()
	case "net_peerCount":
		return s.netPeerCount()
	case "web3_clientVersion":
		return s.web3ClientVersion()
	case "web3_sha3":
		return s.web3Sha3(params)
	case "eth_sendTransaction":
		return s.ethSendTransaction(params)
	case "eth_sendRawTransaction":
		return s.ethSendRawTransaction(params)
	case "eth_call":
		return s.ethCall(params)
	case "eth_getTransactionReceipt":
		return s.ethGetTransactionReceipt(params)
	case "eth_getTransactionByHash":
		return s.ethGetTransactionByHash(params)
	case "eth_getLogs":
		return s.ethGetLogs(params)
	case "eth_sign":
		return s.ethSign(params)
	case "eth_signTransaction":
		return s.ethSignTransaction(params)

	// anvil_* methods
	case "anvil_setBalance":
		return s.anvilSetBalance(params)
	case "anvil_setNonce":
		return s.anvilSetNonce(params)
	case "anvil_setCode":
		return s.anvilSetCode(params)
	case "anvil_setStorageAt":
		return s.anvilSetStorageAt(params)
	case "anvil_impersonateAccount":
		return s.anvilImpersonateAccount(params)
	case "anvil_stopImpersonatingAccount":
		return s.anvilStopImpersonatingAccount(params)
	case "anvil_autoImpersonateAccount":
		return s.anvilAutoImpersonateAccount(params)
	case "anvil_mine":
		return s.anvilMine(params)
	case "anvil_snapshot":
		return s.anvilSnapshot()
	case "anvil_revert":
		return s.anvilRevert(params)
	case "anvil_increaseTime":
		return s.anvilIncreaseTime(params)
	case "anvil_setNextBlockTimestamp":
		return s.anvilSetNextBlockTimestamp(params)
	case "anvil_setNextBlockBaseFee":
		return s.anvilSetNextBlockBaseFee(params)
	case "anvil_setCoinbase":
		return s.anvilSetCoinbase(params)
	case "anvil_reset":
		return s.anvilReset()
	case "anvil_dumpState":
		return s.anvilDumpState()
	case "anvil_loadState":
		return s.anvilLoadState(params)
	case "anvil_dropTransaction":
		return s.anvilDropTransaction(params)
	case "anvil_setAutomine":
		return s.evmSetAutomine(params)
	case "anvil_setIntervalMining":
		return s.evmSetIntervalMining(params)
	case "anvil_dropAllTransactions":
		return s.anvilDropAllTransactions()
	case "anvil_setMinGasPrice":
		return s.anvilSetMinGasPrice(params)
	case "anvil_nodeInfo":
		return s.anvilNodeInfo()

	// evm_* methods (aliases)
	case "evm_snapshot":
		return s.anvilSnapshot()
	case "evm_revert":
		return s.anvilRevert(params)
	case "evm_increaseTime":
		return s.anvilIncreaseTime(params)
	case "evm_setNextBlockTimestamp":
		return s.anvilSetNextBlockTimestamp(params)
	case "evm_mine":
		return s.anvilMine(params)
	case "evm_setAutomine":
		return s.evmSetAutomine(params)
	case "evm_setIntervalMining":
		return s.evmSetIntervalMining(params)

	// stablenet_* methods
	case "stablenet_addValidator":
		return s.stablenetAddValidator(params)
	case "stablenet_removeValidator":
		return s.stablenetRemoveValidator(params)
	case "stablenet_getValidators":
		return s.stablenetGetValidators()
	case "stablenet_setProposer":
		return s.stablenetSetProposer(params)
	case "stablenet_getProposer":
		return s.stablenetGetProposer(params)
	case "stablenet_setGasTip":
		return s.stablenetSetGasTip(params)
	case "stablenet_getGasTip":
		return s.stablenetGetGasTip()
	case "stablenet_mintStablecoin":
		return s.stablenetMintStablecoin(params)
	case "stablenet_burnStablecoin":
		return s.stablenetBurnStablecoin(params)
	case "stablenet_getStablecoinBalance":
		return s.stablenetGetStablecoinBalance(params)
	case "stablenet_getStablecoinTotalSupply":
		return s.stablenetGetStablecoinTotalSupply()

	// debug_* methods
	case "debug_traceTransaction":
		return s.debugTraceTransaction(params)
	case "debug_traceCall":
		return s.debugTraceCall(params)
	case "debug_traceBlockByNumber":
		return s.debugTraceBlockByNumber(params)
	case "debug_traceBlockByHash":
		return s.debugTraceBlockByHash(params)

	default:
		return nil, &ErrorObject{Code: ErrCodeMethodNotFound, Message: "Method not found"}
	}
}

// eth_chainId returns the chain ID.
func (s *Server) ethChainID() (interface{}, *ErrorObject) {
	return hexutil.EncodeBig(s.chainID), nil
}

// eth_blockNumber returns the current block number.
func (s *Server) ethBlockNumber() (interface{}, *ErrorObject) {
	blockNum := s.chain.BlockNumber()
	return hexutil.EncodeUint64(blockNum), nil
}

// eth_getBalance returns the balance of an account.
func (s *Server) ethGetBalance(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	addr := common.HexToAddress(addrStr)
	balance := s.stateManager.GetBalance(addr)
	return hexutil.EncodeBig(balance), nil
}

// eth_getTransactionCount returns the nonce of an account.
func (s *Server) ethGetTransactionCount(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	addr := common.HexToAddress(addrStr)
	nonce := s.stateManager.GetNonce(addr)
	return hexutil.EncodeUint64(nonce), nil
}

// eth_getCode returns the code of a contract.
func (s *Server) ethGetCode(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	addr := common.HexToAddress(addrStr)
	code := s.stateManager.GetCode(addr)
	if code == nil {
		return "0x", nil
	}
	return hexutil.Encode(code), nil
}

// eth_getStorageAt returns the value at a storage slot.
func (s *Server) ethGetStorageAt(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 3 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	slotStr, ok := args[1].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid slot"}
	}

	addr := common.HexToAddress(addrStr)
	slot := common.HexToHash(slotStr)
	value := s.stateManager.GetStorageAt(addr, slot)
	return value.Hex(), nil
}

// eth_getBlockByNumber returns a block by number.
func (s *Server) ethGetBlockByNumber(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	blockNumStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid block number"}
	}

	fullTx, _ := args[1].(bool)

	var blockNum uint64
	if blockNumStr == "latest" || blockNumStr == "pending" {
		blockNum = s.chain.BlockNumber()
	} else if blockNumStr == "earliest" {
		blockNum = 0
	} else {
		num, err := hexutil.DecodeUint64(blockNumStr)
		if err != nil {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid block number"}
		}
		blockNum = num
	}

	block, err := s.chain.BlockByNumber(blockNum)
	if err != nil {
		return nil, nil // Return null for not found
	}

	return s.formatBlock(block, fullTx), nil
}

// eth_getBlockByHash returns a block by hash.
func (s *Server) ethGetBlockByHash(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	hashStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid hash"}
	}

	fullTx, _ := args[1].(bool)

	hash := common.HexToHash(hashStr)
	block, err := s.chain.BlockByHash(hash)
	if err != nil {
		return nil, nil // Return null for not found
	}

	return s.formatBlock(block, fullTx), nil
}

// eth_gasPrice returns the current gas price.
func (s *Server) ethGasPrice() (interface{}, *ErrorObject) {
	// Return 1 gwei as default
	gasPrice := big.NewInt(1e9)
	return hexutil.EncodeBig(gasPrice), nil
}

// eth_estimateGas estimates the gas for a transaction.
func (s *Server) ethEstimateGas(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	callParams, ok := args[0].(map[string]interface{})
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid call params"}
	}

	// Simple estimation: 21000 for simple transfers
	_, hasData := callParams["data"]
	if !hasData {
		return hexutil.EncodeUint64(21000), nil
	}

	// For contract calls, return a higher estimate
	return hexutil.EncodeUint64(100000), nil
}

// eth_accounts returns the list of accounts.
func (s *Server) ethAccounts() (interface{}, *ErrorObject) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	accounts := make([]string, len(s.accounts))
	for i, addr := range s.accounts {
		accounts[i] = addr.Hex()
	}
	return accounts, nil
}

// net_version returns the network ID.
func (s *Server) netVersion() (interface{}, *ErrorObject) {
	return s.chainID.String(), nil
}

// web3_clientVersion returns the client version.
func (s *Server) web3ClientVersion() (interface{}, *ErrorObject) {
	return ClientVersion, nil
}

// formatBlock formats a block for JSON-RPC response.
func (s *Server) formatBlock(block *types.Block, fullTx bool) map[string]interface{} {
	result := map[string]interface{}{
		"number":           hexutil.EncodeUint64(block.NumberU64()),
		"hash":             block.Hash().Hex(),
		"parentHash":       block.ParentHash().Hex(),
		"timestamp":        hexutil.EncodeUint64(block.Time()),
		"gasLimit":         hexutil.EncodeUint64(block.GasLimit()),
		"gasUsed":          hexutil.EncodeUint64(block.GasUsed()),
		"miner":            block.Coinbase().Hex(),
		"difficulty":       hexutil.EncodeBig(block.Difficulty()),
		"nonce":            "0x0000000000000000",
		"mixHash":          common.Hash{}.Hex(),
		"sha3Uncles":       common.Hash{}.Hex(),
		"logsBloom":        fmt.Sprintf("0x%0512x", 0),
		"transactionsRoot": common.Hash{}.Hex(),
		"stateRoot":        common.Hash{}.Hex(),
		"receiptsRoot":     common.Hash{}.Hex(),
		"extraData":        "0x",
		"size":             "0x0",
		"uncles":           []string{},
	}

	if fullTx {
		result["transactions"] = []interface{}{}
	} else {
		txHashes := make([]string, len(block.Transactions()))
		for i, tx := range block.Transactions() {
			txHashes[i] = tx.Hash().Hex()
		}
		result["transactions"] = txHashes
	}

	return result
}

// SetAccounts sets the list of accounts.
func (s *Server) SetAccounts(accounts []common.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts = accounts
}

// anvil_setBalance sets the balance of an account.
func (s *Server) anvilSetBalance(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	balanceStr, ok := args[1].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid balance"}
	}

	addr := common.HexToAddress(addrStr)
	balance, err := hexutil.DecodeBig(balanceStr)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid balance format"}
	}

	if err := s.cheats.SetBalance(addr, balance); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// anvil_setNonce sets the nonce of an account.
func (s *Server) anvilSetNonce(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	nonceStr, ok := args[1].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid nonce"}
	}

	addr := common.HexToAddress(addrStr)
	nonce, err := hexutil.DecodeUint64(nonceStr)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid nonce format"}
	}

	if err := s.cheats.SetNonce(addr, nonce); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// anvil_setCode sets the code of a contract.
func (s *Server) anvilSetCode(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	codeStr, ok := args[1].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid code"}
	}

	addr := common.HexToAddress(addrStr)
	code, err := hexutil.Decode(codeStr)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid code format"}
	}

	if err := s.cheats.SetCode(addr, code); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// anvil_setStorageAt sets the storage value at a slot.
func (s *Server) anvilSetStorageAt(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 3 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	slotStr, ok := args[1].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid slot"}
	}

	valueStr, ok := args[2].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid value"}
	}

	addr := common.HexToAddress(addrStr)
	slot := common.HexToHash(slotStr)
	value := common.HexToHash(valueStr)

	if err := s.cheats.SetStorageAt(addr, slot, value); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// anvil_impersonateAccount enables impersonation for an address.
func (s *Server) anvilImpersonateAccount(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	addr := common.HexToAddress(addrStr)
	if err := s.cheats.ImpersonateAccount(addr); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// anvil_stopImpersonatingAccount disables impersonation for an address.
func (s *Server) anvilStopImpersonatingAccount(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	addr := common.HexToAddress(addrStr)
	if err := s.cheats.StopImpersonatingAccount(addr); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// anvil_autoImpersonateAccount enables or disables auto-impersonation.
func (s *Server) anvilAutoImpersonateAccount(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	enabled, ok := args[0].(bool)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid enabled flag"}
	}

	s.cheats.SetAutoImpersonate(enabled)
	return true, nil
}

// anvil_mine mines one or more blocks.
func (s *Server) anvilMine(params json.RawMessage) (interface{}, *ErrorObject) {
	count := uint64(1)

	if len(params) > 0 {
		var args []interface{}
		if err := json.Unmarshal(params, &args); err == nil && len(args) > 0 {
			if countStr, ok := args[0].(string); ok {
				if n, err := hexutil.DecodeUint64(countStr); err == nil {
					count = n
				}
			} else if countFloat, ok := args[0].(float64); ok {
				count = uint64(countFloat)
			}
		}
	}

	for i := uint64(0); i < count; i++ {
		if _, err := s.miner.MineBlock(); err != nil {
			return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
		}
	}

	return true, nil
}

// anvil_snapshot creates a snapshot.
func (s *Server) anvilSnapshot() (interface{}, *ErrorObject) {
	id := s.snapshots.Snapshot()
	return hexutil.EncodeUint64(id), nil
}

// anvil_revert reverts to a snapshot.
func (s *Server) anvilRevert(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	var id uint64
	switch v := args[0].(type) {
	case string:
		var err error
		id, err = hexutil.DecodeUint64(v)
		if err != nil {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid snapshot ID"}
		}
	case float64:
		id = uint64(v)
	default:
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid snapshot ID type"}
	}

	success := s.snapshots.Revert(id)
	return success, nil
}

// anvil_increaseTime increases the current timestamp.
func (s *Server) anvilIncreaseTime(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	var seconds uint64
	switch v := args[0].(type) {
	case string:
		var err error
		seconds, err = hexutil.DecodeUint64(v)
		if err != nil {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid seconds"}
		}
	case float64:
		seconds = uint64(v)
	default:
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid seconds type"}
	}

	newTime, err := s.cheats.IncreaseTime(seconds)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return hexutil.EncodeUint64(newTime), nil
}

// anvil_setNextBlockTimestamp sets the timestamp for the next block.
func (s *Server) anvilSetNextBlockTimestamp(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	var timestamp uint64
	switch v := args[0].(type) {
	case string:
		var err error
		timestamp, err = hexutil.DecodeUint64(v)
		if err != nil {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid timestamp"}
		}
	case float64:
		timestamp = uint64(v)
	default:
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid timestamp type"}
	}

	if err := s.cheats.SetNextBlockTimestamp(timestamp); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// anvil_setNextBlockBaseFee sets the base fee for the next block.
func (s *Server) anvilSetNextBlockBaseFee(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	baseFeeStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid base fee"}
	}

	baseFee, err := hexutil.DecodeBig(baseFeeStr)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid base fee format"}
	}

	if err := s.cheats.SetNextBlockBaseFee(baseFee); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// anvil_setCoinbase sets the coinbase address.
func (s *Server) anvilSetCoinbase(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	addr := common.HexToAddress(addrStr)
	if err := s.cheats.SetCoinbase(addr); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// anvil_reset resets the chain state.
func (s *Server) anvilReset() (interface{}, *ErrorObject) {
	s.cheats.Reset()
	s.snapshots.Clear()
	s.pool.Clear()
	s.validators.Clear()
	s.stablecoin.Clear()
	return true, nil
}

// anvil_dumpState dumps the current state as JSON.
func (s *Server) anvilDumpState() (interface{}, *ErrorObject) {
	dump := s.stateManager.Dump()
	return dump, nil
}

// anvil_loadState loads state from a dump.
func (s *Server) anvilLoadState(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	// The state dump can be passed as a map or as a raw JSON object
	dumpData, ok := args[0].(map[string]interface{})
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid state dump"}
	}

	// Convert map to StateDump
	dump := &state.StateDump{
		Accounts: make(map[string]state.AccountDump),
	}

	accountsData, ok := dumpData["accounts"].(map[string]interface{})
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid accounts in state dump"}
	}

	for addrHex, accData := range accountsData {
		accMap, ok := accData.(map[string]interface{})
		if !ok {
			continue
		}

		accDump := state.AccountDump{
			Balance: "0x0",
			Storage: make(map[string]string),
		}

		if v, ok := accMap["balance"].(string); ok {
			accDump.Balance = v
		}
		if v, ok := accMap["nonce"].(float64); ok {
			accDump.Nonce = uint64(v)
		}
		if v, ok := accMap["code"].(string); ok {
			accDump.Code = v
		}
		if storageData, ok := accMap["storage"].(map[string]interface{}); ok {
			for slot, value := range storageData {
				if v, ok := value.(string); ok {
					accDump.Storage[slot] = v
				}
			}
		}

		dump.Accounts[addrHex] = accDump
	}

	if err := s.stateManager.Load(dump); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// anvil_dropTransaction drops a pending transaction from the pool.
func (s *Server) anvilDropTransaction(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	txHashStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid transaction hash"}
	}

	txHash := common.HexToHash(txHashStr)
	err := s.pool.Remove(txHash)
	if err != nil {
		// Transaction not found, return false instead of error
		return false, nil
	}

	return true, nil
}

// evm_setAutomine enables or disables auto-mining mode.
func (s *Server) evmSetAutomine(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	enabled, ok := args[0].(bool)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid enabled flag"}
	}

	if err := s.cheats.SetAutomine(enabled); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// evm_setIntervalMining sets the interval for automatic block mining.
func (s *Server) evmSetIntervalMining(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	var interval uint64
	switch v := args[0].(type) {
	case string:
		var err error
		interval, err = hexutil.DecodeUint64(v)
		if err != nil {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid interval"}
		}
	case float64:
		interval = uint64(v)
	default:
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid interval type"}
	}

	if err := s.cheats.SetIntervalMining(interval); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// stablenet_addValidator adds a validator.
func (s *Server) stablenetAddValidator(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params: [address, operator] or [address, operator, blsKey]"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	operatorStr, ok := args[1].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid operator"}
	}

	addr := common.HexToAddress(addrStr)
	operator := common.HexToAddress(operatorStr)

	var blsKey []byte
	if len(args) >= 3 {
		blsKeyStr, ok := args[2].(string)
		if ok {
			blsKey = common.FromHex(blsKeyStr)
		}
	}
	if blsKey == nil {
		blsKey = make([]byte, 48) // Empty BLS key for testing
	}

	if err := s.validators.AddValidator(addr, operator, blsKey); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// stablenet_removeValidator removes a validator.
func (s *Server) stablenetRemoveValidator(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	addr := common.HexToAddress(addrStr)
	if err := s.validators.RemoveValidator(addr); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// stablenet_getValidators returns all validators.
func (s *Server) stablenetGetValidators() (interface{}, *ErrorObject) {
	validators := s.validators.GetValidators()

	result := make([]map[string]interface{}, len(validators))
	for i, v := range validators {
		result[i] = map[string]interface{}{
			"address":      v.Address.Hex(),
			"operator":     v.Operator.Hex(),
			"blsPublicKey": hexutil.Encode(v.BLSPublicKey),
		}
	}

	return result, nil
}

// stablenet_setProposer is a no-op since proposer is determined by round-robin.
func (s *Server) stablenetSetProposer(params json.RawMessage) (interface{}, *ErrorObject) {
	// Proposer is determined by round-robin, this is for API compatibility
	return true, nil
}

// stablenet_getProposer returns the proposer for a given block number.
func (s *Server) stablenetGetProposer(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	var blockNum uint64
	switch v := args[0].(type) {
	case string:
		if v == "latest" || v == "pending" {
			blockNum = s.chain.BlockNumber()
		} else {
			var err error
			blockNum, err = hexutil.DecodeUint64(v)
			if err != nil {
				return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid block number"}
			}
		}
	case float64:
		blockNum = uint64(v)
	default:
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid block number type"}
	}

	proposer, err := s.validators.GetProposer(blockNum)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return proposer.Hex(), nil
}

// stablenet_setGasTip sets the gas tip.
func (s *Server) stablenetSetGasTip(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	gasTipStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid gas tip"}
	}

	gasTip, err := hexutil.DecodeBig(gasTipStr)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid gas tip format"}
	}

	s.validators.SetGasTip(gasTip)
	return true, nil
}

// stablenet_getGasTip returns the current gas tip.
func (s *Server) stablenetGetGasTip() (interface{}, *ErrorObject) {
	gasTip := s.validators.GetGasTip()
	return hexutil.EncodeBig(gasTip), nil
}

// stablenet_mintStablecoin mints stablecoins to an address.
func (s *Server) stablenetMintStablecoin(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params: [address, amount]"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	amountStr, ok := args[1].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid amount"}
	}

	addr := common.HexToAddress(addrStr)
	amount, err := hexutil.DecodeBig(amountStr)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid amount format"}
	}

	if err := s.stablecoin.Mint(addr, amount); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// stablenet_burnStablecoin burns stablecoins from an address.
func (s *Server) stablenetBurnStablecoin(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params: [address, amount]"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	amountStr, ok := args[1].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid amount"}
	}

	addr := common.HexToAddress(addrStr)
	amount, err := hexutil.DecodeBig(amountStr)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid amount format"}
	}

	if err := s.stablecoin.Burn(addr, amount); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	return true, nil
}

// stablenet_getStablecoinBalance returns the stablecoin balance of an address.
func (s *Server) stablenetGetStablecoinBalance(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	addr := common.HexToAddress(addrStr)
	balance := s.stablecoin.GetBalance(addr)
	return hexutil.EncodeBig(balance), nil
}

// stablenet_getStablecoinTotalSupply returns the total supply of stablecoins.
func (s *Server) stablenetGetStablecoinTotalSupply() (interface{}, *ErrorObject) {
	supply := s.stablecoin.GetTotalSupply()
	return hexutil.EncodeBig(supply), nil
}

// TraceConfig holds configuration for tracing operations.
type TraceConfig struct {
	Tracer       string          `json:"tracer,omitempty"`
	TracerConfig json.RawMessage `json:"tracerConfig,omitempty"`
}

// debug_traceTransaction traces a transaction by hash.
func (s *Server) debugTraceTransaction(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	txHashStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid transaction hash"}
	}

	txHash := common.HexToHash(txHashStr)

	// Get the transaction from chain
	tx, blockHash, blockNum, txIndex := s.chain.GetTransaction(txHash)
	if tx == nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: "Transaction not found"}
	}

	// Get the block
	block := s.chain.GetBlockByHash(blockHash)
	if block == nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: "Block not found"}
	}

	// Parse tracer config
	var tracerCfg *tracing.CallTracerConfig
	if len(args) >= 2 {
		cfgMap, ok := args[1].(map[string]interface{})
		if ok {
			if tcRaw, exists := cfgMap["tracerConfig"]; exists {
				if tcMap, ok := tcRaw.(map[string]interface{}); ok {
					tracerCfg = &tracing.CallTracerConfig{}
					if v, ok := tcMap["onlyTopCall"].(bool); ok {
						tracerCfg.OnlyTopCall = v
					}
					if v, ok := tcMap["withLog"].(bool); ok {
						tracerCfg.WithLog = v
					}
				}
			}
		}
	}

	// Create tracer
	tracer := tracing.NewCallTracer(tracerCfg)

	// Replay transaction with tracing
	// For simplicity, we return a basic trace structure
	// Full implementation would replay the transaction
	result := &tracing.CallFrame{
		Type:    "CALL",
		From:    getSender(tx, s.chainID),
		To:      tx.To(),
		Gas:     hexutil.Uint64(tx.Gas()),
		GasUsed: hexutil.Uint64(21000), // Simplified
		Input:   tx.Data(),
	}

	if tx.Value() != nil && tx.Value().Sign() > 0 {
		result.Value = (*hexutil.Big)(tx.Value())
	}

	_ = tracer // Tracer would be used in full implementation
	_ = block  // Block would be used in full implementation

	// Return trace info with transaction context
	return map[string]interface{}{
		"result":      result,
		"txHash":      txHash.Hex(),
		"blockNumber": hexutil.Uint64(blockNum),
		"blockHash":   blockHash.Hex(),
		"txIndex":     hexutil.Uint64(txIndex),
	}, nil
}

// debug_traceCall traces a call without executing it.
func (s *Server) debugTraceCall(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	callArgsMap, ok := args[0].(map[string]interface{})
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid call arguments"}
	}

	// Parse call arguments
	var from, to common.Address
	var value *big.Int
	var gas uint64 = 1000000 // Default gas
	var data []byte

	if v, ok := callArgsMap["from"].(string); ok {
		from = common.HexToAddress(v)
	}
	if v, ok := callArgsMap["to"].(string); ok {
		to = common.HexToAddress(v)
	}
	if v, ok := callArgsMap["value"].(string); ok {
		value, _ = hexutil.DecodeBig(v)
	}
	if v, ok := callArgsMap["gas"].(string); ok {
		gas, _ = hexutil.DecodeUint64(v)
	}
	if v, ok := callArgsMap["data"].(string); ok {
		data = common.FromHex(v)
	}
	if v, ok := callArgsMap["input"].(string); ok {
		data = common.FromHex(v)
	}

	// Parse tracer config
	var tracerCfg *tracing.CallTracerConfig
	if len(args) >= 3 {
		cfgMap, ok := args[2].(map[string]interface{})
		if ok {
			if tcRaw, exists := cfgMap["tracerConfig"]; exists {
				if tcMap, ok := tcRaw.(map[string]interface{}); ok {
					tracerCfg = &tracing.CallTracerConfig{}
					if v, ok := tcMap["onlyTopCall"].(bool); ok {
						tracerCfg.OnlyTopCall = v
					}
					if v, ok := tcMap["withLog"].(bool); ok {
						tracerCfg.WithLog = v
					}
				}
			}
		}
	}

	// Create tracer
	tracer := tracing.NewCallTracer(tracerCfg)

	// For simplified implementation, return basic trace
	result := &tracing.CallFrame{
		Type:    "CALL",
		From:    from,
		To:      &to,
		Gas:     hexutil.Uint64(gas),
		GasUsed: hexutil.Uint64(21000), // Simplified
		Input:   data,
	}

	if value != nil && value.Sign() > 0 {
		result.Value = (*hexutil.Big)(value)
	}

	_ = tracer // Tracer would be used in full implementation
	return result, nil
}

// debug_traceBlockByNumber traces all transactions in a block.
func (s *Server) debugTraceBlockByNumber(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	blockNumStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid block number"}
	}

	var blockNum uint64
	if blockNumStr == "latest" {
		blockNum = s.chain.BlockNumber()
	} else if blockNumStr == "pending" {
		blockNum = s.chain.BlockNumber()
	} else {
		var err error
		blockNum, err = hexutil.DecodeUint64(blockNumStr)
		if err != nil {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid block number format"}
		}
	}

	block := s.chain.GetBlockByNumber(blockNum)
	if block == nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: "Block not found"}
	}

	// Parse tracer config
	var tracerCfg *tracing.CallTracerConfig
	if len(args) >= 2 {
		cfgMap, ok := args[1].(map[string]interface{})
		if ok {
			if tcRaw, exists := cfgMap["tracerConfig"]; exists {
				if tcMap, ok := tcRaw.(map[string]interface{}); ok {
					tracerCfg = &tracing.CallTracerConfig{}
					if v, ok := tcMap["onlyTopCall"].(bool); ok {
						tracerCfg.OnlyTopCall = v
					}
					if v, ok := tcMap["withLog"].(bool); ok {
						tracerCfg.WithLog = v
					}
				}
			}
		}
	}

	// Trace each transaction
	txs := block.Transactions()
	results := make([]map[string]interface{}, len(txs))

	for i, tx := range txs {
		tracer := tracing.NewCallTracer(tracerCfg)

		result := &tracing.CallFrame{
			Type:    "CALL",
			From:    getSender(tx, s.chainID),
			To:      tx.To(),
			Gas:     hexutil.Uint64(tx.Gas()),
			GasUsed: hexutil.Uint64(21000), // Simplified
			Input:   tx.Data(),
		}

		if tx.Value() != nil && tx.Value().Sign() > 0 {
			result.Value = (*hexutil.Big)(tx.Value())
		}

		results[i] = map[string]interface{}{
			"txHash": tx.Hash().Hex(),
			"result": result,
		}

		_ = tracer // Tracer would be used in full implementation
	}

	return results, nil
}

// getSender extracts the sender address from a transaction.
func getSender(tx *types.Transaction, chainID *big.Int) common.Address {
	signer := types.LatestSignerForChainID(chainID)
	from, err := types.Sender(signer, tx)
	if err != nil {
		return common.Address{}
	}
	return from
}

// net_listening returns true (always listening).
func (s *Server) netListening() (interface{}, *ErrorObject) {
	return true, nil
}

// net_peerCount returns 0x0 (no peers for local dev node).
func (s *Server) netPeerCount() (interface{}, *ErrorObject) {
	return "0x0", nil
}

// web3_sha3 returns the Keccak-256 hash of the input data.
func (s *Server) web3Sha3(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	dataStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid data"}
	}

	data := common.FromHex(dataStr)
	hash := common.BytesToHash(keccak256(data))
	return hash.Hex(), nil
}

// keccak256 computes the Keccak-256 hash of the input.
func keccak256(data []byte) []byte {
	return crypto.Keccak256(data)
}

// eth_sendTransaction sends an unsigned transaction.
func (s *Server) ethSendTransaction(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	txArgs, ok := args[0].(map[string]interface{})
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid transaction args"}
	}

	// Parse from address
	fromStr, ok := txArgs["from"].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Missing from address"}
	}
	from := common.HexToAddress(fromStr)

	// Check if impersonating or auto-impersonate enabled
	if !s.cheats.IsImpersonating(from) && !s.cheats.IsAutoImpersonate() {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Sender not impersonated"}
	}

	// Parse to address
	var to *common.Address
	if toStr, ok := txArgs["to"].(string); ok {
		toAddr := common.HexToAddress(toStr)
		to = &toAddr
	}

	// Parse value
	value := big.NewInt(0)
	if valueStr, ok := txArgs["value"].(string); ok {
		var err error
		value, err = hexutil.DecodeBig(valueStr)
		if err != nil {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid value"}
		}
	}

	// Parse gas
	gas := uint64(21000)
	if gasStr, ok := txArgs["gas"].(string); ok {
		var err error
		gas, err = hexutil.DecodeUint64(gasStr)
		if err != nil {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid gas"}
		}
	}

	// Parse gas price
	gasPrice := big.NewInt(1e9) // Default 1 gwei
	if gasPriceStr, ok := txArgs["gasPrice"].(string); ok {
		var err error
		gasPrice, err = hexutil.DecodeBig(gasPriceStr)
		if err != nil {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid gasPrice"}
		}
	}

	// Parse data
	var data []byte
	if dataStr, ok := txArgs["data"].(string); ok {
		data = common.FromHex(dataStr)
	}
	if inputStr, ok := txArgs["input"].(string); ok {
		data = common.FromHex(inputStr)
	}

	// Get nonce
	nonce := s.stateManager.GetNonce(from)

	// Create transaction
	var tx *types.Transaction
	if to == nil {
		tx = types.NewContractCreation(nonce, value, gas, gasPrice, data)
	} else {
		tx = types.NewTransaction(nonce, *to, value, gas, gasPrice, data)
	}

	// Check balance for cost
	gasCost := new(big.Int).Mul(gasPrice, big.NewInt(int64(gas)))
	totalCost := new(big.Int).Add(value, gasCost)

	balance := s.stateManager.GetBalance(from)
	if balance.Cmp(totalCost) < 0 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Insufficient funds"}
	}

	// Update state: deduct cost from sender
	s.stateManager.SetBalance(from, new(big.Int).Sub(balance, totalCost))

	// Add value to recipient
	if to != nil {
		toBalance := s.stateManager.GetBalance(*to)
		s.stateManager.SetBalance(*to, new(big.Int).Add(toBalance, value))
	}

	// Update nonce
	s.stateManager.SetNonce(from, nonce+1)

	// Store transaction in chain for later retrieval
	s.chain.AddPendingTransaction(tx, from)

	return tx.Hash().Hex(), nil
}

// eth_sendRawTransaction sends a signed raw transaction.
func (s *Server) ethSendRawTransaction(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	rawTxStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid raw transaction"}
	}

	rawTx := common.FromHex(rawTxStr)
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(rawTx); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Failed to decode transaction"}
	}

	// Verify signature and get sender
	signer := types.LatestSignerForChainID(s.chainID)
	from, err := types.Sender(signer, tx)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid transaction signature"}
	}

	// Check balance
	gasPrice := tx.GasPrice()
	if gasPrice == nil {
		gasPrice = big.NewInt(1e9)
	}
	gasCost := new(big.Int).Mul(gasPrice, big.NewInt(int64(tx.Gas())))
	totalCost := new(big.Int).Add(tx.Value(), gasCost)

	balance := s.stateManager.GetBalance(from)
	if balance.Cmp(totalCost) < 0 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Insufficient funds"}
	}

	// Update balances
	s.stateManager.SetBalance(from, new(big.Int).Sub(balance, totalCost))
	if tx.To() != nil {
		toBalance := s.stateManager.GetBalance(*tx.To())
		s.stateManager.SetBalance(*tx.To(), new(big.Int).Add(toBalance, tx.Value()))
	}

	// Update nonce
	s.stateManager.SetNonce(from, tx.Nonce()+1)

	// Add to pool
	if err := s.pool.Add(tx); err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
	}

	// Auto-mine if enabled
	if s.cheats.IsAutomine() {
		if _, err := s.miner.MineBlock(); err != nil {
			return nil, &ErrorObject{Code: ErrCodeInternal, Message: err.Error()}
		}
	}

	return tx.Hash().Hex(), nil
}

// eth_call executes a call without creating a transaction.
func (s *Server) ethCall(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	callArgs, ok := args[0].(map[string]interface{})
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid call args"}
	}

	// Parse to address (required for calls)
	toStr, ok := callArgs["to"].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Missing to address"}
	}
	to := common.HexToAddress(toStr)

	// Get contract code
	code := s.stateManager.GetCode(to)

	// For simple implementation, return empty result if no contract
	// A full implementation would execute the EVM
	if len(code) == 0 {
		return "0x", nil
	}

	// Return empty result (simplified - full implementation would run EVM)
	return "0x", nil
}

// eth_getTransactionReceipt returns the receipt of a transaction by hash.
func (s *Server) ethGetTransactionReceipt(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	txHashStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid transaction hash"}
	}

	txHash := common.HexToHash(txHashStr)

	// Get transaction from chain
	tx, blockHash, blockNum, txIndex := s.chain.GetTransaction(txHash)
	if tx == nil {
		return nil, nil // Transaction not found, return null
	}

	// Get sender
	from := getSender(tx, s.chainID)

	receipt := map[string]interface{}{
		"transactionHash":   txHash.Hex(),
		"transactionIndex":  hexutil.Uint64(txIndex),
		"blockHash":         blockHash.Hex(),
		"blockNumber":       hexutil.Uint64(blockNum),
		"from":              from.Hex(),
		"cumulativeGasUsed": hexutil.Uint64(21000),
		"gasUsed":           hexutil.Uint64(21000),
		"logs":              []interface{}{},
		"logsBloom":         fmt.Sprintf("0x%0512x", 0),
		"status":            "0x1", // Success
		"type":              "0x0",
	}

	if tx.To() != nil {
		receipt["to"] = tx.To().Hex()
	} else {
		receipt["to"] = nil
		// Contract creation - generate contract address
		receipt["contractAddress"] = crypto.CreateAddress(from, tx.Nonce()).Hex()
	}

	return receipt, nil
}

// eth_getTransactionByHash returns a transaction by hash.
func (s *Server) ethGetTransactionByHash(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	txHashStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid transaction hash"}
	}

	txHash := common.HexToHash(txHashStr)

	// Get transaction from chain
	tx, blockHash, blockNum, txIndex := s.chain.GetTransaction(txHash)
	if tx == nil {
		return nil, nil // Transaction not found, return null
	}

	// Get sender
	from := getSender(tx, s.chainID)

	result := map[string]interface{}{
		"hash":             txHash.Hex(),
		"nonce":            hexutil.Uint64(tx.Nonce()),
		"blockHash":        blockHash.Hex(),
		"blockNumber":      hexutil.Uint64(blockNum),
		"transactionIndex": hexutil.Uint64(txIndex),
		"from":             from.Hex(),
		"value":            hexutil.EncodeBig(tx.Value()),
		"gas":              hexutil.Uint64(tx.Gas()),
		"gasPrice":         hexutil.EncodeBig(tx.GasPrice()),
		"input":            hexutil.Encode(tx.Data()),
		"v":                "0x0",
		"r":                "0x0",
		"s":                "0x0",
	}

	if tx.To() != nil {
		result["to"] = tx.To().Hex()
	} else {
		result["to"] = nil
	}

	return result, nil
}

// anvil_dropAllTransactions drops all pending transactions from the pool.
func (s *Server) anvilDropAllTransactions() (interface{}, *ErrorObject) {
	s.pool.Clear()
	return true, nil
}

// anvil_setMinGasPrice sets the minimum gas price.
func (s *Server) anvilSetMinGasPrice(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	gasPriceStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid gas price"}
	}

	_, err := hexutil.DecodeBig(gasPriceStr)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid gas price format"}
	}

	// Store min gas price (for now, just accept and return true)
	// A full implementation would enforce this on transaction submission
	return true, nil
}

// anvil_nodeInfo returns node information.
func (s *Server) anvilNodeInfo() (interface{}, *ErrorObject) {
	return map[string]interface{}{
		"currentVersion": ClientVersion,
		"chainId":        hexutil.EncodeBig(s.chainID),
		"hardFork":       "london",
		"network":        "anvil-go",
	}, nil
}

// debug_traceBlockByHash traces all transactions in a block by hash.
func (s *Server) debugTraceBlockByHash(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	blockHashStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid block hash"}
	}

	blockHash := common.HexToHash(blockHashStr)
	block, err := s.chain.BlockByHash(blockHash)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: "Block not found"}
	}

	// Parse tracer config
	var tracerCfg *tracing.CallTracerConfig
	if len(args) >= 2 {
		cfgMap, ok := args[1].(map[string]interface{})
		if ok {
			if tcRaw, exists := cfgMap["tracerConfig"]; exists {
				if tcMap, ok := tcRaw.(map[string]interface{}); ok {
					tracerCfg = &tracing.CallTracerConfig{}
					if v, ok := tcMap["onlyTopCall"].(bool); ok {
						tracerCfg.OnlyTopCall = v
					}
					if v, ok := tcMap["withLog"].(bool); ok {
						tracerCfg.WithLog = v
					}
				}
			}
		}
	}

	// Trace each transaction
	txs := block.Transactions()
	results := make([]map[string]interface{}, len(txs))

	for i, tx := range txs {
		tracer := tracing.NewCallTracer(tracerCfg)

		result := &tracing.CallFrame{
			Type:    "CALL",
			From:    getSender(tx, s.chainID),
			To:      tx.To(),
			Gas:     hexutil.Uint64(tx.Gas()),
			GasUsed: hexutil.Uint64(21000), // Simplified
			Input:   tx.Data(),
		}

		if tx.Value() != nil && tx.Value().Sign() > 0 {
			result.Value = (*hexutil.Big)(tx.Value())
		}

		results[i] = map[string]interface{}{
			"txHash": tx.Hash().Hex(),
			"result": result,
		}

		_ = tracer // Tracer would be used in full implementation
	}

	return results, nil
}

// eth_getLogs returns logs matching a filter query.
func (s *Server) ethGetLogs(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	filterParams, ok := args[0].(map[string]interface{})
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid filter params"}
	}

	// Parse block range
	var fromBlock, toBlock uint64
	if fromStr, ok := filterParams["fromBlock"].(string); ok {
		if fromStr == "latest" || fromStr == "pending" {
			fromBlock = s.chain.BlockNumber()
		} else if fromStr == "earliest" {
			fromBlock = 0
		} else {
			var err error
			fromBlock, err = hexutil.DecodeUint64(fromStr)
			if err != nil {
				fromBlock = 0
			}
		}
	}

	if toStr, ok := filterParams["toBlock"].(string); ok {
		if toStr == "latest" || toStr == "pending" {
			toBlock = s.chain.BlockNumber()
		} else if toStr == "earliest" {
			toBlock = 0
		} else {
			var err error
			toBlock, err = hexutil.DecodeUint64(toStr)
			if err != nil {
				toBlock = s.chain.BlockNumber()
			}
		}
	} else {
		toBlock = s.chain.BlockNumber()
	}

	// Parse address filter
	var addresses []common.Address
	if addrParam := filterParams["address"]; addrParam != nil {
		switch v := addrParam.(type) {
		case string:
			addresses = append(addresses, common.HexToAddress(v))
		case []interface{}:
			for _, a := range v {
				if aStr, ok := a.(string); ok {
					addresses = append(addresses, common.HexToAddress(aStr))
				}
			}
		}
	}

	// Parse topics filter
	var topics [][]common.Hash
	if topicsParam, ok := filterParams["topics"].([]interface{}); ok {
		for _, t := range topicsParam {
			var topicGroup []common.Hash
			switch v := t.(type) {
			case string:
				topicGroup = append(topicGroup, common.HexToHash(v))
			case []interface{}:
				for _, h := range v {
					if hStr, ok := h.(string); ok {
						topicGroup = append(topicGroup, common.HexToHash(hStr))
					}
				}
			case nil:
				// nil means any topic
			}
			topics = append(topics, topicGroup)
		}
	}

	// Collect logs from blocks (simplified - no actual log storage)
	// A full implementation would store logs from transaction execution
	logs := []interface{}{}

	_ = fromBlock
	_ = toBlock
	_ = addresses
	_ = topics

	return logs, nil
}

// eth_sign signs a message with an account.
func (s *Server) ethSign(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid address"}
	}

	messageStr, ok := args[1].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid message"}
	}

	addr := common.HexToAddress(addrStr)
	message := common.FromHex(messageStr)

	// Check if we have the private key for this account
	s.mu.RLock()
	privateKey, hasKey := s.privateKeys[addr]
	s.mu.RUnlock()

	if !hasKey {
		// Use a deterministic test key for the default account
		// This matches Anvil's default test accounts
		if addr == common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266") {
			// First Anvil test account private key
			privateKey = common.FromHex("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
		} else {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Account not found"}
		}
	}

	// Create Ethereum signed message hash
	prefix := []byte("\x19Ethereum Signed Message:\n")
	lenStr := []byte(fmt.Sprintf("%d", len(message)))
	prefixedMessage := append(append(prefix, lenStr...), message...)
	hash := crypto.Keccak256(prefixedMessage)

	// Sign the hash
	key, err := crypto.ToECDSA(privateKey)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: "Invalid private key"}
	}

	sig, err := crypto.Sign(hash, key)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: "Failed to sign message"}
	}

	// Adjust v value for Ethereum signature format
	sig[64] += 27

	return hexutil.Encode(sig), nil
}

// eth_signTransaction signs a transaction without sending it.
func (s *Server) ethSignTransaction(params json.RawMessage) (interface{}, *ErrorObject) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	}

	txArgs, ok := args[0].(map[string]interface{})
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid transaction args"}
	}

	// Parse from address
	fromStr, ok := txArgs["from"].(string)
	if !ok {
		return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Missing from address"}
	}
	from := common.HexToAddress(fromStr)

	// Get private key
	s.mu.RLock()
	privateKey, hasKey := s.privateKeys[from]
	s.mu.RUnlock()

	if !hasKey {
		// Use default test account key
		if from == common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266") {
			privateKey = common.FromHex("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
		} else {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Account not found"}
		}
	}

	// Parse to address
	var to *common.Address
	if toStr, ok := txArgs["to"].(string); ok {
		toAddr := common.HexToAddress(toStr)
		to = &toAddr
	}

	// Parse value
	value := big.NewInt(0)
	if valueStr, ok := txArgs["value"].(string); ok {
		var err error
		value, err = hexutil.DecodeBig(valueStr)
		if err != nil {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid value"}
		}
	}

	// Parse gas
	gas := uint64(21000)
	if gasStr, ok := txArgs["gas"].(string); ok {
		var err error
		gas, err = hexutil.DecodeUint64(gasStr)
		if err != nil {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid gas"}
		}
	}

	// Parse gas price
	gasPrice := big.NewInt(1e9)
	if gasPriceStr, ok := txArgs["gasPrice"].(string); ok {
		var err error
		gasPrice, err = hexutil.DecodeBig(gasPriceStr)
		if err != nil {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid gasPrice"}
		}
	}

	// Parse nonce
	nonce := s.stateManager.GetNonce(from)
	if nonceStr, ok := txArgs["nonce"].(string); ok {
		var err error
		nonce, err = hexutil.DecodeUint64(nonceStr)
		if err != nil {
			return nil, &ErrorObject{Code: ErrCodeInvalidParams, Message: "Invalid nonce"}
		}
	}

	// Parse data
	var data []byte
	if dataStr, ok := txArgs["data"].(string); ok {
		data = common.FromHex(dataStr)
	}
	if inputStr, ok := txArgs["input"].(string); ok {
		data = common.FromHex(inputStr)
	}

	// Create transaction
	var tx *types.Transaction
	if to == nil {
		tx = types.NewContractCreation(nonce, value, gas, gasPrice, data)
	} else {
		tx = types.NewTransaction(nonce, *to, value, gas, gasPrice, data)
	}

	// Sign the transaction
	key, err := crypto.ToECDSA(privateKey)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: "Invalid private key"}
	}

	signer := types.NewEIP155Signer(s.chainID)
	signedTx, err := types.SignTx(tx, signer, key)
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: "Failed to sign transaction"}
	}

	// Encode signed transaction
	rawTx, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, &ErrorObject{Code: ErrCodeInternal, Message: "Failed to encode transaction"}
	}

	// Return signed transaction info
	result := map[string]interface{}{
		"raw": hexutil.Encode(rawTx),
		"tx": map[string]interface{}{
			"hash":     signedTx.Hash().Hex(),
			"nonce":    hexutil.Uint64(signedTx.Nonce()),
			"gasPrice": hexutil.EncodeBig(signedTx.GasPrice()),
			"gas":      hexutil.Uint64(signedTx.Gas()),
			"value":    hexutil.EncodeBig(signedTx.Value()),
			"input":    hexutil.Encode(signedTx.Data()),
			"v":        hexutil.EncodeBig(new(big.Int).SetBytes([]byte{signedTx.Type()})),
			"r":        "0x0",
			"s":        "0x0",
		},
	}

	if signedTx.To() != nil {
		result["tx"].(map[string]interface{})["to"] = signedTx.To().Hex()
	}

	return result, nil
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s)
}
