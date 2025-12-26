# Anvil-Go Implementation Roadmap

## Overview

This document outlines the phased implementation plan for Anvil-Go. Each phase builds upon the previous, ensuring a stable foundation before adding advanced features.

---

## Phase 1: Foundation (MVP)

**Goal**: Basic simulator that can execute transactions and mine blocks

**Duration**: 2-3 weeks

### Deliverables

```
anvil-go/
├── cmd/
│   └── anvil/
│       └── main.go              # CLI entry point
├── pkg/
│   ├── config/
│   │   └── config.go            # Configuration management
│   ├── backend/
│   │   ├── backend.go           # Main backend implementation
│   │   └── backend_test.go
│   ├── state/
│   │   ├── manager.go           # State management
│   │   └── manager_test.go
│   ├── blockchain/
│   │   ├── chain.go             # Blockchain management
│   │   └── chain_test.go
│   ├── txpool/
│   │   ├── pool.go              # Transaction pool
│   │   └── pool_test.go
│   ├── miner/
│   │   ├── miner.go             # Block production
│   │   └── miner_test.go
│   ├── genesis/
│   │   ├── genesis.go           # Genesis creation
│   │   └── accounts.go          # Test account generation
│   └── rpc/
│       ├── server.go            # RPC server
│       ├── eth_api.go           # eth_* methods
│       ├── net_api.go           # net_* methods
│       └── web3_api.go          # web3_* methods
├── go.mod
├── go.sum
└── Makefile
```

### Milestones

| ID | Milestone | Description | Acceptance Criteria |
|----|-----------|-------------|---------------------|
| P1.1 | Project Setup | Go module, dependencies, CI | `go build` succeeds |
| P1.2 | Genesis Creation | Create genesis block with test accounts | 10 accounts with 10K ETH each |
| P1.3 | State Manager | In-memory state management | Get/Set balance, nonce, code, storage |
| P1.4 | Transaction Pool | Basic tx pool with validation | Add, remove, list pending txs |
| P1.5 | Block Miner | Auto-mine blocks | Execute txs, produce blocks |
| P1.6 | RPC Server | Basic eth_* APIs | eth_sendTransaction works |
| P1.7 | Integration | End-to-end flow | Send tx via RPC, verify receipt |

### Key APIs (Phase 1)

- `eth_chainId`
- `eth_blockNumber`
- `eth_getBalance`
- `eth_getCode`
- `eth_getTransactionCount`
- `eth_sendTransaction`
- `eth_sendRawTransaction`
- `eth_call`
- `eth_estimateGas`
- `eth_getTransactionReceipt`
- `eth_getBlockByNumber`
- `eth_getBlockByHash`
- `eth_accounts`
- `net_version`
- `web3_clientVersion`

---

## Phase 2: Cheat Codes

**Goal**: Full Foundry/Hardhat cheat code compatibility

**Duration**: 1-2 weeks

### Deliverables

```
pkg/
├── cheats/
│   ├── cheats.go                # Cheat codes implementation
│   ├── impersonation.go         # Account impersonation
│   ├── time.go                  # Time manipulation
│   └── cheats_test.go
├── snapshot/
│   ├── manager.go               # Snapshot management
│   └── manager_test.go
└── rpc/
    ├── anvil_api.go             # anvil_* methods
    └── evm_api.go               # evm_* methods
```

### Milestones

| ID | Milestone | Description | Acceptance Criteria |
|----|-----------|-------------|---------------------|
| P2.1 | Balance/Code/Storage | Set account state | anvil_setBalance works |
| P2.2 | Impersonation | Send tx as any account | anvil_impersonateAccount works |
| P2.3 | Time Manipulation | Control block timestamp | evm_increaseTime works |
| P2.4 | Snapshot/Revert | State snapshots | evm_snapshot/revert works |
| P2.5 | Mining Control | Manual/interval mining | evm_setAutomine works |
| P2.6 | Tx Management | Drop transactions | anvil_dropTransaction works |

### Key APIs (Phase 2)

#### Anvil APIs
- `anvil_setBalance`
- `anvil_setCode`
- `anvil_setStorageAt`
- `anvil_setNonce`
- `anvil_impersonateAccount`
- `anvil_stopImpersonatingAccount`
- `anvil_mine`
- `anvil_dropTransaction`
- `anvil_dropAllTransactions`
- `anvil_reset`

#### EVM APIs
- `evm_snapshot`
- `evm_revert`
- `evm_increaseTime`
- `evm_setNextBlockTimestamp`
- `evm_mine`
- `evm_setAutomine`
- `evm_setIntervalMining`

---

## Phase 3: StableNet Integration

**Goal**: Full StableNet/WBFT support

**Duration**: 1-2 weeks

### Deliverables

```
pkg/
├── stablenet/
│   ├── genesis.go               # StableNet genesis with system contracts
│   ├── contracts.go             # System contract bytecode
│   ├── validators.go            # Validator management
│   └── stablenet_test.go
└── rpc/
    └── stablenet_api.go         # stablenet_* methods
```

### Milestones

| ID | Milestone | Description | Acceptance Criteria |
|----|-----------|-------------|---------------------|
| P3.1 | System Contracts | Deploy GovValidator, etc. | Contracts accessible |
| P3.2 | Validator Management | Add/remove validators | stablenet_addValidator works |
| P3.3 | WBFT Simulation | Simulated WBFT rules | Proposer rotation works |
| P3.4 | Stablecoin Utils | Mint/burn helpers | stablenet_mintStablecoin works |

### Key APIs (Phase 3)

- `stablenet_addValidator`
- `stablenet_removeValidator`
- `stablenet_getValidators`
- `stablenet_setProposer`
- `stablenet_mintStablecoin`
- `stablenet_burnStablecoin`

---

## Phase 4: Advanced Features

**Goal**: Production-ready with debugging and fork mode

**Duration**: 2-3 weeks

### Deliverables

```
pkg/
├── tracing/
│   ├── tracer.go                # Transaction tracer
│   ├── call_tracer.go           # Call tracer
│   └── tracer_test.go
├── fork/
│   ├── provider.go              # Remote state provider
│   ├── cache.go                 # State cache
│   └── fork_test.go
└── rpc/
    └── debug_api.go             # debug_* methods
```

### Milestones

| ID | Milestone | Description | Acceptance Criteria |
|----|-----------|-------------|---------------------|
| P4.1 | Transaction Tracing | debug_traceTransaction | Trace output matches geth |
| P4.2 | Call Tracing | debug_traceCall | Call traces work |
| P4.3 | Fork Provider | Load state from remote | Fork from mainnet works |
| P4.4 | State Caching | Cache remote state | Performance acceptable |
| P4.5 | State Dump/Load | Export/import state | anvil_dumpState works |

### Key APIs (Phase 4)

- `debug_traceTransaction`
- `debug_traceCall`
- `debug_traceBlockByNumber`
- `debug_traceBlockByHash`
- `anvil_dumpState`
- `anvil_loadState`
- `anvil_nodeInfo`

---

## Phase 5: Polish & Performance

**Goal**: Production-ready quality

**Duration**: 1-2 weeks

### Deliverables

```
├── docs/
│   ├── API.md                   # Complete API documentation
│   └── EXAMPLES.md              # Usage examples
├── test/
│   ├── e2e/                     # End-to-end tests
│   ├── compat/                  # Compatibility tests
│   │   ├── foundry_test.go      # Foundry compatibility
│   │   └── hardhat_test.go      # Hardhat compatibility
│   └── benchmark/               # Performance benchmarks
└── scripts/
    ├── build.sh
    └── release.sh
```

### Milestones

| ID | Milestone | Description | Acceptance Criteria |
|----|-----------|-------------|---------------------|
| P5.1 | E2E Tests | Full integration tests | 90%+ coverage |
| P5.2 | Foundry Compat | forge test compatibility | Foundry tests pass |
| P5.3 | Hardhat Compat | Hardhat compatibility | Hardhat tests pass |
| P5.4 | Benchmarks | Performance testing | Meet performance targets |
| P5.5 | Documentation | Complete docs | All APIs documented |
| P5.6 | Release | v1.0.0 release | Binary distribution |

---

## Timeline Summary

```
Week 1-3:   Phase 1 - Foundation (MVP)
Week 4-5:   Phase 2 - Cheat Codes
Week 6-7:   Phase 3 - StableNet Integration
Week 8-10:  Phase 4 - Advanced Features
Week 11-12: Phase 5 - Polish & Performance
```

---

## Success Criteria

### Functional

- [ ] All eth_* APIs working correctly
- [ ] All anvil_* cheat codes implemented
- [ ] All evm_* methods implemented
- [ ] StableNet system contracts deployable
- [ ] Fork mode working
- [ ] Tracing working

### Performance

- [ ] Startup time < 1 second
- [ ] Transaction execution < 10ms
- [ ] RPC response time < 50ms
- [ ] Memory usage < 100MB (idle)

### Compatibility

- [ ] Foundry `forge test` passes
- [ ] Hardhat tests pass
- [ ] ethers.js compatible
- [ ] viem compatible

### Quality

- [ ] Test coverage > 80%
- [ ] No critical bugs
- [ ] Documentation complete
- [ ] CI/CD pipeline established

---

## Risk Assessment

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| go-ethereum API changes | High | Low | Pin to specific version |
| Performance issues | Medium | Medium | Early benchmarking |
| Compatibility gaps | Medium | Medium | Extensive testing |
| Scope creep | Medium | High | Strict phase boundaries |

---

## Dependencies

### External Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| go-stablenet | latest | Core EVM, types |
| go-ethereum/rpc | v1.13+ | RPC server |
| ethereum/go-ethereum | v1.13+ | Common utilities |

### Internal Dependencies

```
Phase 1 ──→ Phase 2 ──→ Phase 3 ──→ Phase 4 ──→ Phase 5
   │           │           │           │           │
   │           │           │           │           └── Release
   │           │           │           └── Fork mode, tracing
   │           │           └── StableNet contracts
   │           └── Cheat codes, snapshots
   └── Core functionality
```
