# Anvil-Go Task List

## Development Methodology

- **Spec Driven Development**: Each task references SPEC.md
- **Test Driven Development**: Write tests before implementation
- **SOLID Principles**: Follow throughout
- **Clean Code**: Meaningful names, small functions, no magic numbers

---

## Task Status Legend

- [ ] Not started
- [~] In progress
- [x] Completed
- [!] Blocked

---

## Completed Phases Summary

### Phase 1: Foundation (MVP) ✅
**Completion Date**: 2025-12-24 | **Tests**: 103 passing

- Project setup, config, genesis, state manager, txpool, blockchain, miner, RPC server, backend, CLI

### Phase 2: Cheat Codes ✅
**Completion Date**: 2025-12-24 | **Tests**: 143 passing

- Cheat codes package, impersonation, time manipulation, snapshot manager, mining control
- anvil_* and evm_* RPC APIs

### Phase 3: StableNet Integration ✅
**Completion Date**: 2025-12-24 | **Tests**: 182 passing

- System contracts, validator management, stablenet_* RPC APIs, stablecoin management

### Phase 4: Advanced Features ✅
**Completion Date**: 2025-12-24 | **Tests**: 246 passing

- Tracing package, fork provider, state dump/load

### Phase 5: Polish & Performance ✅
**Completion Date**: 2025-12-26 | **Tests**: 246+ passing

- E2E tests, Foundry compatibility tests, benchmarks, documentation

---

## Phase 6: Remaining Implementation Tasks

### P6.1 Core eth_* RPC Methods (Priority 1) ✅

| Task ID | Method | Description | Est. |
|---------|--------|-------------|------|
| P6.1.1 | `eth_sendTransaction` | Send unsigned transaction | 2h |
| P6.1.2 | `eth_sendRawTransaction` | Send signed transaction | 1h |
| P6.1.3 | `eth_call` | Execute call without creating tx | 2h |
| P6.1.4 | `eth_getTransactionReceipt` | Get transaction receipt | 1h |
| P6.1.5 | `eth_getTransactionByHash` | Get transaction by hash | 0.5h |
| P6.1.6 | `eth_getLogs` | Get event logs (FilterQuery) | 2h |
| P6.1.7 | `eth_sign` | Sign data with account | 1h |
| P6.1.8 | `eth_signTransaction` | Sign transaction | 1h |

**Checklist:**
- [x] P6.1.1: eth_sendTransaction
- [x] P6.1.2: eth_sendRawTransaction
- [x] P6.1.3: eth_call
- [x] P6.1.4: eth_getTransactionReceipt
- [x] P6.1.5: eth_getTransactionByHash
- [x] P6.1.6: eth_getLogs
- [x] P6.1.7: eth_sign
- [x] P6.1.8: eth_signTransaction

---

### P6.2 net_*/web3_* Methods (Priority 2) ✅

| Task ID | Method | Description | Est. |
|---------|--------|-------------|------|
| P6.2.1 | `net_listening` | Always returns true | 0.5h |
| P6.2.2 | `net_peerCount` | Always returns 0 | 0.5h |
| P6.2.3 | `web3_sha3` | Keccak-256 hash | 0.5h |

**Checklist:**
- [x] P6.2.1: net_listening
- [x] P6.2.2: net_peerCount
- [x] P6.2.3: web3_sha3

---

### P6.3 anvil_* Cheat Codes (Priority 3) ✅

| Task ID | Method | Description | Est. |
|---------|--------|-------------|------|
| P6.3.1 | `anvil_dropAllTransactions` | Drop all pending transactions | 0.5h |
| P6.3.2 | `anvil_setMinGasPrice` | Set minimum gas price | 0.5h |
| P6.3.3 | `anvil_nodeInfo` | Return node information | 1h |

**Checklist:**
- [x] P6.3.1: anvil_dropAllTransactions
- [x] P6.3.2: anvil_setMinGasPrice
- [x] P6.3.3: anvil_nodeInfo

---

### P6.4 debug_* Methods (Priority 4) ✅

| Task ID | Method | Description | Est. |
|---------|--------|-------------|------|
| P6.4.1 | `debug_traceBlockByHash` | Trace block by hash | 1h |

**Checklist:**
- [x] P6.4.1: debug_traceBlockByHash

---

### P6.5 CI/CD & Release (Priority 5) ✅

| Task ID | Task | Description | Est. |
|---------|------|-------------|------|
| P6.5.1 | GitHub Actions CI | Setup CI workflow | 2h |
| P6.5.2 | Release automation | GitHub release workflow | 2h |
| P6.5.3 | v1.0.0 release | Create first release | 2h |

**Checklist:**
- [x] P6.5.1: .github/workflows/ci.yml
- [x] P6.5.2: .github/workflows/release.yml
- [ ] P6.5.3: v1.0.0 release tag and binaries (ready when repo is pushed)

---

### P6.6 Hardhat Compatibility (Priority 6) ✅

| Task ID | Task | Description | Est. |
|---------|------|-------------|------|
| P6.6.1 | Hardhat test suite | test/compat/hardhat_compat_test.go | 4h |

**Checklist:**
- [x] P6.6.1: Hardhat compatibility tests (45 tests)

---

## Estimation Summary

| Section | Status | Remaining |
|---------|--------|-----------|
| P6.1 Core eth_* RPC | ✅ Complete | - |
| P6.2 net_*/web3_* | ✅ Complete | - |
| P6.3 anvil_* Cheat Codes | ✅ Complete | - |
| P6.4 debug_* | ✅ Complete | - |
| P6.5 CI/CD & Release | ✅ Complete | v1.0.0 tag when ready |
| P6.6 Hardhat Compat | ✅ Complete | - |
| **Total** | **18/19 done** | **v1.0.0 release only** |

---

## Recommended Next Steps

1. **Release**: Create v1.0.0 tag after pushing to repository
2. **Optional**: Add more RPC methods as needed for specific use cases

---

## Definition of Done

Each task is complete when:

1. [x] Implementation complete
2. [x] Unit tests written and passing
3. [x] Test coverage > 80%
4. [x] No lint errors
5. [x] Code reviewed (self or peer)
6. [x] Documentation updated if needed
