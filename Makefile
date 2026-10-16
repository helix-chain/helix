# HELIX Makefile — Unified Command Interface
# Version: V1.0_202604120942
# Reference: Engineering Spec Section 2.2

.PHONY: contract-test smoke-ci fp-proxy-ci harness-selftest check help install-hooks

# --- CI Targets ---

contract-test:  ## Detector output data-contract regression (no torch/transformers)
	python test_output_contract.py
	python test_replay_gate.py
	python test_extraction_layer.py

smoke-ci:  ## Run CI smoke test (SafeToken→LOW, VulnerableVault→CRITICAL)
	python ci_smoke_test.py

fp-proxy-ci:  ## Run Proxy/Diamond/CREATE2 FP test suite (6 contracts; exit 0 = no NEW false positive, 2 known FPs baselined)
	python proxy_fp_test_runner.py

harness-selftest:  ## Prove the harness gate bites (no torch; temp-repo probes)
	python test_harness_gate.py

check: harness-selftest contract-test smoke-ci fp-proxy-ci  ## Run all CI checks (harness self-test + contract + smoke + FP)
	@echo "All CI checks passed."

# --- Development Targets ---

scan:  ## Scan a single file: make scan FILE=contract.sol
	python helix_scan.py $(FILE)

scan-json:  ## Scan with JSON output: make scan-json FILE=contract.sol
	python helix_scan.py --json $(FILE)

install-hooks:  ## Install the harness pre-commit hook from tracked .ci/pre-commit
	sh .ci/install-hooks.sh

# --- Help ---

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
