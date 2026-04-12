# HELIX Makefile — Unified Command Interface
# Version: V1.0_202604120942
# Reference: Engineering Spec Section 2.2

.PHONY: smoke-ci fp-proxy-ci check help

# --- CI Targets ---

smoke-ci:  ## Run CI smoke test (SafeToken→LOW, VulnerableVault→CRITICAL)
	python ci_smoke_test.py

fp-proxy-ci:  ## Run Proxy/Diamond/CREATE2 FP test suite (6 contracts, all must PASS)
	python proxy_fp_test_runner.py

check: smoke-ci fp-proxy-ci  ## Run all CI checks (smoke + FP suite)
	@echo "All CI checks passed."

# --- Development Targets ---

scan:  ## Scan a single file: make scan FILE=contract.sol
	python helix_scan.py $(FILE)

scan-json:  ## Scan with JSON output: make scan-json FILE=contract.sol
	python helix_scan.py --json $(FILE)

# --- Help ---

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
