.PHONY: test coverage coverage-html coverage-lcov coverage-summary clean-coverage \
       wasm wasm-web wasm-node clean-wasm wasm-test wasm-test-only

# Common coverage flags: exclude WASM + derive crates, ignore platform.rs WASM branches
COV_FLAGS = --workspace \
	--exclude supabase-client-wasm \
	--exclude supabase-client-derive \
	--ignore-filename-regex 'platform\.rs'

# Run all workspace tests
test:
	cargo test --workspace

# Print a per-file coverage summary table to stdout
coverage:
	cargo llvm-cov $(COV_FLAGS)

# Generate an HTML report in coverage/html/
coverage-html:
	cargo llvm-cov $(COV_FLAGS) --html --output-dir coverage/html
	@echo "\nReport: coverage/html/index.html"

# Generate an lcov.info file (for CI / Codecov / Coveralls)
coverage-lcov:
	@mkdir -p coverage
	cargo llvm-cov $(COV_FLAGS) --lcov --output-path coverage/lcov.info
	@echo "\nGenerated: coverage/lcov.info"

# Print only the bottom-line totals
coverage-summary:
	cargo llvm-cov $(COV_FLAGS) 2>&1 | tail -3

# Remove generated coverage artifacts
clean-coverage:
	cargo llvm-cov clean --workspace
	rm -rf coverage/

# Build WASM for browser (ES modules)
wasm-web:
	wasm-pack build crates/supabase-client-wasm --target web --out-dir ../../pkg/web

# Build WASM for Node.js (CommonJS)
wasm-node:
	wasm-pack build crates/supabase-client-wasm --target nodejs --out-dir ../../pkg/node

# Build both WASM targets
wasm: wasm-web wasm-node

# Build WASM for Node.js and run integration tests
wasm-test: wasm-node
	node --test tests/wasm-node/*.test.js

# Run WASM integration tests only (assumes pkg/node/ already built)
wasm-test-only:
	node --test tests/wasm-node/*.test.js

# Clean WASM output
clean-wasm:
	rm -rf pkg/
