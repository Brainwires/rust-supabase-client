.PHONY: test coverage coverage-html coverage-lcov coverage-summary clean-coverage

# Run all workspace tests
test:
	cargo test --workspace

# Print a per-file coverage summary table to stdout
coverage:
	cargo llvm-cov --workspace

# Generate an HTML report in coverage/html/
coverage-html:
	cargo llvm-cov --workspace --html --output-dir coverage/html
	@echo "\nReport: coverage/html/index.html"

# Generate an lcov.info file (for CI / Codecov / Coveralls)
coverage-lcov:
	@mkdir -p coverage
	cargo llvm-cov --workspace --lcov --output-path coverage/lcov.info
	@echo "\nGenerated: coverage/lcov.info"

# Print only the bottom-line totals
coverage-summary:
	cargo llvm-cov --workspace 2>&1 | tail -3

# Remove generated coverage artifacts
clean-coverage:
	cargo llvm-cov clean --workspace
	rm -rf coverage/
