.PHONY: all clean fhe-programs test-python lint format bench help

# Default target: build everything (Rust, Python extension, FHE programs)
all: fhe-programs
	cargo build --release
	cd sunscreen_fhe && uv run maturin develop --release

# Build FHE programs
fhe-programs:
	$(MAKE) -C fhe-programs/src all

# Run all benchmarks (builds dependencies first)
bench: all
	$(MAKE) -C bench/greater_than greater_than
	cd sunscreen_fhe && uv run python ../bench/greater_than/bench.py

# Clean all build artifacts
clean:
	$(MAKE) -C fhe-programs/src clean
	$(MAKE) -C bench/greater_than clean

# Run Python client tests (builds all dependencies first)
test-python: all
	cd sunscreen_fhe && uv sync && uv run pyright python/ tests/ && uv run pytest tests/ -v

# Run all linters (Rust + Python)
lint:
	cargo clippy
	cd sunscreen_fhe && uv run ruff check && uv run pyright python/ tests/

# Run all formatters (Rust + Python)
format:
	cargo fmt
	cd sunscreen_fhe && uv run ruff format python/ tests/

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build everything (Rust, Python extension, FHE programs)"
	@echo "  fhe-programs - Build FHE programs"
	@echo "  bench        - Build and run all benchmarks"
	@echo "  test-python  - Build and run Python client tests"
	@echo "  lint         - Run all linters (Rust + Python)"
	@echo "  format       - Run all formatters (Rust + Python)"
	@echo "  clean        - Clean all build artifacts"
	@echo "  help         - Show this help message"
