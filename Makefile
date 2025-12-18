.PHONY: all clean fhe-programs test-python lint format

# Default target
all: fhe-programs

# Build FHE programs
fhe-programs:
	$(MAKE) -C fhe-programs/src all

# Clean all build artifacts
clean:
	$(MAKE) -C fhe-programs/src clean

# Run Python client tests (builds all dependencies first)
test-python: fhe-programs
	cargo build --release
	cd sunscreen_fhe && uv sync && uv run maturin develop --release && uv run pyright python/ tests/ && uv run pytest tests/ -v

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
	@echo "  all          - Build all FHE programs (default)"
	@echo "  fhe-programs - Build FHE programs"
	@echo "  test-python  - Build and run Python client tests"
	@echo "  lint         - Run all linters (Rust + Python)"
	@echo "  format       - Run all formatters (Rust + Python)"
	@echo "  clean        - Clean all build artifacts"
	@echo "  help         - Show this help message"

.PHONY: help
