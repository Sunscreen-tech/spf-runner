.PHONY: all clean fhe-programs test-python

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

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build all FHE programs (default)"
	@echo "  fhe-programs - Build FHE programs"
	@echo "  test-python  - Build and run Python client tests"
	@echo "  clean        - Clean all build artifacts"
	@echo "  help         - Show this help message"

.PHONY: help
