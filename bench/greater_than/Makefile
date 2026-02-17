.PHONY: clean

LLVM_CLANG := $(LLVM_DIR)/clang

greater_than: greater_than.c
	$(LLVM_CLANG) -O2 -target parasol -o $@ $<

clean:
	$(RM) greater_than
