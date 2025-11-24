.PHONY: all clean

SOURCES := $(wildcard *.c)
BASENAMES := $(basename $(SOURCES))
OBJECTS := $(addprefix ../compiled/, $(addsuffix .o, $(BASENAMES)))
EXECUTABLES := $(addprefix ../compiled/, $(BASENAMES))

LLVM_CLANG := $(LLVM_DIR)/clang

all: $(EXECUTABLES)

../compiled/%: %.c | ../compiled
	$(LLVM_CLANG) -O2 -target parasol -o $@ $<

../compiled:
	mkdir -p $@

clean:
	$(RM) $(EXECUTABLES) $(OBJECTS)
	$(RM) -r ../compiled
