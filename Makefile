# mini-tcp-stack build file.
#
#   make            build the static library + tests
#   make test       build and run the unit tests
#   make taptcp     build the Linux TAP echo-server demo (Linux only)
#   make clean      remove build artefacts

CC      ?= cc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -g
CPPFLAGS = -Iinclude

BUILD   := build
LIB_SRC := $(wildcard src/*.c)
LIB_OBJ := $(patsubst src/%.c,$(BUILD)/%.o,$(LIB_SRC))
LIB     := $(BUILD)/libnetstack.a

TEST_SRC := $(wildcard tests/*.c)
TEST_BIN := $(patsubst tests/%.c,$(BUILD)/%,$(TEST_SRC))

.PHONY: all test taptcp clean

all: $(LIB) $(TEST_BIN)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(LIB): $(LIB_OBJ)
	ar rcs $@ $^

# Each test binary links against the library. Tests include test_util.h from
# the tests/ directory, so add it to the include path.
$(BUILD)/%: tests/%.c $(LIB) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -Itests $< $(LIB) -o $@

test: $(TEST_BIN)
	@echo "=============================="
	@fail=0; for t in $(TEST_BIN); do \
		echo "Running $$t"; \
		$$t || fail=1; \
		echo; \
	done; \
	if [ $$fail -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "TESTS FAILED"; exit 1; fi

# The TAP demo uses Linux /dev/net/tun, so it is built on demand only.
taptcp: apps/taptcp.c $(LIB) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) apps/taptcp.c $(LIB) -o $(BUILD)/taptcp

clean:
	rm -rf $(BUILD)
