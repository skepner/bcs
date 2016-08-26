# -*- Makefile -*-
# ----------------------------------------------------------------------

MAKEFLAGS = -w

# ----------------------------------------------------------------------

CLANG = $(shell if g++ --version 2>&1 | grep -i llvm >/dev/null; then echo Y; else echo N; fi)
ifeq ($(CLANG),Y)
  WEVERYTHING = -Weverything -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-padded
  WARNINGS = # -Wno-weak-vtables # -Wno-padded
  STD = c++14
else
  WEVERYTHING = -Wall -Wextra
  WARNINGS =
  STD = c++14
endif

# OPTIMIZATION = -O3
CXXFLAGS = -MMD -g $(OPTIMIZATION) -fPIC -std=$(STD) $(WEVERYTHING) $(WARNINGS) -I/usr/local/opt/openssl/include
LDFLAGS = -L/usr/local/opt/openssl/lib
LDLIBS = -lcrypto

BUILD = build
DIST = dist

# ----------------------------------------------------------------------

all: $(DIST)/bcs
	$(DIST)/bcs

clean:
	rm -rf $(DIST) $(BUILD)

# ----------------------------------------------------------------------

$(DIST)/%: $(BUILD)/%.o | $(DIST)
	g++ $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: %.cc | $(BUILD)
	@#echo $<
	g++ $(CXXFLAGS) -c -o $@ $<

# ----------------------------------------------------------------------

$(DIST):
	mkdir -p $(DIST)

$(BUILD):
	mkdir -p $(BUILD)

# ======================================================================
