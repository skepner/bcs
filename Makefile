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
CXXFLAGS = -MMD -g $(OPTIMIZATION) -fPIC -std=$(STD) $(WEVERYTHING) $(WARNINGS) $(INCLUDES)
CFLAGS = -MMD -g $(OPTIMIZATION) -fPIC $(WARNINGS) $(INCLUDES)
LDFLAGS =
LDLIBS =

BUILD = build
DIST = dist

# ----------------------------------------------------------------------

AESCRYPT_ROOT = AESCrypt/Linux
AESCRYPT_SRC = $(AESCRYPT_ROOT)/src
INCLUDES += -I$(AESCRYPT_ROOT) -I$(AESCRYPT_SRC)
AESCRYPT_CONFIG_H = $(AESCRYPT_ROOT)/config.h
AESCRYPT_SOURCES = aes.c sha256.c password.c keyfile.c aesrandom.c util.c
AESCRYPT_OBJ = $(patsubst %.c,$(BUILD)/%.o,$(AESCRYPT_SOURCES))

# ----------------------------------------------------------------------

all: $(DIST)/bcs
	$(DIST)/bcs

clean:
	rm -rf $(DIST) $(BUILD)

# ----------------------------------------------------------------------

$(DIST)/%: $(BUILD)/%.o $(AESCRYPT_OBJ) | $(DIST)
	g++ $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: %.cc | $(BUILD) $(BUILD)/submodules
	@#echo $<
	g++ $(CXXFLAGS) -c -o $@ $<

$(BUILD)/%.o: $(AESCRYPT_SRC)/%.c $(AESCRYPT_CONFIG_H) | $(BUILD)
	gcc $(CFLAGS) -c -o $@ $<

# ----------------------------------------------------------------------

$(AESCRYPT_CONFIG_H): $(AESCRYPT_ROOT)/Makefile.am
	cd $(AESCRYPT_ROOT) && autoreconf -i && ./configure

$(BUILD)/submodules:
	git submodule init
	git submodule update
	git submodule update --remote
	touch $@

# ----------------------------------------------------------------------

$(DIST):
	mkdir -p $(DIST)

$(BUILD):
	mkdir -p $(BUILD)

.PRECIOUS: $(BUILD)/%.o

# ======================================================================
