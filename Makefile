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

OPTIMIZATION = -O3
CXXFLAGS = -MMD -g $(OPTIMIZATION) -fPIC -std=$(STD) $(WEVERYTHING) $(WARNINGS) $(INCLUDES)
CFLAGS = -MMD -g $(OPTIMIZATION) -fPIC $(WARNINGS) $(INCLUDES)
LDFLAGS =
LDLIBS =

BUILD = build
DIST = dist

# ----------------------------------------------------------------------

SOURCES = bcs.cc bcs-encrypt.cc file.cc server.cc

# ----------------------------------------------------------------------

AESCRYPT_ROOT = AESCrypt/Linux
AESCRYPT_SRC = $(AESCRYPT_ROOT)/src
INCLUDES += -I$(AESCRYPT_ROOT) -I$(AESCRYPT_SRC)
AESCRYPT_CONFIG_H = $(AESCRYPT_ROOT)/config.h
AESCRYPT_SOURCES = aes.c sha256.c password.c keyfile.c aesrandom.c util.c
AESCRYPT_OBJ = $(patsubst %.c,$(BUILD)/%.o,$(AESCRYPT_SOURCES))

# ----------------------------------------------------------------------

all: $(DIST)/bcs
	@#$(DIST)/bcs

clean:
	rm -rf $(DIST) $(BUILD)

-include $(BUILD)/*.d

# ----------------------------------------------------------------------

$(DIST)/bcs: $(patsubst %.cc,$(BUILD)/%.o,$(SOURCES)) $(AESCRYPT_OBJ) | $(DIST)
	g++ $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: %.cc $(AESCRYPT_CONFIG_H) | $(BUILD) $(BUILD)/submodules
	@#echo $<
	g++ $(CXXFLAGS) -c -o $@ $<

$(BUILD)/%.o: $(AESCRYPT_SRC)/%.c | $(AESCRYPT_CONFIG_H) $(BUILD) $(BUILD)/submodules
	gcc $(CFLAGS) -c -o $@ $<

# ----------------------------------------------------------------------

$(AESCRYPT_CONFIG_H): $(AESCRYPT_ROOT)/Makefile.am
	cd $(AESCRYPT_ROOT) && autoreconf -i && ./configure

$(AESCRYPT_ROOT)/Makefile.am: | $(BUILD)/submodules

$(BUILD)/submodules: | $(BUILD)
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
