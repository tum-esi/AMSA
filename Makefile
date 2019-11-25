
# target binary
BIN := amss
BIN_DIR := bin
TESTS := test_hashes test_wots test_merkle test_amsa 

# PREFIX ?= arm-none-eabi

# select compiler
CXX := gcc
#CXXFLAGS = -g -Wall -O0 -fno-omit-frame-pointer # debug
CXXFLAGS = -Wall -O3  # benchmarking
CSTD ?= -std=c99   # c18

# sources
SRC_EXT := .c
SRC_DIR := src
SRC_SUBDIRS := hashes util

# include paths (space separated)
INC_DIRS = . ./hashes /usr/include

# library paths (space separated)
LIB_DIRS := # /usr/lib/x86_64-linux-gnu/openssl

# library names e.g. "pthread" or crypto"
LIB_NAMES := #crypto  # uncomment for SSL

# where to store the objects
OBJ_DIR := ./obj
OBJ_EXT := .o


# Do not etdit below this line
# ----------------------------------------------------

# find and collect sources
SRCS := $(wildcard $(SRC_DIR)/*$(SRC_EXT))
SRCS += $(foreach subdir,$(SRC_SUBDIRS),$(wildcard $(SRC_DIR)/$(subdir)/*$(SRC_EXT)))

# collect includes
INCS += $(foreach idir,$(INC_DIRS),-I$(idir))

# collect libraries
LIBS += $(foreach ldir,$(LIB_DIRS),-L$(ldir))
LIBS += $(foreach lname,$(LIB_NAMES),-l$(lname))

# determine objects to build based on sources
OBJS += $(patsubst $(SRC_DIR)/%$(SRC_EXT), $(OBJ_DIR)/%.o, $(SRCS))
OBJS := $(OBJS:$(SRC_EXT)=$(OBJ_EXT))  # double protection

# determine objects to link for binaries
LINKOBJ := $(filter-out $(OBJ_DIR)/main.o,$(OBJS))

# add flags
CXXFLAGS += -include src/config.h


# available targets
# ----------------------------------------------------
all: echo mkobjdirs tests

lib: amsa_lib.a

tests: $(TESTS)

clean:
	@rm -f $(BIN_DIR)/$(BIN) $(OBJS) 


# Internal rules
# ----------------------------------------------------
echo:
	@echo "Compiling with $(CXX) $(CXXFLAGS)"
	@echo "Includes:  $(INCS)"
	@echo "Libraries: $(LIBS)"
	@echo "Sources:   $(SRCS)"
	@echo "Objects:   $(OBJS)"
	@echo ""	

amsa_lib.a: obj/amss.o obj/hash.o obj/merkle.o obj/wots.o obj/hashes/sha256.o
	$(AR) rcs $@ $^

mkobjdirs:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(foreach subdir, $(SRC_SUBDIRS), $(OBJ_DIR)/$(subdir))

# link objects
main: $(OBJS)
	@echo "Linking $@..."	
	$(CXX) $^ -o $(BIN_DIR)/$(BIN) $(CXXFLAGS) $(INCS) $(LIBS)


# compile sources to objects	
$(TESTS): $(OBJS)
	@echo "\nLinking $@:"
	$(CXX) $(LINKOBJ) src/bin/$@.c -o $(BIN_DIR)/$@ $(CXXFLAGS) $(INCS) $(LIBS)


# compile sources to objects	
$(OBJ_DIR)/%$(OBJ_EXT):$(SRC_DIR)/%$(SRC_EXT)
	$(CXX) -c -o $@ $< $(CXXFLAGS) 



# will be called even if newest files exists
.PHONY: clean


# References
# https://ubuntuforums.org/showthread.php?t=1204739
