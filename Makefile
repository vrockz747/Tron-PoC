# Include the nanopb provided Makefile rules
include ./nanopb/extra/nanopb.mk

# Compiler flags to enable all warnings & debug info
CFLAGS = -Wall -Werror -g -O0
CFLAGS += "-I$(NANOPB_DIR)"

# C source code files that are required
CSRC  = main.c                   # The main program
CSRC += ./proto/tron.pb.c                # The compiled protocol definition
CSRC += ./proto/any.pb.c                # The compiled protocol definition
CSRC += $(NANOPB_DIR)/pb_encode.c  # The nanopb encoder
CSRC += $(NANOPB_DIR)/pb_decode.c  # The nanopb decoder
CSRC += $(NANOPB_DIR)/pb_common.c  # The nanopb common parts


# Build rule for the main program
main: $(CSRC)
	$(CC) $(CFLAGS) -omain $(CSRC)

# Build rule for the protocol
# currently using https://github.com/LedgerHQ/app-tron/blob/6a86b1147a5ffa4c52ed9eb38e5590d2cf91eefc/proto/core/Tron.pb.h
# dir has associated .py to compile Tron.proto
tron.pb.c: tron.proto 
	$(PROTOC) $(PROTOC_OPTS) --nanopb_out=. tron.proto

any.pb.c: any.proto
	$(PROTOC) $(PROTOC_OPTS) --nanopb_out=. any.proto


