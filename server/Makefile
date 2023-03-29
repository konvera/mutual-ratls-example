# Build Server as follows:
#
# - make               -- create non-SGX no-debug-log manifest
# - make SGX=1         -- create SGX no-debug-log manifest
# - make SGX=1 DEBUG=1 -- create SGX debug-log manifest
#
# Use `make clean` to remove Gramine-generated files

################################# CONSTANTS ###################################

# directory with arch-specific libraries, used by Server
# the below path works for Debian/Ubuntu; for CentOS/RHEL/Fedora, you should
# overwrite this default like this: `ARCH_LIBDIR=/lib64 make`
ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ENCLAVE_SIZE ?= 1G

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: server server.manifest
ifeq ($(SGX),1)
all: server.manifest.sgx server.sig
endif

# Build server
server:
	go build -o server server.go

################################ server MANIFEST ###############################

# The template file is a Jinja2 template and contains almost all necessary
# information to run Server under Gramine / Gramine-SGX. We create
# server.manifest (to be run under non-SGX Gramine) by replacing variables
# in the template file using the "gramine-manifest" script.

RA_TYPE		?= none
ISVPRODID	?= 0
ISVSVN		?= 0

server.manifest: server.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dratls_enclave_path="/tls" \
		-Dserver_bin="server" \
		-Dra_type=$(RA_TYPE) \
		-Disvprodid=$(ISVPRODID) \
		-Disvsvn=$(ISVSVN) \
		-Denclave_size=$(ENCLAVE_SIZE) \
		$< >$@

# Manifest for Gramine-SGX requires special "gramine-sgx-sign" procedure. This
# procedure measures all server's trusted files, adds the measurement to the
# resulting manifest.sgx file (among other, less important SGX options) and
# creates server.sig (SIGSTRUCT object).

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the gramine helloworld example for details on this workaround.
server.manifest.sgx server.sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: server.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.sig *.args OUTPUT* server

.PHONY: distclean
distclean: clean