

LIBUNWIND_PREFIX:=/usr
LIBBFD_PREFIX:=/usr

BIN=app1 app2 app4 app11-sigchld ptrace-singlestep ptrace-sampler

PTRACE_SAMPLER_CXX_SRCS:=ptrace-sampler.C DebugInterpreter.C Vdso.C

HAVE_LIBUNWIND:=$(shell ls $(LIBUNWIND_PREFIX)/lib/libunwind-ptrace.a 2>/dev/null)
ifeq ($(HAVE_LIBUNWIND),)
    LIBUNWIND_OPTIONS:=
else
    LIBUNWIND_OPTIONS:= \
	-DHAVE_LIBUNWIND=1 \
	-I$(LIBUNWIND_PREFIX)/include/ \
	-L$(LIBUNWIND_PREFIX)/lib/ \
	-lunwind-ptrace -lunwind-generic
endif

HAVE_LIBBFD:=$(shell ls $(LIBBFD_PREFIX)/lib/libbfd.a 2>/dev/null)
ifeq ($(HAVE_LIBBFD),)
    LIBBFD_OPTIONS:=
else
    LIBBFD_OPTIONS:= \
	-DHAVE_LIBBFD=1 \
	-I$(LIBBFD_PREFIX)/include/ \
	-L$(LIBBFD_PREFIX)/lib/ \
	-lbfd -lopcodes -liberty

    PTRACE_SAMPLER_CXX_SRCS+=Disassembler.C DebugCreator.C
endif


all: $(BIN)

clean:
	rm -f $(BIN)

app%: app%.C
	g++ -W -Wall -Wextra \
	-g3 -O0 -rdynamic \
	-pthread \
	-o $@ \
	$+

ptrace-%: ptrace-%.C
	g++ -W -Wall -Wextra \
	-g3 -O0 \
	-o $@ \
	$+

ptrace-sampler: $(PTRACE_SAMPLER_CXX_SRCS)
	g++ -W -Wall -Wextra \
	-g3 -O2 \
	-I. \
	-o $@ \
	$+ \
	$(LIBBFD_OPTIONS) \
	$(LIBUNWIND_OPTIONS)

release: ptrace-sampler
	tar cvzf ../ptrace-sampler-release-`date '+%Y%m%d-%H%M%S'`.tgz \
		ptrace-sampler sample_reader.py samples2calltree.py resolve_addr.py syscalls.py start_sampling.sh

