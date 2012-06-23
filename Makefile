

LIBUNWIND_PREFIX:=/usr
BIN=app1 app2 app4 app11-sigchld ptrace-singlestep ptrace-sampler


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

ptrace-sampler: ptrace-sampler.C
	g++ -W -Wall -Wextra \
	-g3 -O0 \
	-o $@ \
	$+ \
	$(LIBUNWIND_OPTIONS)

release: ptrace-sampler
	tar cvzf ../ptrace-sampler-release-`date '+%Y%m%d-%H%M%S'`.tgz \
		ptrace-sampler sample_reader.py samples2calltree.py resolve_addr.py syscalls.py start_sampling.sh

