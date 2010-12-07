

all: app1 app2 ptrace-singlestep ptrace-sampler

app%: app%.C
	g++ -W -Wall -Wextra \
	-g3 -O0 -rdynamic \
	-o $@ \
	$+

ptrace-%: ptrace-%.C
	g++ -W -Wall -Wextra \
	-g3 -O0 \
	-o $@ \
	$+

release: ptrace-sampler
	tar cvzf ../ptrace-sampler-release-`date '+%Y%m%d-%H%M%S'`.tgz \
		ptrace-sampler sample_reader.py samples2calltree.py resolve_addr.py start_sampling.sh

