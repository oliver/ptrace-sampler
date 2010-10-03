

all: app1 app2 ptrace-singlestep

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

