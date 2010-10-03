

all: app1

app%: app%.C
	g++ -W -Wall -Wextra \
	-g3 -O0 -rdynamic \
	-o $@ \
	$+

