#!/bin/sh

cmd=$1
pid=`pgrep $cmd`

[ "x$pid" == "x" ] && exit 1

echo "attaching to command '$cmd' (PID $pid)"
tracefile=/tmp/trace-$cmd-`date +%Y%m%d-%H%M%S`-$pid.txt
./ptrace-sampler $pid 2>$tracefile
echo "wrote $tracefile:"
ls -lh $tracefile
