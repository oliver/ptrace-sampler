#!/bin/bash

arg=$1

ps -p $arg &> /dev/null
if [ $? == 0 ]; then
    # arg is a valid PID
    pid=$arg
else
    pid=`pgrep $arg`
    numProcs=`echo $pid | wc -w`
    if [ "x$numProcs" == "x0" ]; then
        echo "no process matching '$arg'"
        exit 1
    fi

    if [ "x$numProcs" != "x1" ]; then
        echo "$numProcs processes matching '$arg'"
        exit 1
    fi
fi

[ "x$pid" == "x" ] && exit 1


echo "attaching to '$arg' (PID $pid)"
tracefile=/tmp/trace-$arg-`date +%Y%m%d-%H%M%S`-$pid.txt
./ptrace-sampler $pid 2>$tracefile
echo "wrote $tracefile:"
ls -lh $tracefile

./samples2calltree.py $tracefile
calltree=calltree.`basename $tracefile`
ls -lh $calltree
kcachegrind $calltree &
