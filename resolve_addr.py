#!/usr/bin/python

#
# Resolve symbol address from running process
#

import sys
import time

from sample_reader import Mappings, SymbolResolver


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print "Usage: %s <pid> <addr>" % sys.argv[0]
        sys.exit(1)

    pid = int(sys.argv[1])
    addr = int(sys.argv[2], 0)

    mappings = Mappings()
    fd = open('/proc/%d/maps' % pid)
    for line in fd:
        line = line.rstrip('\n')
        mappings.parseLine(line)
    fd.close()

    resolver = SymbolResolver(mappings)
    res = resolver.resolve(addr)
    #print res

    # result contains: (binary, function name, source file, source line number)
    if res[1] is None:
        print "??"
    else:
        print res[1]

    if res[2] is None:
        sys.stdout.write("??:")
    else:
        sys.stdout.write(res[2]+":")
    if res[3] is None:
        print "??"
    else:
        print res[3]
