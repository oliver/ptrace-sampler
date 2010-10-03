#!/usr/bin/python

#
# Read and analyze output from ptrace-sampler
#

import sys
import os
import time
import subprocess
import re


class Mappings:
    def __init__ (self):
        self.mappings = []
        pass

    def parseLine (self, line):
        # b74b3000-b760f000 r-xp 00000000 09:00 9593032    /lib/tls/i686/cmov/libc-2.9.so
        #(addrs, perms, offset, dev, inode, path) = line.split()
        parts = line.split()

        addrs = parts[0].split('-')
        start = int(addrs[0], 16)
        end = int(addrs[1], 16)

        perms = parts[1]
        offset = int(parts[2], 16)
        dev = parts[3]
        inode = int(parts[4])
        if len(parts) > 5:
            path = parts[5]
        else:
            path = None

        self.mappings.append( ((start, end), perms, offset, dev, inode, path) )

    def find (self, addr):
        for m in self.mappings:
            if m[0][0] <= addr and m[0][1] >= addr:
                return m
        return None


class SymbolResolver:
    # this is just a pile of hacks, based on looking at output from readelf and addr2line...

    def __init__ (self, mappings):
        self.mappings = mappings
        self.resultCache = {}

    def addr2line (self, binPath, addr):
        a2lOutput = subprocess.Popen(["addr2line", "-e", binPath, "-f", "-C", "0x%x" % addr],
            stdout=subprocess.PIPE).communicate()[0]
        lines = a2lOutput.split('\n')
        if len(lines) != 3:
            raise Exception("bad output from addr2line (got %d lines, expected 3)" % len(lines))
        funcName = lines[0]
        if funcName == '??':
            funcName = None
        (sourceFile, lineNo) = lines[1].rsplit(':', 1)
        lineNo = int(lineNo)
        if sourceFile == '??':
            sourceFile = None
            lineNo = None
        return (funcName, sourceFile, lineNo)

    def resolve (self, addr):
        if self.resultCache.has_key(addr):
            return self.resultCache[addr]
        else:
            res = self._resolveUncached(addr)
            self.resultCache[addr] = res
            return res

    def _resolveUncached (self, addr):
        """ Returns (lib, function, source file, line number) tuple """

        m = self.mappings.find(addr)
        if m is None or m[5] is None:
            return (None, None, None, None)

        libPath = m[5]
        if not(os.path.exists(libPath)):
            return (libPath, None, None, None)

        readelfSummary = subprocess.Popen(["readelf", "-h", libPath], stdout=subprocess.PIPE).communicate()[0]
        if re.search('Type:\s+EXEC ', readelfSummary):
            # executable
            (funcName, sourceFile, lineNo) = self.addr2line(libPath, addr)
            return (libPath, funcName, sourceFile, lineNo)
        elif re.search('Type:\s+DYN ', readelfSummary):
            # lib
            offset = addr - m[0][0]
            (funcName, sourceFile, lineNo) = self.addr2line(libPath, offset)
            return (libPath, funcName, sourceFile, lineNo)
        else:
            # unknown type
            raise Exception("unrecognized ELF format in '%s'" % libPath)

        return (libPath, None, None, None)


mappings = Mappings()
resolver = SymbolResolver( mappings )


def parseEvent (line):
    #print "line: %s" % line
    (timeStr, stacktrace) = line.split('\t')
    (timeSec, timeUsec) = timeStr.split('.')
    timeSec = int(timeSec, 10)
    timeUsec = int(timeUsec, 10)
    timeF = float(timeStr)

    frames = []
    for f in stacktrace.split():
        addr = int(f, 16)

        res = resolver.resolve(addr)
        #frames.append( (addr, res) )
        frameRes = [addr]
        if res:
            frameRes += list(res)
        frames.append( tuple(frameRes) )
        #print res

#         if res[1] is not None:
#             # show function name
#             displayFrames.append( res[1] )
#         elif res[0] is not None:
#             # show lib name
#             displayFrames.append( "(" + os.path.basename(res[0]) + ")" )
#         else:
#             displayFrames.append( "0x%x" % addr )

#        m = mappings.find(addr)
#        if m:
#            #print m
#            if m[5]:
#                print os.path.basename(m[5])

    #print "event at %s.%d: %s" % (time.strftime('%c', time.localtime(timeF) ), timeUsec, displayFrames)
    return (timeF, frames)


def parseFile (path, eventHandler=None):
    fd = open(path, 'r')
    for line in fd:
        line = line.rstrip('\n')
        if line[0] == '#':
            continue
        elif line.startswith('M: '):
            mappings.parseLine(line[3:])
        elif line.startswith('E: '):
            result = parseEvent(line[3:])
            if eventHandler is not None:
                eventHandler(result)
        else:
            raise Exception("invalid line: '%s'" % line)


def handleEvent (e):
    displayFrames = []
    for frame in e[1]:
        #print frame
        if frame[2] is not None:
            # show function name
            text = frame[2]
            if frame[3] is not None:
                text += " (%s:%d)" % (os.path.basename(frame[3]), frame[4])
            displayFrames.append( text )
        elif frame[1] is not None:
            # show lib name
            displayFrames.append( "(" + os.path.basename(frame[1]) + ")" )
        else:
            displayFrames.append( "0x%x" % frame[0] )

    timeUsec = int((e[0] - int(e[0])) * 1000000)
    print "event at %s.%d: %s" % (time.strftime('%c', time.localtime(e[0]) ), timeUsec, displayFrames)
    #sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Usage: %s <sample data file>" % sys.argv[0]
        sys.exit(1)

    parseFile(sys.argv[1], handleEvent)

