#!/usr/bin/python

#
# Read and analyze output from ptrace-sampler
#

import sys
import os
import time
import subprocess
import select
import re

from lib_finder import LibFinder


class Mappings:
    def __init__ (self):
        self.origLines = []
        self.mappings = []

    def parseLine (self, line):
        self.origLines.append(line)

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


class Disassembler:
    def __init__ (self):
        self.tables = {}

    def _disassembleBin (self, binPath):
        'generates a table mapping from an address to the address of the preceding (call) instruction'
        callTable = {}
        #print "disassembling %s ..." % binPath
        objdumpOutput = subprocess.Popen(["objdump", "-d", "-w", "-z", binPath], stdout=subprocess.PIPE).communicate()[0]

        #print "parsing objdump output ..."
        prevAddr = None
        for line in objdumpOutput.split('\n'):
            if not(line.startswith(' ')):
                continue

            line = line[1:] # strip leading space
            (lineAddr, bytes, decoded) = line.split('\t')
            lineAddr = lineAddr.rstrip(':')
            lineAddr = int(lineAddr, 16)
            instr = decoded.split()[0]
            #print "0x%08x: %s|%s|%s" % (lineAddr, bytes, decoded, instr)

            if prevAddr is not None:
                callTable[lineAddr] = prevAddr

            if instr == 'call':
                prevAddr = lineAddr
            else:
                prevAddr = None

        #print "...done"
        return callTable

    def findCallAddress (self, retAddr, binPath):
        "tries to find the call instruction that belongs to a given return target address"

        if not(self.tables.has_key(binPath)):
            table = self._disassembleBin(binPath)
            self.tables[binPath] = table
        else:
            table = self.tables[binPath]

        if table.has_key(retAddr):
            return table[retAddr]
        else:
            print "no matching call site found for 0x%08x in %s" % (retAddr, binPath)
            #raise Exception("not found: 0x%08x in %s" % (retAddr, binPath))
            return retAddr


class NmResolver:
    """ Resolve an address by using "nm" command line tool """
    def __init__ (self, libFinder):
        self.libFinder = libFinder
        self.nmTables = {}

    def resolve (self, binPath, addr):
        "addr must be offsetInLib"

        debugPath = self.libFinder.findDebugBin(binPath)
        return self.resolve_real(debugPath, addr)

    def _getNmTable (self, binPath):
        nmOutput = subprocess.Popen(["nm", "-A", "-C", "-l", "-n", binPath], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
        #print "running nm on %s" % binPath

        table = []
        for line in nmOutput.split('\n'):
            #print "line: '%s'" % line
            if not(line):
                continue

            if line.find('\t') >= 0:
                (prefix, sourceLoc) = line.split('\t', 1)
                (sourceFile, lineNo) = sourceLoc.split(':', 1)
                lineNo = int(lineNo)
            else:
                prefix = line
                sourceFile = None
                lineNo = None

            (binLoc, typ, funcName) = prefix.split(' ', 2)
            (parsedBinPath, parsedAddr) = binLoc.split(':', 1)
            if parsedAddr:
                parsedAddr = int(parsedAddr, 16)
                table.append( (parsedAddr, funcName, sourceFile, lineNo) )
        return table

    def resolve_real (self, binPath, addr):
        #print "looking for 0x%08x in %s" % (addr, binPath)

        if not(self.nmTables.has_key(binPath)):
            table = self._getNmTable(binPath)
            self.nmTables[binPath] = table
        else:
            table = self.nmTables[binPath]

        lastLine = (None, None, None)
        for e in table:
            if e[0] > addr:
                # lastLine now contains the match
                break
            lastLine = e[1:]
        return lastLine


class SymbolResolver:
    # this is just a pile of hacks, based on looking at output from readelf and addr2line...

    def __init__ (self, mappings):
        self.mappings = mappings
        self.mapFile = None
        self.resultCache = {}

        self.a2lProcs = {} # holds a list of running addr2line processes (indexed by binPath)

        self.textSectionOffsetCache = {}
        
        self.libFinder = LibFinder()
        self.disassembler = Disassembler()
        self.nmResolver = NmResolver(self.libFinder)

    def getTextSectionOffset (self, binPath):
        if self.textSectionOffsetCache.has_key(binPath):
            return self.textSectionOffsetCache[binPath]
        else:
            res = self._getTextSectionOffset_real(binPath)
            self.textSectionOffsetCache[binPath] = res
            return res

    def _getTextSectionOffset_real (self, binPath):
        readelfOutput = subprocess.Popen(["readelf", "-S", binPath], stdout=subprocess.PIPE).communicate()[0]
        for line in readelfOutput.split('\n'):
            #m = re.match(r'\s*\[\d+\]\s+\.text\s*')
            line = line.lstrip(' [')
            parts = line.split()
            if len(parts) > 5 and parts[1] == '.text' and parts[2] == 'PROGBITS':
                addr = int(parts[3], 16)
                offset = int(parts[4], 16)
                return (addr, offset)
        return (None, None)

    def addr2line (self, binPath, addr):
        debugBin = self.libFinder.findDebugBin(binPath)
        return self.addr2line_real(debugBin, addr)

    def addr2line_real (self, binPath, addr, cmd=None):
        if not(self.a2lProcs.has_key(binPath)) or self.a2lProcs[binPath] is None:
            # start a2l process:
            cmd = ["addr2line", "-e", binPath, "-f", "-C", "-i"]
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            self.a2lProcs[binPath] = proc

        proc = self.a2lProcs[binPath]

        #if not(self.a2lProcs.has_key(binPath)):
        proc.poll()
        if proc.returncode is not None:
            # error starting a2l
            raise Exception("a2l isn't running")
            return (None, None, None)

        proc.stdin.write("0x%x\n" % addr)

        lines = []
        while True:
            line = proc.stdout.readline()
            if line == '':
                os.kill(proc.pid, 15)
                #proc.send_signal(15)
                self.a2lProcs[binPath] = None
                break
            line = line.rstrip('\n\r')
            lines.append(line)

            (rlist, wlist, xlist) = select.select([proc.stdout], [], [], 0)
            if not(proc.stdout in rlist):
                break

        frames = []
        for linePair in zip( lines[::2], lines[1::2] ):
            funcName = linePair[0].strip()
            if funcName == '??':
                funcName = None

            (sourceFile, lineNo) = linePair[1].strip().rsplit(':', 1)
            lineNo = int(lineNo)
            if sourceFile == '??':
                sourceFile = None
                lineNo = None
            frames.append( (funcName, sourceFile, lineNo) )

        return frames

    def resolve (self, addr, fixAddress=False):
        if self.resultCache.has_key(addr):
            return self.resultCache[addr]
        else:
            res = self._resolveUncached(addr, fixAddress)
            self.resultCache[addr] = res
            return res

    def _resolveUncached (self, addr, fixAddress):
        """
        Returns (lib, function, source file, line number, lib-local function address) tuple
        If fixAddress is True, the address is treated as return address, and the matching
        call instruction is searched and resolved instead.
        """

        assert(addr >= 0)

        m = self.mappings.find(addr)
        if m is None or m[5] is None:
            return {}

        libPath = m[5]
        if not(os.path.exists(libPath)):
            return {'binPath': libPath}

        offsetInBin = addr - m[0][0]
        assert(offsetInBin >= 0)
        (textSectionAddr, textSectionOffset) = self.getTextSectionOffset(libPath)
        if textSectionOffset is None:
            # can happen eg. if function is in /dev/zero...
            return {'binPath': libPath}
        assert(textSectionOffset >= 0)
        offsetInTextSection = offsetInBin - textSectionOffset
        #assert(offsetInTextSection >= 0)

        if offsetInTextSection < 0:
            # not sure why, but this happens sometimes
            return {'binPath': libPath}

        offsetInLib = textSectionAddr + offsetInTextSection
        if fixAddress:
            offsetInLib = self.disassembler.findCallAddress(offsetInLib, libPath)

        resultFrames = []
        for frame in self.addr2line(libPath, offsetInLib):
            (funcName, sourceFile, lineNo) = frame
            if funcName is None:
                # try fall back to "nm" if addr2line can't resolve the function name
                (funcName, dummy, dummy) = self.nmResolver.resolve(libPath, offsetInLib)
            resultFrames.append( (funcName, sourceFile, lineNo) )

        return {'binPath': libPath, 'offsetInBin': offsetInLib, 'frames': resultFrames}


mappings = Mappings()
resolver = SymbolResolver( mappings )


def parseEvent (line):
    #print "line: %s" % line
    (timeStr, stacktrace) = line.split('\t')
    attrs = {}
    if timeStr.find('t=') >= 0:
        # new-style format
        for p in timeStr.split(';'):
            (k,v) = p.split('=')
            attrs[k] = v
    else:
        # old-style format
        attrs['t'] = timeStr

    (timeSec, timeUsec) = attrs['t'].split('.')
    timeSec = int(timeSec, 10)
    timeUsec = int(timeUsec, 10)
    timeF = float(attrs['t'])

    if attrs.has_key('p'):
        pid = int(attrs['p'])
    else:
        pid = None

    regs = {}
    for k,v in attrs.items():
        if k.startswith('r_'):
            regs[ k[2:] ] = int(v, 16)

    frames = []
    addrIndex = 0
    for f in stacktrace.split():
        addr = int(f, 16)

        addrIndex+=1
        res = resolver.resolve(addr, fixAddress=(addrIndex > 1))
        #frames.append( (addr, res) )
        if res.has_key('frames'): # handle detailed list of frames
            for f in res['frames']:
                assert(len(f) == 3)
                frameRes = [addr]
                frameRes.append(res['binPath'])
                frameRes += list(f) # funcName, sourceFile, lineNo
                frameRes.append(res['offsetInBin'])
                assert(len(frameRes) >= 6)
                frames.append( tuple(frameRes) )
                #print res
        else:
            frameRes = [addr]
            if res.has_key('binPath'):
                frameRes.append(res['binPath'])
            else:
                frameRes.append(None)
            frameRes += [None] * 3
            if res.has_key('offsetInBin'):
                frameRes.append(res['offsetInBin'])
            else:
                frameRes.append(None)
            assert(len(frameRes) >= 6)
            frames.append( tuple(frameRes) )

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
    return (timeF, frames, pid, regs)


def parseFile (path, eventHandler=None, headerHandler=None):
    fd = open(path, 'r')
    threads = []
    headerFinished = False
    for line in fd:
        line = line.rstrip('\n')
        if line[0] == '#':
            continue
        elif line.startswith('M: '):
            mappings.parseLine(line[3:])
        elif line.startswith('T: '):
            threads.append(int(line[3:]))
        elif line.startswith('E: '):
            if headerHandler and not(headerFinished):
                header = {'all_threads': threads}
                headerHandler(header)
            headerFinished = True
            result = parseEvent(line[3:])
            if eventHandler is not None:
                eventHandler(result)
        else:
            raise Exception("invalid line: '%s'" % line)


def handleHeader (header):
    if header.has_key('all_threads'):
        print "threads: " + " ".join( [str(t) for t in header['all_threads']] )

def handleEvent (e):
    # e is a tuple of (timestamp, framelist).
    # timestamp is a Unix timestamp as floating-point value.
    # framelist is a list of tuples, representing the stack frames.
    # tuple format:
    # address (int), binary file, function name, source file name, source file line (int)
    # except for address, all values can be None

    displayFrames = []
    for frame in e[1]:
        #print frame
        text = "0x%x" % frame[0]
        if frame[2] is not None:
            # show function name
            text += ": " + frame[2]
            if frame[3] is not None:
                text += " (%s:%d)" % (os.path.basename(frame[3]), frame[4])
        elif frame[1] is not None:
            # show lib name
            text += " (" + os.path.basename(frame[1]) + ")"
        displayFrames.append(text)

    timeUsec = int((e[0] - int(e[0])) * 1000000)
    print "event at %s.%d [pid %d]: %s" % (time.strftime('%c', time.localtime(e[0]) ), timeUsec, e[2], displayFrames)
    #sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Usage: %s <sample data file>" % sys.argv[0]
        sys.exit(1)

    parseFile(sys.argv[1], handleEvent, handleHeader)

