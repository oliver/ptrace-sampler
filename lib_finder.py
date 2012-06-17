
import os
import subprocess
import binascii
import struct

class LibFinder:
    def __init__ (self):
        self.resultCache = {}

    def _getDebugLink (self, binPath):
        objdumpOutput = subprocess.Popen(["objdump", "-s", "-w", "-j", ".gnu_debuglink", binPath], stdout=subprocess.PIPE).communicate()[0]

        debugName = None
        debugCrc = None

        #print "parsing objdump output ..."
        bytes = ''
        for line in objdumpOutput.split('\n'):
            if not(line.startswith(' ')):
                continue

            line = line[1:] # strip leading space
            (addr, asciiBytes) = line.split(' ', 1)
            dwords = asciiBytes.split(' ', 4)[:4]
            bytes += binascii.a2b_hex("".join(dwords))

        pos = bytes.find('\0')
        if pos >= 0:
            debugName = bytes[:pos]
            remainder = bytes[pos+1:]
            crcBytes = remainder[-4:]
            if len(crcBytes) == 4:
                debugCrc = struct.unpack('L', crcBytes)[0]

        #print "crc: 0x%x" % debugCrc
        return (debugName, debugCrc)

    def _calcCrc (self, path):
        fd = open(path, 'rb')
        return (binascii.crc32(fd.read()) & 0xffffffff)

    def findDebugBin (self, binPath):
        """
        Returns the path of an external debuginfo library, or None if no
        matching debuginfo library could be found.
        """
        if self.resultCache.has_key(binPath):
            return self.resultCache[binPath]
        else:
            res = self._findDebugBin_uncached(binPath)
            self.resultCache[binPath] = res
            return res

    def _findDebugBin_uncached (self, binPath):
        (debugName, debugCrc) = self._getDebugLink(binPath)
        if debugName is None:
            debugName = os.path.basename(binPath)

        templates = [
            "%(dir)s/%(name)s",
            "%(dir)s/%(name)s.debug",
            "%(dir)s/%(debug)s",
            "%(dir)s/%(debug)s.debug",
            "%(dir)s/.debug/%(debug)s",
            "%(dir)s/.debug/%(debug)s.debug",
            "/usr/lib/debug/%(dir)s/%(debug)s",
            "/usr/lib/debug/%(dir)s/%(debug)s.debug",
        ]

        for t in templates:
            path = t % {'dir': os.path.dirname(binPath), 'name': os.path.basename(binPath), 'debug': debugName}
            #print "checking '%s' ..." % path
            if not(os.path.exists(path)):
                continue
            if debugCrc is not None:
                crc = self._calcCrc(path)
                if crc == debugCrc:
                    #print "debug file %s has matching CRC" % path
                    return path
                elif path.find('debug') >= 0:
                    print "debug file %s exists but CRC doesn't match (found 0x%08x, expected 0x%08x)" % (path, crc, debugCrc)

        return None

if __name__ == '__main__':
    import sys
    libFinder = LibFinder()
    origBinary = sys.argv[1]
    debugBinary = libFinder.findDebugBin(origBinary)
    if debugBinary is None:
        print "no separate debug symbols found for '%s'" % origBinary
    else:
        print "debug symbols for '%s' are stored in '%s'" % (origBinary, debugBinary)

