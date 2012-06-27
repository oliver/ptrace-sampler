
import os
import cPickle as pickle
import urllib
import binascii

class Cacher:
    """
    Generic class for persistent (on-disk) caching of data related to a specific file.
    """

    def __init__ (self):

        self.memCache = {}

        if os.environ.has_key('XDG_CACHE_HOME') and os.environ['XDG_CACHE_HOME']:
            self.basePath = os.path.join(os.environ['XDG_CACHE_HOME'], 'ptrace-sampler')
        else:
            self.basePath = os.path.expanduser('~/.cache/ptrace-sampler/')
        if not(os.path.exists(self.basePath)):
            os.makedirs(self.basePath)
        assert(os.path.isdir(self.basePath))

    def get (self, typ, path, useDisk=True):
        """
        Returns the cached data of given type for the specified path.
        If the specified file has a newer ctime or mtime or if its CRC doesn't
        match the one stored in the cache file, or if there is no matching
        cache file at all, None is returned.
        """

        memKey = (typ, path)
        if self.memCache.has_key(memKey):
            return self.memCache[memKey]

        if not(useDisk):
            return None

        assert(os.path.isfile(path))
        realStat = os.stat(path)
        realTimestamp = max(realStat.st_ctime, realStat.st_mtime)
        realCrc = self._calcCrc(path)

        for f in os.listdir(self.basePath):
            if not f.endswith('.cache'):
                continue

            filePath = os.path.join(self.basePath, f)
            try:
                (ftyp, fpath, fcrc) = f[:-6].split('_')
                ftyp = urllib.unquote(ftyp)
                fpath = urllib.unquote(fpath)
                fcrc = int(fcrc, 16)
                fstat = os.stat(filePath)
                ftimestamp = max(fstat.st_ctime, fstat.st_mtime)

                if ftyp == typ and fpath == path and fcrc == realCrc and ftimestamp >= realTimestamp:
                    fd = open(filePath, 'rb')
                    data = pickle.load(fd)
                    self.memCache[memKey] = data
                    return data
            except:
                continue
        return None

    def store (self, typ, path, data, useDisk=True):
        """
        Adds the given data of given type as cache item for the given path.
        """
        self.memCache[ (typ, path) ] = data

        if useDisk:
            self._invalidate(typ, path)

            cacheFile = self._getFilename(typ, path)
            fd = open(cacheFile, 'wb')
            pickle.dump(data, fd)
            fd.close()

    def _invalidate (self, typ, path):
        "removes all outdated cache entries of the given type for the given path"
        # TODO
        #os.listdir()
        pass

    def _getFilename (self, typ, path):
        assert(os.path.isfile(path))
        crc = self._calcCrc(path)
        fileName = '%s_%s_%08x.cache' % (self._urlquote(typ), self._urlquote(path), crc)
        return os.path.join(self.basePath, fileName)

    def _calcCrc (self, path):
        fd = open(path, 'rb')
        return (binascii.crc32(fd.read()) & 0xffffffff)

    def _urlquote (self, s):
        "Like urllib.quote, but quotes all characters except for letters and numbers"
        res = ''
        for c in s:
            if not(
                (c >= 'a' and c <= 'z') or
                (c >= 'A' and c <= 'Z') or
                #(c in ('.', '-')) or
                (c >= '0' and c <= '9')):
                res += '%%%02x' % ord(c)
            else:
                res += c
        return res

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print "Usage: %s <type> <path>" % sys.argv[0]
        sys.exit(1)

    cache = Cacher()
    data = cache.get(sys.argv[1], sys.argv[2])
    if data is None:
        print "no cached data found"
    else:
        print "found cached data; type: %s; length: %d" % (type(data), len(data))
