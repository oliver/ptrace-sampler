
#include "Vdso.h"
#include "Common.h"
#include "MemoryMappings.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vector>
#include <unistd.h>

using std::vector;


VdsoBinary::VdsoBinary ()
: outFile(NULL)
{
    const MemoryMappings allMappings(getpid());
    const MemoryMappings::Mapping* vdsoMemory = allMappings.Find("[vdso]");
    if (!vdsoMemory)
    {
        return;
    }
    const unsigned int startAddress = vdsoMemory->start;
    const unsigned int endAddress = vdsoMemory->end;

    const int size = endAddress - startAddress;
    if (size <= 0 || size > 100000)
    {
        printf("invalid VDSO size %d\n", size);
        return;
    }

    char memPath[] = "/proc/self/mem";
    const int memFd = open(memPath, O_RDONLY);
    if (!memFd)
    {
        printf("failed to open %s: %s (%d)\n", memPath, strerror(errno), errno);
        return;
    }

    const off64_t seekResult = lseek64(memFd, startAddress, SEEK_SET);
    if (seekResult == -1)
    {
        printf("seeking to 0x%x in %s failed: %s (%d)\n", startAddress, memPath, strerror(errno), errno);
        close(memFd);
        return;
    }

    vector<char> data;
    data.resize(size+1);
    errno = 0;
    const int bytesRead = read(memFd, &(data[0]), size);
    if (bytesRead != size)
    {
        printf("reading from %s failed: read %d bytes, expected %d bytes; error: %s (%d)\n",
            memPath, bytesRead, size, strerror(errno), errno);
        close(memFd);
        return;
    }
    close(memFd);

    static const char pathTemplate[] = "/tmp/extracted-vdso.bin.XXXXXX";
    vector<char> tempName;
    tempName.resize(sizeof(pathTemplate));
    memcpy(&(tempName[0]), pathTemplate, sizeof(pathTemplate));

    const int tempFd = mkstemp(&(tempName[0]));
    this->outFile = fdopen(tempFd, "w");
    if (!this->outFile)
    {
        printf("opening temp fd %d (for file '%s') failed: %s (%d)\n", tempFd, &(tempName[0]), strerror(errno), errno);
        close(tempFd);
        return;
    }
    const int bytesWritten = fwrite(&(data[0]), 1, size, this->outFile);
    if (bytesWritten != size)
    {
        printf("writing to %s failed: wrote %d bytes of %d bytes; error: %s (%d)\n",
            &(tempName[0]), bytesWritten, size, strerror(errno), errno);
        return;
    }

    this->path = string(&(tempName[0]));
    DEBUG("VDSO path: %s", this->path.c_str());
}


VdsoBinary::~VdsoBinary ()
{
    if (this->outFile)
    {
        fclose(this->outFile);
        this->outFile = NULL;
    }
    if (!this->path.empty())
    {
        unlink(this->path.c_str());
    }
}


string VdsoBinary::Path () const
{
    return this->path;
}
