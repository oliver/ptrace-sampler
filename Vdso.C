
#include "Vdso.h"
#include "Common.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vector>

using std::vector;


VdsoBinary::VdsoBinary ()
: outFile(NULL)
{
    unsigned int startAddress = 0;
    unsigned int endAddress = 0;
    GetVdsoAddress(startAddress, endAddress);

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


void VdsoBinary::GetVdsoAddress (unsigned int& start, unsigned int& end)
{
    char mapFileName[] = "/proc/self/maps";
    FILE* mapFd = fopen(mapFileName, "r");
    while (true)
    {
        // example line:
        // 08048000-08063000 r-xp 00000000 09:00 1968565    /usr/bin/less

        char line[500];
        memset(line, '\0', sizeof(line));
        const char* result = fgets(line, 500, mapFd);
        if (result == NULL || feof(mapFd))
        {
            break;
        }

        if (strncmp(line+49, "[vdso]", 6) == 0)
        {
            start = strtoll(line, NULL, 16);
            end = strtoll(line+9, NULL, 16);
            break;
        }
    }
    fclose(mapFd);
}

