

#include "MemoryMappings.h"
#include "Common.h"

#include <stdlib.h>
#include <string.h>


MemoryMappings::MemoryMappings (const int pid)
{
    const vector<string> lines = RawLines(pid);
    for (unsigned int i = 0; i < lines.size(); ++i)
    {
        const char* line = lines[i].c_str();
        Mapping m;
        m.start = strtoll(line, NULL, 16);
        m.end = strtoll(line+9, NULL, 16);
        m.name = string(line+49);
        m.name = m.name.substr(0, m.name.length()-1);
        m.isExecutable = (line[20] == 'x');
        this->mappings.push_back(m);
    }
}

const MemoryMappings::Mapping* MemoryMappings::Find (const string& name) const
{
    for (const_iterator it = this->Begin(); it != this->End(); ++it)
    {
        if (it->name == name)
        {
            return &(*it);
        }
    }
    return NULL;
}


vector<MemoryMappings::Mapping>::const_iterator MemoryMappings::Begin () const
{
    return this->mappings.begin();
}

vector<MemoryMappings::Mapping>::const_iterator MemoryMappings::End () const
{
    return this->mappings.end();
}

unsigned int MemoryMappings::Size () const
{
    return this->mappings.size();
}


vector<string> MemoryMappings::RawLines (const int pid)
{
    vector<string> lines;

    char mapFileName[200];
    sprintf(mapFileName, "/proc/%d/maps", pid);
    FILE* mapFd = fopen(mapFileName, "r");
    if (!mapFd)
    {
        return lines;
    }

    while (true)
    {
        char line[500];
        memset(line, '\0', sizeof(line));
        const char* result = fgets(line, sizeof(line), mapFd);
        if (result == NULL || feof(mapFd))
        {
            break;
        }
        lines.push_back(line);
    }
    fclose(mapFd);

    return lines;
}
