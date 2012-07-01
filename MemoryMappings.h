#ifndef MEMORY_MAPPINGS_H_
#define MEMORY_MAPPINGS_H_

#include <string>
#include <vector>
using std::string;
using std::vector;


class MemoryMappings
{
public:
    struct Mapping
    {
        unsigned int start;
        unsigned int end;
        string name;
        bool isExecutable; ///< whether the "x" flag is set
    };

    MemoryMappings (const int pid);

    const Mapping* Find (const string& name) const;

    typedef vector<Mapping>::const_iterator const_iterator;
    vector<Mapping>::const_iterator Begin () const;
    vector<Mapping>::const_iterator End () const;
    unsigned int Size () const;

    static vector<string> RawLines (const int pid);

private:
    vector<Mapping> mappings;
};

#endif
