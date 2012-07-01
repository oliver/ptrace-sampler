#ifndef PLT_LIST_H
#define PLT_LIST_H

#include "MemoryMappings.h"
#include <string>
using std::string;


/// @brief Stores a list of PLT ("Procedure Linkage Table") sections
class PltList
{
public:
    struct Section
    {
        /// start of PLT section (in current process memory)
        unsigned long start;
        /// end of PLT section
        unsigned long end;
    };

    /// Adds the PLT section of the binary of the specified memory mapping
    /// to the internal list.
    bool AddPlt (const MemoryMappings::Mapping& mapping);

    /// Searches the internal for a PLT section containing the specified address.
    /// Returns NULL if addr is not in any PLT section.
    const Section* FindContainingPlt (const unsigned long addr) const;

private:
    vector<Section> sections;
};

#endif
