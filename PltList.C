
#include "PltList.h"
#include "Common.h"

#ifdef HAVE_LIBBFD
#include <bfd.h>
#endif


bool PltList::AddPlt (const MemoryMappings::Mapping& mapping)
{
#ifndef HAVE_LIBBFD
    return false;
#else
    DEBUG("looking for PLT section in '%s'", mapping.name.c_str());

    bfd_init();

    bfd* abfd = bfd_openr(mapping.name.c_str(), NULL);
    if (!abfd)
    {
        return false;
    }

    const int formatOk = bfd_check_format(abfd, bfd_object);
    if (!formatOk)
    {
        bfd_close(abfd);
        return false;
    }

    const asection* pltSectionPtr = bfd_get_section_by_name(abfd, ".plt");
    if (!pltSectionPtr)
    {
        bfd_close(abfd);
        return false;
    }

    Section newSection;
    newSection.start = mapping.start + pltSectionPtr->filepos;
    newSection.end = newSection.start + pltSectionPtr->size;
    this->sections.push_back(newSection);

    bfd_close(abfd);

    return true;
#endif
}


const PltList::Section* PltList::FindContainingPlt (const unsigned long addr) const
{
    for (vector<Section>::const_iterator it = this->sections.begin();
         it != this->sections.end(); ++it)
    {
        if (addr >= it->start && addr <= it->end)
        {
            return &(*it);
        }
    }
    return NULL;
}
