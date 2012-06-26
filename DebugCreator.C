
#include "DebugCreator.h"
#include "Common.h"
#include "Disassembler.h"

#include <string.h>
#include <algorithm>


class DebugCreator : public Disassembler
{
public:
    DebugCreator (DI::DebugTable& debugTable,
                  bfd* abfd,
                  asection* section,
                  const unsigned int segmentMapAddress,
                  char* sectionContents,
                  const unsigned int startAddress,
                  const unsigned int endAddress);

    virtual bool HandleInstruction (const unsigned int addr,
                                    const unsigned int /*length*/,
                                    const InsType insType,
                                    const vector<char*>& args);

private:
    DI::DebugTable& debugTableRef;
    const unsigned int segmentMapAddress;
    asection* section;

    int stackSize;
    bool ebpPushed;
    int ebpStackOffset;
};


DebugCreator::DebugCreator (DI::DebugTable& debugTable_,
                            bfd* abfd_,
                            asection* section_,
                            const unsigned int segmentMapAddress_,
                            char* sectionContents_,
                            const unsigned int startAddress,
                            const unsigned int endAddress)
: debugTableRef(debugTable_),
segmentMapAddress(segmentMapAddress_),
section(section_),
stackSize(0),
ebpPushed(false),
ebpStackOffset(0)
{
    this->Disassemble(abfd_, section_, sectionContents_, startAddress, endAddress);
}

bool DebugCreator::HandleInstruction (const unsigned int addr,
                                      const unsigned int /*length*/,
                                      const InsType insType,
                                      const vector<char*>& args)
{
    const unsigned int vdsoTextSectionOffset = this->section->filepos;

    const unsigned int sectionRelativePc = addr - this->section->vma;
    const unsigned int segmentRelativeIp = sectionRelativePc + vdsoTextSectionOffset;
    const unsigned int processLocalPc = segmentMapAddress + segmentRelativeIp;

    /// debug instructions for getting EBP:
    {
        DI::ExecChain ec;
        if (ebpPushed)
        {
            if (this->ebpStackOffset == 4)
            {
                // ebp has been saved as first element on stack;
                // hence we can use normal frame pointer walking for this function,
                // and won't need additional debug info:
                DEBUG("stopping debug info generation because function effectively has good prolog");
                return false;
            }
            // get EBP from stack:
            ec.push_back( new DI::FuncReadStackValue(this->stackSize - this->ebpStackOffset) );
        }
        else
        {
            // EBP has not been saved so far; as EBP must be restored by each function,
            // it must still be valid:
            ec.push_back( new DI::FuncReadReg(DI::REG_EBP) );
        }
        this->debugTableRef.AddDebugInfo(DI::REG_EBP, processLocalPc, ec);
    }

    /// debug instructions for getting EIP:
    {
        DI::ExecChain ec;
        ec.push_back( new DI::FuncReadStackValue(this->stackSize) );
        this->debugTableRef.AddDebugInfo(DI::REG_EIP, processLocalPc, ec);
    }

    /// debug instructions for getting ESP (as it was at function entry):
    {
        DI::ExecChain ec;
        ec.push_back( new DI::FuncReadReg(DI::REG_ESP) );
        ec.push_back( new DI::FuncAdd( this->stackSize+4 ) );
        this->debugTableRef.AddDebugInfo(DI::REG_ESP, processLocalPc, ec);
    }

    switch (insType)
    {
        case INS_UNKNOWN:
            break;
        case INS_MOV:
            // TODO
            break;
        case INS_PUSH:
            if (strcmp(args[0], "%ebp") == 0)
            {
                this->ebpPushed = true;
                this->ebpStackOffset = this->stackSize+4;
            }
            this->stackSize += 4;
            break;
        case INS_POP:
            if (strcmp(args[0], "%ebp") == 0)
            {
                this->ebpPushed = false;
                ebpStackOffset = -1;
            }
            this->stackSize -= 4;
            break;
    }
    return true;
}


struct SymbolAddressSort
{
    bool operator() (const asymbol* a, const asymbol* b)
    {
        return (a->value < b->value);
    }
};

void CreateDebugInfo (DI::DebugTable& debugTable,
                      const string& binPath,
                      const unsigned int mapAddress)
{
    bfd_init();

    bfd* abfd = bfd_openr(binPath.c_str(), NULL);
    DEBUG("abfd for '%s': %p", binPath.c_str(), abfd);
    if (!abfd)
    {
        return;
    }

    const int formatOk = bfd_check_format(abfd, bfd_object);
    DEBUG("formatOk: %d", formatOk);
    if (!formatOk)
    {
        return;
    }

    const int size = bfd_get_dynamic_symtab_upper_bound(abfd);
    typedef std::vector<asymbol*> SymbolArray;
    SymbolArray asymtab;
    asymtab.resize(size / sizeof(asymbol*));
    const int numSymbols = bfd_canonicalize_dynamic_symtab(abfd, &(asymtab[0]));
    DEBUG("size: %d; numSymbols: %d", size, numSymbols);
    asymtab.resize(numSymbols);
    std::sort(asymtab.begin(), asymtab.end(), SymbolAddressSort());

    asection* textSection = bfd_get_section_by_name(abfd, ".text");
    bfd_byte* textSectionContents;
    bfd_malloc_and_get_section(abfd, textSection, &textSectionContents);

    for (unsigned int i = 0; i < asymtab.size(); ++i)
    {
        if (i > 0 && asymtab[i-1]->value == asymtab[i]->value && asymtab[i-1]->section == asymtab[i]->section)
        {
            // skip over symbols location which were handled already 
            continue;
        }

        asection* section = asymtab[i]->section;
        if (string(section->name) != ".text")
        {
            continue;
        }

        // peek at first bytes in function:
        const bfd_byte* startAddress = textSectionContents + asymtab[i]->value;
        const unsigned int* firstBytes = (unsigned int*)(startAddress);

        // A "good" function prolog (which saves the frame pointer and also can
        // be detected by ptrace-sampler at runtime) looks like this:
        //   55      push %ebp
        //   89 e5   mov %esp,%ebp
        static const unsigned int goodPrologBytes = 0xe58955;

        const bool haveGoodProlog = (((*firstBytes) & 0xFFFFFF) == goodPrologBytes);
        if (!haveGoodProlog)
        {
            DEBUG("    sym #%d; name: %s; value: 0x%llx; flags: 0x%x; section name: %s",
                i, asymtab[i]->name, asymtab[i]->value, asymtab[i]->flags, asymtab[i]->section->name);

            unsigned long long nextAddress = 0;
            bool foundNextAddress = false;
            for (unsigned int j = i+1; j < asymtab.size(); j++)
            {
                nextAddress = asymtab[j]->value;
                if (nextAddress != asymtab[i]->value)
                {
                    foundNextAddress = true;
                    break;
                }
            }
            if (!foundNextAddress)
            {
                nextAddress = asymtab[i]->section->size;
            }

            const unsigned long long symbolSize = nextAddress - asymtab[i]->value;
            DEBUG("      nextAddress: 0x%08llx; symbol size: 0x%llx", nextAddress, symbolSize);

            DebugCreator st(debugTable, abfd, asymtab[i]->section,
                mapAddress,
                (char*)textSectionContents,
                asymtab[i]->value + asymtab[i]->section->vma,
                asymtab[i]->value + asymtab[i]->section->vma + symbolSize);
        }
    }

    free(textSectionContents);

    bfd_close(abfd);
    DEBUG("finished %s", binPath.c_str());
}
