
#include "DebugCreator.h"
#include "Common.h"
#include "Disassembler.h"

#include <algorithm>


class DebugCreator : public Disassembler
{
public:
    DebugCreator (DI::DebugTable& debugTable,
                  bfd* abfd,
                  asection* section,
                  const unsigned int segmentMapAddress,
                  const unsigned int startAddress,
                  const unsigned int endAddress);

    virtual void HandleInstruction (const unsigned int addr,
                                    const unsigned int /*length*/,
                                    const InsType insType,
                                    const vector<string>& args);

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
                            const unsigned int startAddress,
                            const unsigned int endAddress)
: debugTableRef(debugTable_),
segmentMapAddress(segmentMapAddress_),
section(section_),
stackSize(0),
ebpPushed(false),
ebpStackOffset(0)
{
    this->Disassemble(abfd_, section_, startAddress, endAddress);
}

void DebugCreator::HandleInstruction (const unsigned int addr,
                                      const unsigned int /*length*/,
                                      const InsType insType,
                                      const vector<string>& args)
{
    const unsigned int vdsoTextSectionOffset = this->section->filepos;

    const unsigned int sectionRelativePc = addr - this->section->vma;
    const unsigned int segmentRelativeIp = sectionRelativePc + vdsoTextSectionOffset;
    const unsigned int processLocalPc = segmentMapAddress + segmentRelativeIp;

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

    /// debug instructions for getting EBP:
    {
        DI::ExecChain ec;
        if (ebpPushed)
        {
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

    switch (insType)
    {
        case INS_UNKNOWN:
            break;
        case INS_MOV:
            // TODO
            break;
        case INS_PUSH:
            if (args[0] == "%ebp")
            {
                this->ebpPushed = true;
                this->ebpStackOffset = this->stackSize+4;
            }
            this->stackSize += 4;
            break;
        case INS_POP:
            if (args[0] == "%ebp")
            {
                this->ebpPushed = false;
                ebpStackOffset = -1;
            }
            this->stackSize -= 4;
            break;
    }
}


struct SymbolAddressSort
{
    bool operator() (const asymbol* a, const asymbol* b)
    {
        return (a->value < b->value);
    }
};

/// Create debug information for the specified functions in a binary
void CreateDebugInfo (DI::DebugTable& debugTable, const string& binPath, const unsigned int mapAddress, const vector<string>& functions)
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

    for (unsigned int i = 0; i < asymtab.size(); ++i)
    {
        if (std::find(functions.begin(), functions.end(), asymtab[i]->name) != functions.end())
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
                asymtab[i]->value + asymtab[i]->section->vma,
                asymtab[i]->value + asymtab[i]->section->vma + symbolSize);
        }
    }

    bfd_close(abfd);
    DEBUG("finished %s", binPath.c_str());
}
