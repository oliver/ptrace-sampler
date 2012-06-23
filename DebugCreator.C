
#include "DebugCreator.h"


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

