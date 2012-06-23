#ifndef DEBUG_CREATOR_H_
#define DEBUG_CREATOR_H_


#include "Disassembler.h"
#include "DebugInterpreter.h"


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


#endif
