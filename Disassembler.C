
#include "Common.h"
#include "Disassembler.h"

#include <dis-asm.h>
#include <cstdarg>


void Disassembler::Disassemble (bfd* abfd, asection* section,
    const unsigned int startAddress, const unsigned int endAddress)
{
    disassembler_ftype disasFunc = disassembler(abfd);
    DEBUG("disasFunc: %p", disasFunc);

    DEBUG("section name: %s; size: %lld; vma: 0x%llx; lma: 0x%llx; output_offset: 0x%lld; filepos: %llx",
        section->name, section->size, section->vma, section->lma, section->output_offset, section->filepos);

    struct disassemble_info disasInfo;
    string printBuffer;
    init_disassemble_info(&disasInfo, &printBuffer, (fprintf_ftype)DisasPrintf);
    disasInfo.arch = bfd_get_arch(abfd);
    disasInfo.mach = bfd_get_mach(abfd);
    disasInfo.buffer_vma = section->vma;
    disasInfo.buffer_length = section->size;
    disasInfo.section = section;
    bfd_malloc_and_get_section(abfd, section, &disasInfo.buffer);
    disassemble_init_for_target(&disasInfo);

    DEBUG("disassembling addr range: 0x%x - 0x%x", startAddress, endAddress);


    for (unsigned int pc = startAddress; pc < endAddress; /* empty */)
    {
        printBuffer.clear();
        const int count = disasFunc(pc, &disasInfo);
        DEBUG("  pc: %x; count: %d; disas: '%s'", pc, count, printBuffer.c_str());
        if (count <= 0)
        {
            break;
        }

        std::vector<std::string> args;
        const InsType insType = DecodeInsString(printBuffer, args);
        DEBUG("    pc: 0x%08x; raw: '%s'; instype: %d; %d args:",
            pc, printBuffer.c_str(), insType, args.size());
        for (unsigned int j = 0; j < args.size(); ++j)
        {
            DEBUG("      args[%d]: '%s'", j, args[j].c_str());
        }

        this->HandleInstruction(pc, count, insType, args);

        pc += count;
    }
}


Disassembler::InsType Disassembler::DecodeInsString (const string& s, vector<string>& args)
{
    args.clear();
    string::size_type pos = s.find(' ');
    if (pos == std::string::npos)
    {
        return INS_UNKNOWN;
    }
    const string insStr = s.substr(0, pos);

    pos = s.find_first_not_of(' ', pos+1);
    if (pos != string::npos)
    {
        while (1)
        {
            const string::size_type commaPos = s.find(',', pos);
            if (commaPos == string::npos)
            {
                break;
            }
            args.push_back( s.substr(pos, commaPos - pos) );
            pos = commaPos+1;
        }
        args.push_back( s.substr(pos) );
    }

    InsType typ = INS_UNKNOWN;
    if (insStr == "mov" && args.size() == 2)
    {
        typ = INS_MOV;
    }
    else if (insStr == "push" && args.size() == 1)
    {
        typ = INS_PUSH;
    }
    else if (insStr == "pop" && args.size() == 1)
    {
        typ = INS_POP;
    }
    return typ;
}


void Disassembler::DisasPrintf (void* userData, const char* format, ...)
{
    string* outString = (string*)userData;

    va_list args;
    va_start(args, format);
    char buffer[100];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    outString->append(buffer);
}
