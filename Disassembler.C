
#include "Common.h"
#include "Disassembler.h"

#include <malloc.h>
#include <dis-asm.h>
#include <cstdarg>

#include <string.h>
#include <assert.h>


static void DisasPrintAddress(bfd_vma, struct disassemble_info*)
{
    // do nothing
}


void Disassembler::Disassemble (bfd* abfd, asection* section,
    char* sectionContents,
    const unsigned int startAddress, const unsigned int endAddress)
{
    disassembler_ftype disasFunc = disassembler(abfd);
    DEBUG("disasFunc: %p", disasFunc);

    DEBUG("section name: %s; size: %lld; vma: 0x%llx; lma: 0x%llx; output_offset: 0x%lld; filepos: %llx",
        section->name, (long long int)section->size, (long long int)section->vma,
        (long long int)section->lma, (long long int)section->output_offset,
        (long long int)section->filepos);

    struct disassemble_info disasInfo;
    char printBuffer[100];
    init_disassemble_info(&disasInfo, &printBuffer, (fprintf_ftype)DisasPrintf);
    disasInfo.print_address_func = DisasPrintAddress;
    disasInfo.arch = bfd_get_arch(abfd);
    disasInfo.mach = bfd_get_mach(abfd);
    disasInfo.buffer_vma = section->vma;
    disasInfo.buffer_length = section->size;
    disasInfo.section = section;
    disasInfo.buffer = (bfd_byte*) sectionContents;
    disassemble_init_for_target(&disasInfo);

    DEBUG("disassembling addr range: 0x%x - 0x%x", startAddress, endAddress);


    for (unsigned int pc = startAddress; pc < endAddress; /* empty */)
    {
        printBuffer[0] = '\0';
        const int count = disasFunc(pc, &disasInfo);
        DEBUG("  pc: %x; count: %d; disas: '%s'", pc, count, printBuffer);
        if (count <= 0)
        {
            break;
        }

        vector<char*> args;
        const InsType insType = DecodeInsString(printBuffer, args);
        DEBUG("    pc: 0x%08x; raw: '%s'; instype: %d; %d args:",
            pc, printBuffer, insType, args.size());
        for (unsigned int j = 0; j < args.size(); ++j)
        {
            DEBUG("      args[%d]: '%s'", j, args[j]);
        }

        if (!this->HandleInstruction(pc, count, insType, args))
        {
            break;
        }

        pc += count;
    }
}


Disassembler::InsType Disassembler::DecodeInsString (char* s, vector<char*>& args)
{
    char* pos = strchr(s, ' ');
    if (pos == NULL)
    {
        return INS_UNKNOWN;
    }
    *pos = '\0';
    
    pos++;
    while (*pos == ' ')
    {
        pos++;
    }

    if (*pos != '\0')
    {
        while (1)
        {
            args.push_back(pos);
            pos = strchr(pos, ',');
            if (pos == NULL)
            {
                break;
            }
            *pos = '\0';
            pos++;
        }
    }

    InsType typ = INS_UNKNOWN;
    if (strcmp(s, "mov") == 0 && args.size() == 2)
    {
        typ = INS_MOV;
    }
    else if (strcmp(s, "push") == 0 && args.size() == 1)
    {
        typ = INS_PUSH;
    }
    else if (strcmp(s, "pop") == 0 && args.size() == 1)
    {
        typ = INS_POP;
    }
    return typ;
}


void Disassembler::DisasPrintf (void* userData, const char* format, ...)
{
    char* outBuffer = (char*)userData;
    
    if (strchr(format, '%') == NULL)
    {
        strcat(outBuffer, format);
    }
    else
    {
        assert( strcmp(format, "%s") == 0 );
        va_list args;
        va_start(args, format);
        const char* stringArg = va_arg(args, char*);
        strcat(outBuffer, stringArg);
        va_end(args);
    }
}
