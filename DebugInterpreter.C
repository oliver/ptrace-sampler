
#include "Common.h"
#include "DebugInterpreter.h"
#include "Disassembler.h"

#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>


// Debug Interpreter
namespace DI
{


FuncValue::FuncValue (const unsigned int value_)
: value(value_)
{ }

void FuncValue::Execute (Context& c) const
{
    DEBUG("FuncValue: value %d", this->value);
    c.value = this->value;
}


FuncAdd::FuncAdd (const int value_)
: value(value_)
{ }

void FuncAdd::Execute (Context& c) const
{
    DEBUG("FuncAdd: adding %d to c.value of 0x%x", this->value, c.value);
    c.value += this->value;
}


FuncReadReg::FuncReadReg (const RegisterName reg_)
: reg(reg_)
{ }

void FuncReadReg::Execute (Context& c) const
{
    // note: current register values for ESP and EBP must have been set in context
    switch (this->reg)
    {
        case REG_ESP:
            c.value = c.esp;
            break;
        case REG_EBP:
            c.value = c.ebp;
            break;
        default:
            abort();
    }
    DEBUG("FuncReadReg: read register %d, found 0x%08x", this->reg, c.value);
}


FuncReadStackValue::FuncReadStackValue (const int offsetFromESP)
: offset(offsetFromESP)
{ }

void FuncReadStackValue::Execute (Context& c) const
{
    DEBUG("FuncReadStackValue: reading stack value at 0x%x + 0x%x", c.esp, this->offset);
    c.value = ptrace(PTRACE_PEEKDATA, c.pid, c.esp + this->offset, 0);
}


bool DebugTable::GetRegValue (const RegisterName reg, const unsigned int pc, Context& c) const
{
    const PcMap::const_iterator itPc = this->debugInfo.find(pc);
    if (itPc == this->debugInfo.end())
    {
        // no debug info for this address
        return false;
    }
    else
    {
        const RegisterMap::const_iterator itReg = itPc->second.find(reg);
        if (itReg == itPc->second.end())
        {
            // no debug info for this register
            return false;
        }
        else
        {
            DEBUG("executing %d funcs to get value of register %d", itReg->second.size(), reg);
            for (ExecChain::const_iterator itChain = itReg->second.begin();
                 itChain != itReg->second.end(); ++itChain)
            {
                const BaseFunc* func = *itChain;
                func->Execute(c);
            }
            DEBUG("found value 0x%x for register %d", c.value, reg);
            return true;
        }
    }
}

void DebugTable::AddDebugInfo (const RegisterName reg, const unsigned int pc, const ExecChain& ec)
{
    DEBUG("DebugTable: adding debug info for register %d, pc 0x%08x: %d BaseFuncs",
        reg, pc, ec.size());
    debugInfo[pc][reg] = ec;
}


} // end namespace

