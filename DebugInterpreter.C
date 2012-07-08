
#include "Common.h"
#include "DebugInterpreter.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/ptrace.h>


// Debug Interpreter
namespace DI
{


BaseFunc::~BaseFunc ()
{ }

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



DebugTable::~DebugTable ()
{
    for (PcMap::iterator itPc = this->debugInfo.begin();
         itPc != this->debugInfo.end(); ++itPc)
    {
        for (int i = 0; i < NUM_REGISTERS; ++i)
        {
            for (unsigned int j = 0; j < itPc->second.registerFuncs[i].size(); ++j)
            {
                delete itPc->second.registerFuncs[i].at(j);
            }
        }
    }
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
        const ExecChain& funcs = itPc->second.registerFuncs[reg];

        DEBUG("executing %d funcs to get value of register %d", funcs.size(), reg);
        for (unsigned int i = 0; i < funcs.size(); ++i)
        {
            const BaseFunc* func = funcs.at(i);
            func->Execute(c);
        }
        DEBUG("found value 0x%x for register %d", c.value, reg);
        return true;
    }
}

bool DebugTable::HaveInfo (const unsigned int pc) const
{
    return (this->debugInfo.find(pc) != this->debugInfo.end());
}

void DebugTable::AddDebugInfo (const RegisterName reg, const unsigned int pc, const ExecChain& ec)
{
    DEBUG("DebugTable: adding debug info for register %d, pc 0x%08x: %d BaseFuncs",
        reg, pc, ec.size());
    assert(debugInfo[pc].registerFuncs[reg].size() == 0);
    debugInfo[pc].registerFuncs[reg] = ec;
}


} // end namespace

