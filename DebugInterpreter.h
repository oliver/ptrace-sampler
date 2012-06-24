#ifndef DEBUG_INTERPRETER_H_
#define DEBUG_INTERPRETER_H_

#include <string>
#include <vector>
#include <map>

using std::string;
using std::vector;
using std::map;


// Debug Interpreter
namespace DI
{

enum RegisterName
{
    REG_EIP,
    REG_ESP,
    REG_EBP,
};


class Context
{
public:
    int pid;
    unsigned int value;

    unsigned int esp;
    unsigned int ebp;
};


class BaseFunc
{
public:
    virtual ~BaseFunc ();
    virtual void Execute (Context& c) const = 0;
};


/// Constant value
class FuncValue : public BaseFunc
{
public:
    FuncValue (const unsigned int value);
    virtual void Execute (Context& c) const;

private:
    unsigned int value;
};


/// Add constant value to context.value
class FuncAdd : public BaseFunc
{
public:
    FuncAdd (const int value);
    virtual void Execute (Context& c) const;

private:
    int value;
};


/// Read a register
class FuncReadReg : public BaseFunc
{
public:
    FuncReadReg (const RegisterName reg_);
    virtual void Execute (Context& c) const;

private:
    RegisterName reg;
};


/// Read a value from stack
class FuncReadStackValue : public BaseFunc
{
public:
    FuncReadStackValue (const int offsetFromESP);
    virtual void Execute (Context& c) const;

private:
    int offset;
};



typedef vector<BaseFunc*> ExecChain;

class DebugTable
{
public:
    ~DebugTable ();

    /// @brief Use debug info to get register value
    bool GetRegValue (const RegisterName reg, const unsigned int pc, Context& c) const;
    void AddDebugInfo (const RegisterName reg, const unsigned int pc, const ExecChain& ec);

private:
    typedef map<RegisterName, ExecChain> RegisterMap;
    typedef map<unsigned int, RegisterMap> PcMap;
    PcMap debugInfo;
};

} // end namespace

#endif
