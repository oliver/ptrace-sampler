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
static const int NUM_REGISTERS = 3;


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



class ExecChain
{
public:
    ExecChain ()
    : numFuncs(0)
    { }

    inline void push_back(BaseFunc* func)
    {
        this->funcs[this->numFuncs] = func;
        this->numFuncs++;
    }

    inline BaseFunc* at (const unsigned short index) const
    {
        return this->funcs[index];
    }

    inline unsigned short size () const
    {
        return this->numFuncs;
    }

private:
    // statically allow up to four functions for this exec chain
    BaseFunc* funcs[4];
    unsigned short numFuncs;
};


class DebugTable
{
public:
    ~DebugTable ();

    /// @brief Use debug info to get register value
    bool GetRegValue (const RegisterName reg, const unsigned int pc, Context& c) const;
    void AddDebugInfo (const RegisterName reg, const unsigned int pc, const ExecChain& ec);

private:
    struct PcFuncs
    {
        // function chains for each register
        ExecChain registerFuncs[NUM_REGISTERS];
    };

    typedef map<unsigned int, PcFuncs> PcMap;
    PcMap debugInfo;
};

} // end namespace

#endif
