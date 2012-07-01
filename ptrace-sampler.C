
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <dirent.h>
#include <string>
#include <vector>
#include <set>
#include <map>

#include <wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>

#ifdef HAVE_LIBUNWIND
#include <libunwind-ptrace.h>
#endif

#include "Common.h"
#include "MemoryMappings.h"
#include "DebugInterpreter.h"
#include "DebugCreator.h"
#include "Vdso.h"
#include "PltList.h"


// from https://bugzilla.redhat.com/attachment.cgi?id=263751&action=edit :
#include <asm/unistd.h>
#define tkill(tid, sig) syscall (__NR_tkill, (tid), (sig))

using std::string;
using std::vector;
using std::set;
using std::map;

//
// Global Options
//

FILE* outFile = stderr;

/// if true, use heuristic to find next stack frame if frame pointer has been omitted
bool useFpoHeuristic = true;

/// if true, debug messages will be printed
bool debugEnabled = false;

/// max. number of stack frames to trace back
int maxFrames = 40;


unsigned int stackStart = 0;
unsigned int stackEnd = 0;


int64_t TimestampUsec ()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return int64_t(tv.tv_sec) * 1000000 + tv.tv_usec;
}

char* TimestampString ()
{
	static char timeStr[50];
	struct timeval tv;
	gettimeofday(&tv, NULL);
	sprintf(timeStr, "%d.%06d", int(tv.tv_sec), int(tv.tv_usec));
	return timeStr;
}


//
// Sampling Functions
//

#ifdef HAVE_LIBUNWIND
void CreateSampleLibunwind (const int pid, unw_addr_space_t targetAddrSpace, void* uptInfo)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    struct user_regs_struct regs;
    memset(&regs, 0x00, sizeof(regs));
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    fprintf(outFile, "E: t=%d.%06d;p=%d;r_oeax=%lx\t", int(tv.tv_sec), int(tv.tv_usec), pid, regs.orig_eax);

    unw_cursor_t cursor;
    const int success = unw_init_remote(&cursor, targetAddrSpace, uptInfo);
    if (success != 0)
    {
        printf("unw_init_remote failed: %d\n", success);
    }
    else
    {
        for (int i = 0; i < maxFrames; i++)
        {
            unw_word_t ip;
            const int regResult = unw_get_reg(&cursor, UNW_REG_IP, &ip);
            if (regResult != 0)
            {
                printf("unw_get_reg failed (%d)\n", regResult);
            }
            fprintf(outFile, "%08x ", ip);

            const int stepResult = unw_step(&cursor);
            if (stepResult == 0)
            {
                break;
            }
            else if (stepResult < 0)
            {
                printf("unw_step failed (%d / %s)\n", stepResult, unw_strerror(stepResult));
                break;
            }
        }

        fprintf(outFile, "\n");
    }
}
#endif


void CreateSampleFramepointer (const int pid, const DI::DebugTable& debugTable, const PltList& pltList)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    // Store eax and orig_eax (if we're in a syscall, this specifies the syscall number).
    // Note: while we're in syscall epilog, syscall number has unfortunately already been lost.
    struct user_regs_struct regs;
    memset(&regs, 0x00, sizeof(regs));
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    fprintf(outFile, "E: t=%d.%06d;p=%d;r_eax=%lx;r_oeax=%lx\t", int(tv.tv_sec), int(tv.tv_usec), pid, regs.eax, regs.orig_eax);

    const unsigned int ip = regs.eip;
    const unsigned int bp = regs.ebp;
    const unsigned int sp = regs.esp;

    fprintf(outFile, "%08x ", ip);

    if (pltList.FindContainingPlt(ip))
    {
        // PLT entries don't save ebp; so calling address is at esp.
        // Simply insert an additional frame for the calling function.
        const int retAddr = ptrace(PTRACE_PEEKDATA, pid, sp, 0);
        DEBUG("adding frame with EIP 0x%08x (from 0x%08x) due to PLT", retAddr, sp);
        fprintf(outFile, "%08x ", retAddr);
    }
    // Check if eip is in function prolog (ie. when ebp is not updated yet),
    // and use esp in that case to get eip of calling frame.
    // Similarly, detect if eip is in function epilog (ie. when ebp is already
    // updated for return to caller), and again fall back to esp in that case.
    else
    {
        const unsigned int instrBytes = ptrace(PTRACE_PEEKTEXT, pid, ip, 0);
        int retAddrAddr = 0; /// address (on stack) where return address is stored

        // prolog (as observed in the wild):
        //   55      push %ebp
        //   89 e5   mov %esp,%ebp
        if ((instrBytes & 0xFFFFFF) == 0xe58955)
        {
            // eip is at "push %ebp", and return address (ie. eip of calling function)
            // is stored at (esp) now
            retAddrAddr = sp;
        }
        else if ((instrBytes & 0xFFFF) == 0xe589)
        {
            // eip is at "mov %esp,%ebp", and return address is stored at (esp+4) now
            retAddrAddr = sp + 4;
        }

        // epilog (as observed in the wild):
        //   c3   ret
        else if ((instrBytes & 0xFF) == 0xc3)
        {
            // eip is at "ret"; we assume that the previous instruction ("leave" or "pop %ebp")
            // has prepared ebp for calling function, and that stack
            // (and hence esp) have been cleaned up.
            // So, only return address should be on stack now.
            retAddrAddr = sp;
        }

        if (retAddrAddr != 0)
        {
            // simply insert an additional frame for the calling function
            const int retAddr = ptrace(PTRACE_PEEKDATA, pid, retAddrAddr, 0);
            DEBUG("adding frame with EIP 0x%08x (from 0x%08x), EBP 0x%08x", retAddr, retAddrAddr, bp);
	        fprintf(outFile, "%08x ", retAddr);
        }
    }

    unsigned int oldSp = sp;
    unsigned int oldBp = bp;
    unsigned int oldIp = ip;
    unsigned int lastGoodSp = sp;

    for (int i = 1; i < maxFrames; i++)
    {
        DEBUG("-------- FRAME %d --------", i);
        unsigned int newSp = 0;
        unsigned int newBp = 0;
        bool haveNewBp = false;

        unsigned int newIp = 0;
        bool haveNewIp = false;

#ifdef HAVE_LIBBFD
        // try debug info first
        {
            DI::Context context;
            context.pid = pid;
            context.esp = oldSp;
            context.ebp = oldBp;
            const bool foundEip = debugTable.GetRegValue(DI::REG_EIP, oldIp, context);
            const unsigned int debugReturnEip = context.value;

            if (foundEip)
            {
                newIp = debugReturnEip;
                haveNewIp = true;
                DEBUG("used debug info to get new EIP 0x%08x (from old EIP 0x%08x, ESP 0x%08x)",
                    newIp, oldIp, oldSp);
            }
        }

        {
            DI::Context context;
            context.pid = pid;
            context.esp = oldSp;
            context.ebp = oldBp;
            const bool foundEsp = debugTable.GetRegValue(DI::REG_ESP, oldIp, context);
            const unsigned int debugEsp = context.value;

            context.pid = pid;
            context.esp = oldSp;
            context.ebp = oldBp;
            const bool foundEbp = debugTable.GetRegValue(DI::REG_EBP, oldIp, context);
            const unsigned int debugEbp = context.value;

            if (foundEsp && foundEbp)
            {
                newSp = debugEsp;
                newBp = debugEbp;
                haveNewBp = true;
                DEBUG("used debug info to get new EBP 0x%08x, ESP 0x%08x (from old EIP 0x%08x, ESP 0x%08x)",
                    newBp, newSp, oldIp, oldSp);
            }
        }
#endif

        if (useFpoHeuristic && (oldBp < stackStart || oldBp > stackEnd) && (lastGoodSp >= stackStart && lastGoodSp <= stackEnd))
        {
            DEBUG("EBP 0x%x is outside of stack", oldBp);
            fprintf(outFile, "*"); // add mark that this frame was missing frame pointer

            /*
            EBP does not point to a location on stack; so we assume there is
            no frame pointer saved here.
            Use heuristic to find a frame with stack pointer again:
            - search stack downwards, starting at ESP (ie. incrementing addresses)
            - look for bytes which form a valid address on stack
            - check if pointed-to stack location contains another valid stack pointer
              and a valid IP pointer
            */

            unsigned int currAddr = lastGoodSp;
            bool success = false;
            while (currAddr < stackEnd)
            {
                const unsigned int stackValue = ptrace(PTRACE_PEEKDATA, pid, currAddr, 0);
                if (stackValue >= stackStart && stackValue <= stackEnd && stackValue > currAddr)
                {
                    //printf("found candidate 0x%x , at ESP + %d\n", stackValue, currAddr - sp);

                    // check if pointed-to location on stack appears to be a valid stack frame:
                    const unsigned int candidateBp = stackValue;
                    const unsigned int candidateIp = ptrace(PTRACE_PEEKDATA, pid, currAddr+4, 0);
                    const unsigned int candidateSubBp = ptrace(PTRACE_PEEKDATA, pid, candidateBp, 0);
                    //const unsigned int candidateSubIp = ptrace(PTRACE_PEEKDATA, pid, candidateBp+4, 0);
                    //printf("candidate EBP gives frame with EBP 0x%x and EIP 0x%x\n", candidateSubBp, candidateSubIp);

                    if (candidateSubBp >= stackStart && candidateSubBp <= stackEnd
                        && candidateSubBp > candidateBp
                        && candidateIp != 0x0 && candidateIp != 0xffffffff)
                    {
                        DEBUG("heuristic found better EBP 0x%08x (0x%x bytes further down on stack)",
                            candidateBp, currAddr - lastGoodSp);
                        oldBp = candidateBp;
                        success = true;
                        fprintf(outFile, "+"); // add mark that next is a successfully reconstructed frame
                        break;
                    }
                }
                currAddr++;
            }
            if (!success)
            {
                DEBUG("heuristic failed to find better EBP");
            }
            //printf("stack heuristic finished\n");
            fprintf(outFile, " ");
        }

        lastGoodSp = oldBp;

        if (!haveNewIp)
        {
            // fall back to normal frame pointer walking
            newIp = ptrace(PTRACE_PEEKDATA, pid, oldBp+4, 0);
            DEBUG("using frame pointer to get new EIP 0x%08x (from old EIP 0x%08x, EBP 0x%08x)",
                newIp, oldIp, oldBp);
        }

        if (!haveNewBp)
        {
            // fall back to normal frame pointer walking
            newBp = ptrace(PTRACE_PEEKDATA, pid, oldBp, 0);
            newSp = newBp+4;
            DEBUG("using frame pointer to get new EBP 0x%08x (from old EIP 0x%08x, EBP 0x%08x)",
                newBp, oldIp, oldBp);
        }

	    fprintf(outFile, "%08x ", newIp);

        oldSp = newSp;
        oldBp = newBp;
        oldIp = newIp;

	    if (newBp == 0x0 || newBp == 0xFFFFFFFF)
	    {
	        break;
	    }
    }
    fprintf(outFile, "\n");
}


//
// Tracing Functions
//


/// stores all information about a ptraced task (thread)
struct TaskInfo
{
    int pid;
    int stopSignal; ///< the signal that caused the task to stop

#ifdef HAVE_LIBUNWIND
    void* uptInfo;
#endif
};
typedef std::vector<TaskInfo> TaskList;


bool terminate = false;
static void SignalHandler (int /*sig*/)
{
    terminate = true;
}

static void SigchldHandler (int sig)
{
    // ignore signal
    DEBUG("ignoring SIGCHLD (%d)", sig);
}


static void Usage (const char* argv0)
{
    printf("Usage: %s\n\
    --pid <pid>\n\
    [--interval | -i <msec>]\n\
    [--max-samples | -s <max. number of samples to collect>]\n\
    [--max-frames | -f <max. number of frames to trace back>]\n\
    [--debug | -d | --no-debug | -nd]\n\
    [--fpo | --no-fpo]\n\
    [--unwind | -u | --framepointer | -fp]\n\
    [--verbose | -v | --no-verbose]\n", argv0);
}

int main (int argc, char* argv[])
{
    int pid = -1;
    int sampleInterval = 5 * 1000; // usec
    int maxSamples = 0;
    bool useLibunwind = false;
    bool useDebugInfo = true;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--pid") == 0 && i < argc-1)
        {
            pid = atoi(argv[i+1]);
            i++;
        }
        else if ((strcmp(argv[i], "--interval") == 0 || strcmp(argv[i], "-i") == 0) && i < argc-1)
        {
            sampleInterval = atoi(argv[i+1]) * 1000;
            i++;
        }
        else if ((strcmp(argv[i], "--max-samples") == 0 || strcmp(argv[i], "-s") == 0) && i < argc-1)
        {
            maxSamples = atoi(argv[i+1]);
            i++;
        }
        else if ((strcmp(argv[i], "--max-frames") == 0 || strcmp(argv[i], "-f") == 0) && i < argc-1)
        {
            maxFrames = atoi(argv[i+1]);
            i++;
        }
        else if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0)
        {
            useDebugInfo = true;
        }
        else if (strcmp(argv[i], "--no-debug") == 0 || strcmp(argv[i], "-nd") == 0)
        {
            useDebugInfo = false;
        }
        else if (strcmp(argv[i], "--fpo") == 0)
        {
            useFpoHeuristic = true;
        }
        else if (strcmp(argv[i], "--no-fpo") == 0)
        {
            useFpoHeuristic = false;
        }
        else if (strcmp(argv[i], "--unwind") == 0 || strcmp(argv[i], "-u") == 0)
        {
            useLibunwind = true;
        }
        else if (strcmp(argv[i], "--framepointer") == 0 || strcmp(argv[i], "-fp") == 0)
        {
            useLibunwind = false;
        }
        else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0)
        {
            debugEnabled = true;
        }
        else if (strcmp(argv[i], "--no-verbose") == 0)
        {
            debugEnabled = false;
        }
        else
        {
            printf("unknown parameter '%s'\n", argv[i]);
            Usage(argv[0]);
            exit(1);
        }
    }

    if (pid <= 0)
    {
        printf("no valid PID specified\n");
        Usage(argv[0]);
        exit(1);
    }

    if (sampleInterval <= 0)
    {
        printf("invalid sample interval '%d' specified (must be > 0)\n", sampleInterval);
        Usage(argv[0]);
        exit(1);
    }

#ifndef HAVE_LIBUNWIND
    if (useLibunwind)
    {
        printf("support for --unwind is not available\n");
        exit(1);
    }
#endif

    fprintf(outFile, "# trace file from %s\n", argv[0]);
    fprintf(outFile, "# for PID %d\n", pid);
    fprintf(outFile, "# samples taken every %d usec\n", sampleInterval);
    fprintf(outFile, "# legend: T=thread, M=mapping, E=event\n");

    // find threads
    TaskList allTasks;
    {
        char dirName[255];
        sprintf(dirName, "/proc/%d/task/", pid);
        DIR* taskDir = opendir(dirName);
        if (!taskDir)
        {
            printf("opendir failed (%d - %s)\n", errno, strerror(errno));
            exit(1);
        }

        while (true)
        {
            struct dirent* dir = readdir(taskDir);
            if (!dir)
            {
                break;
            }
            if (dir->d_name[0] == '.')
            {
                continue;
            }
            const int taskId = atoi(dir->d_name);
            printf("    task: %d\n", taskId);
            fprintf(outFile, "T: %d\n", taskId);

            TaskInfo ti;
            ti.pid = taskId;
            ti.stopSignal = -1;
#ifdef HAVE_LIBUNWIND
            ti.uptInfo = NULL;
#endif
            allTasks.push_back(ti);
        }
        closedir(taskDir);
    }

    // attach
    for (unsigned int i = 0; i < allTasks.size(); i++)
    {
        printf("attaching to PID %d\n", allTasks[i].pid);
        if (ptrace(PTRACE_ATTACH, allTasks[i].pid, 0, 0) != 0)
        {
            printf("failed to attach to PID %d: %s\n", allTasks[i].pid, strerror(errno));
            exit(1);
        }

        int waitStat = 0;
        const int waitRes = waitpid(allTasks[i].pid, &waitStat, WUNTRACED | __WALL);
        if (waitRes != allTasks[i].pid || !WIFSTOPPED(waitStat))
        {
            printf("unexpected waitpid result %d for PID %d; waitStat: %d\n", waitRes, allTasks[i].pid, waitStat);
            exit(1);
        }
        printf("waitpid result: pid=%d, stat=%d\n", waitRes, waitStat);
    }

    // let all tasks continue
    for (unsigned int i = 0; i < allTasks.size(); i++)
    {
        ptrace(PTRACE_CONT, allTasks[i].pid, 0, 0);
    }

#ifdef HAVE_LIBUNWIND
    unw_addr_space_t targetAddrSpace = 0;

    if (useLibunwind)
    {
     	targetAddrSpace = unw_create_addr_space(&_UPT_accessors, 0);
     	for (unsigned int i = 0; i < allTasks.size(); i++)
     	{
     	    allTasks[i].uptInfo = _UPT_create(allTasks[i].pid);
 	    }
 	}
#endif

    const MemoryMappings mappings(pid);

    const MemoryMappings::Mapping* stackMemory = mappings.Find("[stack]");
    if (stackMemory)
    {
        stackStart = stackMemory->start;
        stackEnd = stackMemory->end;
    }

    // save mappings of child (required for address->line conversion later)
    const vector<string> mapLines = MemoryMappings::RawLines(pid);
    for (unsigned int i = 0; i < mapLines.size(); ++i)
    {
        fprintf(outFile, "M: %s", mapLines[i].c_str());
    }

    if (useFpoHeuristic && !useLibunwind)
    {
        printf("stack start: 0x%x; end: 0x%x; size: %d\n", int(stackStart), int(stackEnd), int(stackEnd - stackStart));
    }


    DI::DebugTable debugTable;
    PltList pltList;

#ifdef HAVE_LIBBFD
    if (useDebugInfo)
    {
        vector<string> debugLibPatterns;
        debugLibPatterns.push_back("[vdso]");
        debugLibPatterns.push_back("/libc");

        for (MemoryMappings::const_iterator itMap = mappings.Begin();
             itMap != mappings.End(); ++itMap)
        {
            pltList.AddPlt(*itMap);

            for (vector<string>::const_iterator it = debugLibPatterns.begin();
                 it != debugLibPatterns.end(); ++it)
            {
                if (itMap->isExecutable && itMap->name.find(*it) != string::npos)
                {
                    if (*it == "[vdso]")
                    {
                        const VdsoBinary tempBinary;
                        CreateDebugInfo(debugTable, tempBinary.Path(), itMap->start);
                    }
                    else
                    {
                        CreateDebugInfo(debugTable, itMap->name, itMap->start);
                    }
                }
            }
        }
    }
#endif

    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);
    signal(SIGCHLD, SigchldHandler);

    DEBUG("starting loop");
    int64_t numSamples = 0;
    int64_t lastSample = 0;
    int64_t totalSamplingDuration = 0;
    while (true)
    {
        if (terminate)
        {
            DEBUG("terminate requested");
            ptrace(PTRACE_CONT, pid, 0, 0);
            break;
        }

        std::set<int> exitedTasks;

        for (unsigned int i = 0; i < allTasks.size(); i++)
        {
            allTasks[i].stopSignal = -1;
        }

        const int64_t nowTime = TimestampUsec();
        if (lastSample + sampleInterval < nowTime)
        {
            // time for new sample
            lastSample = nowTime;

            // ensure all children are stopped
            for (unsigned int i = 0; i < allTasks.size(); i++)
            {
                DEBUG("sending SIGSTOP to %d...", allTasks[i].pid);
                tkill(allTasks[i].pid, SIGSTOP);
            }

            for (unsigned int i = 0; i < allTasks.size(); i++)
            {
                DEBUG("waiting for child %d...", allTasks[i].pid);
                int waitStat = 0;
                const int waitRes = waitpid(allTasks[i].pid, &waitStat, __WALL);
                DEBUG("waitpid finished (waitRes: %d; waitStat: %d; WIFEXITED: %d; WIFSIGNALED: %d; WIFSTOPPED: %d; WSTOPSIG: %d)",
                    waitRes, waitStat, WIFEXITED(waitStat), WIFSIGNALED(waitStat), WIFSTOPPED(waitStat), WSTOPSIG(waitStat));
                if (WIFEXITED(waitStat) || WIFSIGNALED(waitStat))
                {
                    DEBUG("child %d exited\n", allTasks[i].pid);
                    exitedTasks.insert(allTasks[i].pid);
                }
                else
                {
                    int sigNo = WSTOPSIG(waitStat);
                    if (sigNo == SIGSTOP)
                    {
                        sigNo = 0;
                    }
                    else
                    {
                        DEBUG("child got signal %d", sigNo);
                    }
                    allTasks[i].stopSignal = sigNo;
                }

                DEBUG("child %d paused", allTasks[i].pid);
            }

            // create sample
            numSamples++;

            DEBUG("creating sample #%lld", numSamples);
            const int64_t sampleStartTime = TimestampUsec();
            for (unsigned int i = 0; i < allTasks.size(); i++)
            {
                if (exitedTasks.empty() || exitedTasks.find(allTasks[i].pid) == exitedTasks.end())
                {
#ifdef HAVE_LIBUNWIND
                    if (useLibunwind)
                    {
                        CreateSampleLibunwind(allTasks[i].pid, targetAddrSpace, allTasks[i].uptInfo);
                    }
                    else
#endif
                    {
                        CreateSampleFramepointer(allTasks[i].pid, debugTable, pltList);
                    }
                }
            }
            const int64_t sampleEndTime = TimestampUsec();
            totalSamplingDuration += sampleEndTime - sampleStartTime;
            DEBUG("sampling %d thread(s) took %lld usec", allTasks.size(), sampleEndTime - sampleStartTime);
        }
        else
        {
            // ignore unwanted wakeup
            DEBUG("unexpected wakeup");
        }

        // continue all children
        for (unsigned int i = 0; i < allTasks.size(); i++)
        {
            if (!exitedTasks.empty() && exitedTasks.find(allTasks[i].pid) != exitedTasks.end())
            {
                continue;
            }

            int tryCount = 0;
            while (true)
            {
                tryCount++;

                int stopSig = allTasks[i].stopSignal;
                if (stopSig == -1)
                {
                    // if we haven't obtained any stop reason from waitpid() above,
                    // call waitpid() here to get the first reason in queue:
                    int waitStat = 0;
                    const int waitRes = waitpid(allTasks[i].pid, &waitStat, WNOHANG);
                    DEBUG("obtained stop reason for child %d (waitRes: %d; waitStat: %d; WIFEXITED: %d; WIFSIGNALED: %d; WIFSTOPPED: %d; WSTOPSIG: %d)",
                        allTasks[i].pid, waitRes, waitStat, WIFEXITED(waitStat), WIFSIGNALED(waitStat), WIFSTOPPED(waitStat), WSTOPSIG(waitStat));
                    stopSig = WSTOPSIG(waitStat);
                    if (waitRes == allTasks[i].pid && (WIFEXITED(waitStat) || WIFSIGNALED(waitStat)))
                    {
                        exitedTasks.insert(allTasks[i].pid);
                        break;
                    }
                }

                // Apparently there is no reliable way here to find out
                // whether child is stopped and needs to be continued...
                // So just call PTRACE_CONT until it fails.
                const int success = ptrace(PTRACE_CONT, allTasks[i].pid, 0, stopSig);
                DEBUG("child %d continued with signal %d (try #%d; success: %d; errno: %d)", allTasks[i].pid, stopSig, tryCount, success, errno);
                if (success != 0)
                {
                    break;
                }

                allTasks[i].stopSignal = 0; // for further PTRACE_CONT tries use 0 as stopSig
            }
        }

        if (!exitedTasks.empty())
        {
            for (TaskList::iterator it = allTasks.begin(); it != allTasks.end(); /*empty*/)
            {
                if (exitedTasks.find(it->pid) != exitedTasks.end())
                    it = allTasks.erase(it);
                else
                    ++it;
            }
        }

        if (allTasks.empty())
        {
            DEBUG("all tasks finished; exiting");
            break;
        }

        if (maxSamples > 0 && numSamples >= maxSamples)
        {
            DEBUG("max. requested samples (%d) reached; exiting", maxSamples);
            break;
        }

        const int64_t remaining = (lastSample + sampleInterval) - nowTime;
        DEBUG("sleeping for %lld usec", remaining);
        if (remaining > 0)
        {
            usleep(remaining);
        }
    }

    printf("exiting after taking %lld samples\n", numSamples);
    printf("sample creation took %lld usec on average\n", totalSamplingDuration / numSamples);

#ifdef HAVE_LIBUNWIND
    if (useLibunwind)
    {
        for (unsigned int i = 0; i < allTasks.size(); i++)
        {
            _UPT_destroy(allTasks[i].uptInfo);
            allTasks[i].uptInfo = NULL;
        }
    }
#endif

    return 0;
}

