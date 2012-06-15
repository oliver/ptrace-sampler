
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <dirent.h>
#include <vector>
#include <algorithm>

#include <wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>

// from https://bugzilla.redhat.com/attachment.cgi?id=263751&action=edit :
#include <asm/unistd.h>
#define tkill(tid, sig) syscall (__NR_tkill, (tid), (sig))

//
// Sampling Functions
//

#define M_OFFSETOF(STRUCT, ELEMENT) \
	(unsigned int) &((STRUCT *)NULL)->ELEMENT;

int ipoffs, spoffs, bpoffs;

FILE* outFile = stderr;

/// if true, use heuristic to find next stack frame if frame pointer has been omitted
bool useFpoHeuristic = true;

/// if true, debug messages will be printed
bool debugEnabled = false;

unsigned int stackStart = 0;
unsigned int stackEnd = 0;


static char* Timestamp ()
{
	static char timeStr[50];
	struct timeval tv;
	gettimeofday(&tv, NULL);
	sprintf(timeStr, "%d.%06d", int(tv.tv_sec), int(tv.tv_usec));
	return timeStr;
}

#define DEBUG(...) if (debugEnabled) { printf("[%s] ", Timestamp()); printf(__VA_ARGS__); printf("\n"); }


void CreateSample (const int pid)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    struct user_regs_struct regs;
    memset(&regs, 0x00, sizeof(regs));
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    fprintf(outFile, "E: t=%d.%06d;p=%d;r_oeax=%x\t", int(tv.tv_sec), int(tv.tv_usec), pid, regs.orig_eax);

    const unsigned int ip = regs.eip;
    const unsigned int bp = regs.ebp;
    const unsigned int sp = regs.esp;

    fprintf(outFile, "%08x ", ip);

    // Check if eip is in function prolog (ie. when ebp is not updated yet),
    // and use esp in that case to get eip of calling frame.
    // Similarly, detect if eip is in function epilog (ie. when ebp is already
    // updated for return to caller), and again fall back to esp in that case.
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
	        fprintf(outFile, "%08x ", retAddr);
        }
    }

    unsigned int oldBp = bp;
    unsigned int lastGoodSp = sp;
        
    for (int i = 1; i < 40; i++)
    {
        if (useFpoHeuristic && (oldBp < stackStart || oldBp > stackEnd) && (lastGoodSp >= stackStart && lastGoodSp <= stackEnd))
        {
            //printf("bp 0x%x is outside of stack\n", oldBp);
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
                        //printf("candidate appears good\n");
                        oldBp = candidateBp;
                        fprintf(outFile, "+"); // add mark that next is a successfully reconstructed frame
                        break;
                    }
                }
                currAddr++;
            }
            //printf("stack heuristic finished\n");
            fprintf(outFile, " ");
        }

        lastGoodSp = oldBp;

	    const unsigned int newBp = ptrace(PTRACE_PEEKDATA, pid, oldBp, 0);
	    const unsigned int newIp = ptrace(PTRACE_PEEKDATA, pid, oldBp+4, 0);

	    fprintf(outFile, "%08x ", newIp);
	    oldBp = newBp;
	    if (newBp == 0x0 /*|| newBp == 0xFFFFFFFF*/)
	    {
	        break;
	    }
    }
    fprintf(outFile, "\n");
}



//
// Tracing Functions
//

bool terminate = false;
static void SignalHandler (int sig)
{
    terminate = true;
}

int main (int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <pid>\n", argv[0]);
        exit(1);
    }
    const int pid = atoi(argv[1]);
    int sampleInterval = 5 * 1000; // usec

    ipoffs = M_OFFSETOF(struct user, regs.eip);
	spoffs = M_OFFSETOF(struct user, regs.esp);
	bpoffs = M_OFFSETOF(struct user, regs.ebp);

    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);

    fprintf(outFile, "# trace file from %s\n", argv[0]);
    fprintf(outFile, "# for PID %d\n", pid);
    fprintf(outFile, "# samples taken every %d usec\n", sampleInterval);
    fprintf(outFile, "# legend: T=thread, M=mapping, E=event\n");

    // find threads
    std::vector<int> allTasks;
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
            allTasks.push_back(taskId);
        }
    }

    // attach
    for (unsigned int i = 0; i < allTasks.size(); i++)
    {
        printf("attaching to PID %d\n", allTasks[i]);
        if (ptrace(PTRACE_ATTACH, allTasks[i], 0, 0) != 0)
        {
            perror("attach failed");
        }

        int waitStat = 0;
        int waitRes = waitpid(allTasks[i], &waitStat, WUNTRACED | __WALL);
        if (waitRes != allTasks[i] || !WIFSTOPPED(waitStat))
        {
            printf("unexpected waitpid result '%d' for PID %d!\n", waitStat, waitRes);
            exit(1);
        }
        printf("waitpid result: pid=%d, stat=%d\n", waitRes, waitStat);
    }

    // let all tasks continue
    for (unsigned int i = 0; i < allTasks.size(); i++)
    {
        ptrace(PTRACE_CONT, allTasks[i], 0, 0);
    }


    // save mappings of child (required for address->line conversion later)
    char mapFileName[200];
    sprintf(mapFileName, "/proc/%d/maps", pid);
    FILE* mapFd = fopen(mapFileName, "r");
    while (true)
    {
        char line[500];
        memset(line, '\0', sizeof(line));
        fgets(line, 500, mapFd);
        if (feof(mapFd))
        {
            break;
        }

        fprintf(outFile, "M: %s", line);

        if (strncmp(line+49, "[stack]", 7) == 0)
        {
            stackStart = strtoll(line, NULL, 16);
            stackEnd = strtoll(line+9, NULL, 16);
        }
    }

    if (useFpoHeuristic)
    {
        printf("stack start: 0x%x; end: 0x%x; size: %d\n", int(stackStart), int(stackEnd), int(stackEnd - stackStart));
    }

    int64_t numSteps = 0;
    while (true)
    {
        if (terminate)
        {
            DEBUG("terminate requested");
            ptrace(PTRACE_CONT, pid, 0, 0);
            break;
        }

        // interrupt child
        for (unsigned int i = 0; i < allTasks.size(); i++)
        {
            DEBUG("sending SIGSTOP to %d...", allTasks[i]);
            tkill(allTasks[i], SIGSTOP);
        }

        std::vector<int> exitedTasks;
        for (unsigned int i = 0; i < allTasks.size(); i++)
        {
            int sigNo = 0;

            DEBUG("waiting for child %d...", allTasks[i]);
            int waitStat = 0;
            int waitRes = waitpid(allTasks[i], &waitStat, __WALL);
            if (WIFEXITED(waitStat))
            {
                DEBUG("child %d exited\n", allTasks[i]);
                exitedTasks.push_back(allTasks[i]);
            }
            else
            {
                sigNo = WSTOPSIG(waitStat);
                if (sigNo == SIGSTOP)
                {
                    sigNo = 0;
                }
                else
                {
                    DEBUG("child got signal %d", sigNo);
                    ptrace(PTRACE_CONT, allTasks[i], 0, sigNo);
                    continue;
                }
            }

            DEBUG("child %d paused (waitRes: %d; waitStat: %d)", allTasks[i], waitRes, waitStat);
        }

        for (unsigned int i = 0; i < exitedTasks.size(); i++)
        {
            allTasks.erase(std::remove(allTasks.begin(), allTasks.end(), exitedTasks[i]), allTasks.end());
        }

        numSteps++;

        for (unsigned int i = 0; i < allTasks.size(); i++)
        {
            CreateSample(allTasks[i]);
        }

        for (unsigned int i = 0; i < allTasks.size(); i++)
        {
            ptrace(PTRACE_CONT, allTasks[i], 0, 0);
            DEBUG("child %d continued", allTasks[i]);
        }

        if (allTasks.empty())
        {
            DEBUG("all tasks finished; exiting");
            break;
        }

        usleep(sampleInterval);
    }
    printf("exiting after %lld single-steps\n", numSteps);

    return 0;
}

