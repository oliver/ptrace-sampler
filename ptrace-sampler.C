
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#include <wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>


//
// Sampling Functions
//

#define M_OFFSETOF(STRUCT, ELEMENT) \
	(unsigned int) &((STRUCT *)NULL)->ELEMENT;

int ipoffs, spoffs, bpoffs;

FILE* outFile = stderr;

void CreateSample (const int pid)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    fprintf(outFile, "E: %d.%06d\t", int(tv.tv_sec), int(tv.tv_usec));

    const int ip = ptrace(PTRACE_PEEKUSER, pid, ipoffs, 0);
	const int bp = ptrace(PTRACE_PEEKUSER, pid, bpoffs, 0);

    fprintf(outFile, "%08x ", ip);

    int oldBp = bp;
    for (int i = 1; i < 40; i++)
    {
	    const int newBp = ptrace(PTRACE_PEEKDATA, pid, oldBp, 0);
	    const int newIp = ptrace(PTRACE_PEEKDATA, pid, oldBp+4, 0);
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
    int sampleInterval = 200 * 1000; // usec

    ipoffs = M_OFFSETOF(struct user, regs.eip);
	spoffs = M_OFFSETOF(struct user, regs.esp);
	bpoffs = M_OFFSETOF(struct user, regs.ebp);

    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);

    // attach
    printf("attaching to PID %d\n", pid);
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0)
    {
        perror("attach failed");
    }
    int waitStat = 0;
    int waitRes = waitpid(pid, &waitStat, WUNTRACED);
    if (waitRes != pid || !WIFSTOPPED(waitStat))
    {
        printf("unexpected waitpid result!\n");
        exit(1);
    }
    printf("waitpid result: pid=%d, stat=%d\n", waitRes, waitStat);

    ptrace(PTRACE_CONT, pid, 0, 0);


    fprintf(outFile, "# trace file from %s\n", argv[0]);
    fprintf(outFile, "# for PID %d\n", pid);
    fprintf(outFile, "# samples taken every %d usec\n", sampleInterval);
    fprintf(outFile, "# legend: M=mapping, E=event %d\n", pid);

    // save mappings of child (required for address->line conversion later)
    char mapFileName[200];
    sprintf(mapFileName, "/proc/%d/maps", pid);
    FILE* mapFd = fopen(mapFileName, "r");
    while (true)
    {
        char line[500];
        fgets(line, 500, mapFd);
        fprintf(outFile, "M: %s", line);
        if (feof(mapFd))
        {
            break;
        }
    }

    int64_t numSteps = 0;
    while (true)
    {
        if (terminate)
        {
            printf("terminate requested\n");
            ptrace(PTRACE_CONT, pid, 0, 0);
            break;
        }
        
        // interrupt child
        //printf("sending SIGTRAP...\n");
        kill(pid, SIGTRAP);

        int sigNo = 0;

        //printf("waiting for child...\n");        
        waitRes = wait(&waitStat);
        sigNo = WSTOPSIG(waitStat);
        if (sigNo == SIGTRAP)
        {
            sigNo = 0;
        }
        else
        {
            printf("child got unexpected signal %d\n", sigNo);
            ptrace(PTRACE_CONT, pid, 0, sigNo);
            //exit(1);
            break;
        }

        //printf("child paused\n");
        numSteps++;

        CreateSample(pid);

        ptrace(PTRACE_CONT, pid, 0, sigNo);
        //printf("child continued\n");

        usleep(sampleInterval);
    }
    printf("exiting after %lld single-steps\n", numSteps);

    return 0;
}

