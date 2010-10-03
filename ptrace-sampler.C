
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#include <wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include <vector>

using std::vector;


//
// Sampling Functions
//

#define M_OFFSETOF(STRUCT, ELEMENT) \
	(unsigned int) &((STRUCT *)NULL)->ELEMENT;

int ipoffs, spoffs, bpoffs;

/*struct Frame
{
    void* ebp;
    void* eip;
};*/

FILE* outFile = stderr;

void CreateSample (const int pid)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    fprintf(outFile, "%d.%06d\t", int(tv.tv_sec), int(tv.tv_usec));

    const int ip = ptrace(PTRACE_PEEKUSER, pid, ipoffs, 0);
	//const int sp = ptrace(PTRACE_PEEKUSER, pid, spoffs, 0);
	const int bp = ptrace(PTRACE_PEEKUSER, pid, bpoffs, 0);
	//printf("ip: %8x  sp: %8x  bp: %8x\n", ip, sp, bp);

    // printf("frame #0:  ip: %8x  sp: %8x  bp: %8x\n", ip, sp, bp);
    fprintf(outFile, "%08x ", ip);

	/*vector<Frame> frames;

	Frame f1;
	f1.ebp = (void*)bp;
	f1.eip = (void*)ip;
	frames.push_back(f1);*/

    int oldBp = bp;
    for (int i = 1; i < 10; i++)
    {
	    const int newBp = ptrace(PTRACE_PEEKDATA, pid, oldBp, 0);
	    const int newIp = ptrace(PTRACE_PEEKDATA, pid, oldBp+4, 0);
	    // printf("frame #%d:  ip: %8x  sp: %8x  bp: %8x\n", i, newIp, 0, newBp);
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

    // single-step in a loop
    int64_t numSteps = 0;
    while (true)
    {
        if (terminate)
        {
            printf("terminate requested\n");
            ptrace(PTRACE_CONT, pid, 0, 0);
            break;
        }
        
        sleep(1);
        //usleep(100);
        //sleep(1);

        // interrupt child
        //printf("sending SIGTRAP...\n");
        kill(pid, SIGTRAP);

        int sigNo = 0;
        /*const int pRes = ptrace(PTRACE_SINGLESTEP, pid, 0, sigNo);
        if (pRes < 0)
        {
            perror("singlestep error");
            exit(1);
        }*/

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
        //usleep(500 * 1000);
        numSteps++;

        CreateSample(pid);

        ptrace(PTRACE_CONT, pid, 0, sigNo);
        //printf("child continued\n");

        //break;
    }
    printf("exiting after %lld single-steps\n", numSteps);

    return 0;
}

