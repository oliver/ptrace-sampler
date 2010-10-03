
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>

#include <wait.h>
#include <sys/ptrace.h>


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

        int sigNo = 0;
        const int pRes = ptrace(PTRACE_SINGLESTEP, pid, 0, sigNo);
        if (pRes < 0)
        {
            perror("singlestep error");
            exit(1);
        }
        
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

        //ptrace(PTRACE_CONT, pid, 0, sigNo);

        //break;
    }
    printf("exiting after %lld single-steps\n", numSteps);

    return 0;
}

