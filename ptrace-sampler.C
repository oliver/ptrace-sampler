
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

void CreateSample (const int pid)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    fprintf(outFile, "E: t=%d.%06d;p=%d\t", int(tv.tv_sec), int(tv.tv_usec), pid);

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
        for (unsigned int i = 0; i < allTasks.size(); i++)
        {
            //printf("sending SIGSTOP to %d...\n", allTasks[i]);
            tkill(allTasks[i], SIGSTOP);
        }

        for (unsigned int i = 0; i < allTasks.size(); i++)
        {
            int sigNo = 0;

            //printf("waiting for child %d...\n", allTasks[i]);
            int waitStat = 0;
            int waitRes = waitpid(allTasks[i], &waitStat, __WALL);
            sigNo = WSTOPSIG(waitStat);
            if (sigNo == SIGSTOP)
            {
                sigNo = 0;
            }
            else
            {
                printf("child got signal %d\n", sigNo);
                ptrace(PTRACE_CONT, allTasks[i], 0, sigNo);
                continue;
            }

            //printf("child paused\n");
        }

        numSteps++;

        for (unsigned int i = 0; i < allTasks.size(); i++)
        {
            CreateSample(allTasks[i]);
        }

        for (unsigned int i = 0; i < allTasks.size(); i++)
        {
            ptrace(PTRACE_CONT, allTasks[i], 0, 0);
            //printf("child %d continued\n", allTasks[i]);
        }

        usleep(sampleInterval);
    }
    printf("exiting after %lld single-steps\n", numSteps);

    return 0;
}

