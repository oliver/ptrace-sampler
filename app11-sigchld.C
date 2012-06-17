
// test SIGCHLD handling

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/wait.h>


void SigchldHandler (int sig)
{
    printf("signal %d\n", sig);
}

void Sigusr1Handler (int sig)
{
    printf("Sigusr1Handler - signal %d\n", sig);
}

int main (int argc, char* argv[])
{
    printf("main pid: %d\n", getpid());

    signal(SIGCHLD, SigchldHandler);
    signal(SIGUSR1, Sigusr1Handler);

    int counter = 0;
    while (true)
    {
        counter++;
        printf("iteration #%d...\n", counter);

        kill(getpid(), SIGUSR1);
        const int pid = fork();
        if (pid == 0)
        {
            // child process
            sleep(1);
            exit(0);
        }

        const int pid2 = fork();
        if (pid2 == 0)
        {
            exit(0);
        }

        int waitRes;
        do
        {
            int waitStat;
            waitRes = waitpid(-1, &waitStat, WNOHANG);
        } while (waitRes > 0);

        sleep(2);
    }
}

