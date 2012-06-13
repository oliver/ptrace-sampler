
// test SIGCHLD handling

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>


void SigchldHandler (int sig)
{
    printf("signal %d\n", sig);
}

int main (int argc, char* argv[])
{
    printf("main pid: %d\n", getpid());

    //signal(SIGCHLD, SigchldHandler);

    while (true)
    {
        printf("looping...\n");

        const int pid = fork();
        if (pid == 0)
        {
            // child process
            sleep(1);
            exit(0);
        }

        sleep(2);
    }
}

