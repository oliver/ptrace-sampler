
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>


void DoSleep ()
{
    usleep(1);
}


int Calc1 (const int input)
{
    int result = input;
    for (int i = 0; i < 10000; i++)
    {
        result += (i*i);
    }
    DoSleep();
    return result;
}


void* WorkFunc (void* userData)
{
    int* value = (int*)userData;
    while (1)
    {
        *value = Calc1(*value);
    }
    return NULL;
}


int main (int argc, char* argv[])
{
    printf("started; PID: %d\n", getpid());

    int value1 = 11;
    pthread_t threadId;
    pthread_create(&threadId, NULL, &WorkFunc, (void*)(&value1));

    int value = 10;
    while (1)
    {
        value = Calc1(value);
    }

    return value;
}

