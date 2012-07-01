
// test some libc functions (gettimeofday, getpid, memset, memcpy, strncpy)

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <vector>

using namespace std;


int64_t numIterations = 0;

int Func2 ()
{
//    sleep(1);
//    printf("sleep finished\n");
//    return 1;

    static char buffer1[100];
    static char buffer2[100];
    memset(buffer1, 'a', 100);
    strncpy(buffer2, buffer1, 100);
    memcpy(buffer2, buffer1, 100);

    struct timeval tv;
    gettimeofday(&tv, NULL);

    return getpid();
}

int Calc1 ()
{
    static int result = 0;
    for (int i = 0; i < 1000; i++)
    {
        for (int j = 0; j < 5; j++)
        {
            result += Func2();
        }
        numIterations++;
    }
    return result;
}


int main (int argc, char* argv[])
{
    int64_t maxIterations = int64_t(100) * 1000 * 1000;
    if (argc > 1)
    {
        maxIterations = int64_t( atoi(argv[1]) );
    }

    printf("started, for %lld iterations; PID: %d\n", maxIterations, getpid());
    int value = 0;
    for (int64_t i = 0; i < maxIterations; i++)
    {
        value += Calc1();
    }

    return value;
}

