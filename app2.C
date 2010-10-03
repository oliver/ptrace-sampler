
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>


int64_t numIterations = 0;

int Calc1 (const int num)
{
    static int result = 0;
    //for (int i = 0; i < num; i++)
    for (int i = 0; i < 1000; i++)
    {
        for (int j = 0; j < 5; j++)
        {
            result += (i*i);
        }
        numIterations++;
    }
    return result;
}


int main (int argc, char* argv[])
{
    //const int startValue = atoi(argv[1]);
    //int value = int(char(argv[0][0]));
    int value = 10;

    int64_t maxIterations = int64_t(100) * 1000 * 1000;
    if (argc > 1)
    {
        maxIterations = int64_t( atoi(argv[1]) ) * 1000 * 1000;
    }

    printf("started with value %d, for %lld iterations; PID: %d\n", value, maxIterations, getpid());

    struct timeval startTime, endTime;
    while (1)
    {
        //const time_t startTime = time(NULL);
        gettimeofday(&startTime, NULL);
        const int64_t startIterations = numIterations;

        value = Calc1(value);

        //const time_t endTime = time(NULL);
        gettimeofday(&endTime, NULL);
        const int64_t startUsec = (int64_t(startTime.tv_sec)*1000*1000) +  int64_t(startTime.tv_usec);
        const int64_t endUsec   = (int64_t(endTime.tv_sec)  *1000*1000) +  int64_t(endTime.tv_usec);
        const int64_t durationUsec = endUsec - startUsec;

        const int64_t deltaIterations = numIterations - startIterations;
        const double iterationsPerSecond = double(deltaIterations) / (double(durationUsec) / (1000*1000));
        printf("\rit/s: %f (%lld it in %lld usec)    ", iterationsPerSecond, deltaIterations, durationUsec);

        if ( /*value > 100 * 1000 * 1000 ||*/ value <= 0)
        {
            value = 10;
        }
        //usleep(10000);

//        if (maxIterations > 0 && numIterations > maxIterations)
//        {
//            break;
//        }
    }

    return value;
}

