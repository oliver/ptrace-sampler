
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>


int64_t numIterations = 0;

int Calc1 (const int num)
{
    static int result = 0;
    //for (int i = 0; i < num; i++)
    for (int i = 0; i < 1000; i++)
    {
        result += (i*i);
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

    printf("started with value %d, for %lld iterations\n", value, maxIterations);

    while (1)
    {
        value = Calc1(value);
        if ( /*value > 100 * 1000 * 1000 ||*/ value <= 0)
        {
            value = 10;
        }
        //usleep(10000);

        if (maxIterations > 0 && numIterations > maxIterations)
        {
            break;
        }
    }

    return value;
}

