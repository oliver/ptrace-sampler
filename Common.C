
#include "Common.h"
#include <sys/time.h>

/// if true, debug messages will be printed
bool debugEnabled = false;

int64_t TimestampUsec ()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return int64_t(tv.tv_sec) * 1000000 + tv.tv_usec;
}

char* TimestampString ()
{
	static char timeStr[50];
	struct timeval tv;
	gettimeofday(&tv, NULL);
	sprintf(timeStr, "%d.%06d", int(tv.tv_sec), int(tv.tv_usec));
	return timeStr;
}

