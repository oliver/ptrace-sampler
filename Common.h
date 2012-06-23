
#include <stdint.h>

extern bool debugEnabled;

int64_t TimestampUsec ();
char* TimestampString ();


#define DEBUG(...) if (debugEnabled) { printf("[%s] ", TimestampString()); printf(__VA_ARGS__); printf("\n"); }

