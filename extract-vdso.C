
#include "Vdso.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>
using std::string;

int main (int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <output file>\n", argv[0]);
        return 1;
    }

    const string targetPath = argv[1];

    VdsoBinary binary;
    binary.Path();
    const string cmd = string("cp '" + binary.Path() + "' '" + targetPath + "'");
    return system(cmd.c_str());
}
