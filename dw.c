#include <stdio.h>
#include <string.h>

#include "aircrack-ng/src/osdep/osdep.h"

void print_help()
{
    printf("dw <interface>")
}

int main(int argc, const char *argv[])
{
    if (geteuid() != 0)
    {
        printf("This program requires root privileges.\n");
        return 1;
    }

    if (argc < 2  || !memcmp(argv[1], "--help", 6))
    {
        printf("need help");
        return 1;
    }

    return 0;
}
