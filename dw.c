#include <stdio.h>

#include "aircrack-ng/src/osdep/osdep.h"

int main(int argc, const char *argv[])
{
    if (geteuid() != 0)
    {
        printf("This program requires root privileges.\n");
        return 1;
    }

    return 0;
}
