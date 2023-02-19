#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

int main(int argc, char* argv[])
{
    printf("exns\n");
    printf("PID = %d, PPID = %d\n", getpid(), getppid());
    exit(0);
}
