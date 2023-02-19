#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <unistd.h>

// Namespace types returned by NS_GET_NSTYPE.
#define CLONE_NEWNS       0x00020000
#define CLONE_NEWCGROUP   0x02000000
#define CLONE_NEWUTS      0x04000000
#define CLONE_NEWIPC      0x08000000
#define CLONE_NEWUSER     0x10000000
#define CLONE_NEWPID      0x20000000
#define CLONE_NEWNET      0x40000000
#define CLONE_NEWTIME     0x00000080
#define NAMESPACES_LEN    8

// NS paths construction
#define PROC_DIR          "/proc"

typedef struct {
    int flag;
    char* name;
} namespace_t;

namespace_t NAMESPACES[] = {
    {
        CLONE_NEWNS, "mnt"
    },
    {
        CLONE_NEWCGROUP, "cgroup"
    },
    {
        CLONE_NEWUTS, "uts"
    },
    {
        CLONE_NEWIPC, "ipc"
    },
    {
        CLONE_NEWUSER, "user"
    },
    {
        CLONE_NEWPID, "pid"
    },
    {
        CLONE_NEWNET, "net"
    },
    {
        CLONE_NEWTIME, "time"
    }
};


int main(int argc, char* argv[])
{
    char* path_str = (char*) calloc(sizeof(char), PATH_MAX);
    if(path_str == NULL)
    {
        fprintf(stderr, "Unable to allocate path string!\n");
        exit(-1);
    }
    path_str[0] = '\0';

    printf("exns\n");
    printf("PID = %d, PPID = %d\n", getpid(), getppid());

    for(int i = 0; i < NAMESPACES_LEN; i++)
    {
        printf("%s\n", NAMESPACES[i].name);
    }
    exit(0);
}
