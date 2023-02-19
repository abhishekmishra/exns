#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

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

/**
 * Struct representing a namespace type in linux.
 * It has the flag used for namespace APIS, and the name of the namespace
 * in paths.
 */
typedef struct {
    int flag;
    char* name;
} namespace_t;

// Globals

/** path string for use in all methods */
char EXNS_PATH_STR[PATH_MAX] = { '\0' };

/** list of available namespaces on the system, NULL terminated array of
 * strings*/
char* sys_ns[8] = { NULL };

/** All namespaces pairs (API flag, name) possible in linux */
namespace_t ALL_NS[] = {
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

/**
 * Get the ns flag given ns name
 * (return -1 if now found)
 *
 * @param name name of ns
 * @return flag
 */
int get_ns_flag_by_name(char* name)
{
    if(name == NULL)
    {
        return -1;
    }

    for(int i = 0; i < NAMESPACES_LEN; i++)
    {
        if(strcmp(ALL_NS[i].name, name) == 0)
        {
            return ALL_NS[i].flag;
        }
    }
    return -1;
}

/**
 * Get the ns name given flag
 * (return NULL if not found)
 *
 * @param flag flag of ns
 * @return name of ns
 */
char* get_ns_name_by_flag(int flag)
{
    for(int i = 0; i < NAMESPACES_LEN; i++)
    {
        if(ALL_NS[i].flag == flag)
        {
            return ALL_NS[i].name;
        }
    }
    return NULL;
}

void get_ns_symlink_list()
{
    char* self_pid_path = "/proc/self/ns/";
    for(int i = 0; i < NAMESPACES_LEN; i++)
    {
        snprintf(EXNS_PATH_STR, PATH_MAX, "%s%s", self_pid_path, ALL_NS[i].name);
        printf("%s\n", EXNS_PATH_STR);
    }
}


int main(int argc, char* argv[])
{
    printf("exns\n");
    printf("PID = %d, PPID = %d\n", getpid(), getppid());

    for(int i = 0; i < NAMESPACES_LEN; i++)
    {
        printf("%s\n", ALL_NS[i].name);
    }

    get_ns_symlink_list();
    exit(0);
}
