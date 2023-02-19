#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include <unistd.h>
#include <dirent.h>

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
char* EXNS_SYS_NS[NAMESPACES_LEN + 1] = { NULL };

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

/**
 * Updates the list of system namespaces in EXNS_SYS_NS.
 * This is done to ensure only namespaces available in the current
 * linux kernel are used while listing namespaces.
 *
 * @return error code
 */
int get_ns_symlink_list()
{
    char* self_pid_path = "/proc/self/ns/";
    DIR *dirp;
    struct dirent *dent;
    int flag;
    int ns_count = 0;

    // open the self pid directory
    dirp = opendir(self_pid_path);
    if (dirp == NULL)
    {
        fprintf(stderr, "Open directory failed for path %s.\n", self_pid_path);
        return -1;
    }

    // loop till no further directory entries are found
    for (;;)
    {
        // read the next directory entry
        dent = readdir(dirp);

        // if there is no directory entry returned, exit the loop
        if (dent == NULL)
        {
            break;
        }

        // ignore "." and ".." directory entries as they cannot be namespaces
        if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0)
        {
            continue;               /* Skip . and .. */
        }

        // lookup directory entry name to check if it is a namespace name
        flag = get_ns_flag_by_name(dent->d_name);
        //printf("%s/%s, flag = %d\n", self_pid_path, dent->d_name, flag);

        // if the directory entry name is a namespace then
        // get the program static string for the entry
        // and append it to the known namespaces list
        // note that the string provided by directory entry is not
        // owned by this program therefore ns name has to be looked up again.
        if(flag != -1)
        {
            EXNS_SYS_NS[ns_count] = get_ns_name_by_flag(flag);
            ns_count += 1;
        }
    }

    // close the directory and return
    if (closedir(dirp) == -1)
    {
        fprintf(stderr, "Failed to close directory.\n");
        return -1;
    }

    return 0;
}


int main(int argc, char* argv[])
{
    int res;

    printf("Process PID = %d, PPID = %d\n", getpid(), getppid());

    //for(int i = 0; i < NAMESPACES_LEN; i++)
    //{
    //    printf("%s\n", ALL_NS[i].name);
    //}

    // load the system available namespaces
    res = get_ns_symlink_list();

    // if there was an error getting list of system namespaces
    if(res != 0)
    {
        exit(-1);
    }

    printf("Namespace types available on this system are:\n");
    for(int i = 0; i < NAMESPACES_LEN+1; i++)
    {
        if(EXNS_SYS_NS[i] == NULL)
        {
            break;
        }
        printf("%s\n", EXNS_SYS_NS[i]);
    }

    exit(0);
}
