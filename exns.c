/**
 * @file exns.c
 *
 * Parts of this file are heavily based on the go program by Michael Kerrisk
 * for listing namespaces.
 * see https://man7.org/tlpi/code/online/dist/namespaces/namespaces_of.go.html
 *
 * I've re-written this program in C because I needed this program, and didn't
 * have a go environment setup on my linux machines. Also I don't know go
 * so I could only make guesses at some of the functionality in the code.
 *
 * This is also a good way to learn about namespaces by re-implementing the
 * namespace listing code.
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <coll_arraylist.h>
#include <zclk.h>

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
} ns_type_t;

/**
 * This type represents a namespace id,
 * given by the inode id of the namespace fd, and it device id
 */
typedef struct {
    uintmax_t inode;              ///> inode id of ns fd
    uintmax_t device;             ///> device id of ns fd
} ns_id_t;

/**
 * @brief create and return a new namespace id, using the given ns fd.
 *
 * @param nsfd file descriptor of the namespace file
 * @return new namespace id
 */
ns_id_t* new_ns_id(int nsfd);

/**
 * @brief free the given namespace id
 *
 * @param nsid to free
 */
void free_ns_id(ns_id_t* nsid);

typedef struct {
    int ns_type;            ///> CLONE_NEW*
    arraylist* pids;        ///> Member processes
    arraylist* children;    ///> Child+owned namespaces (user/PID NSs only)
    int creator_id;         ///> Userid of creator (User NSs only)
    char* uid_map;          ///> UID Map (User NSs only)
    char* gid_map;          ///> GID Map (User NSs only)
} ns_t;

typedef struct {
    ns_id_t* ns_id;
    ns_t* ns;
} ns_ls_entry_t;

int new_ns_ls_entry(ns_ls_entry_t **ent);

void free_ns_ls_entry(ns_ls_entry_t *ent);

typedef struct {
    arraylist* ns_ls;
    ns_id_t* root_ns;
} ns_info_t;

int new_ns_info(ns_info_t **nsinfo);

void free_ns_info(ns_info_t *nsinfo);

// Globals

/** path string for use in all methods */
char EXNS_PATH_STR[PATH_MAX] = { '\0' };

/** list of available namespaces on the system, NULL terminated array of
 * strings*/
char* EXNS_SYS_NS[NAMESPACES_LEN + 1] = { NULL };

/** All namespaces pairs (API flag, name) possible in linux */
ns_type_t ALL_NS[] = {
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
int get_ns_flag_by_name(char* name);

/**
 * Get the ns name given flag
 * (return NULL if not found)
 *
 * @param flag flag of ns
 * @return name of ns
 */
char *get_ns_name_by_flag(int flag);

/**
 * Updates the list of system namespaces in EXNS_SYS_NS.
 * This is done to ensure only namespaces available in the current
 * linux kernel are used while listing namespaces.
 *
 * The list of namespaces is fetched from the /proc/self/ns directory
 * which is the namespace directory on the /proc file-system of the
 * current process.
 *
 * There might be non-namespace directories in the directory, therefore
 * they are compared agains an existing list of all known linux namespace
 * types.
 *
 * @return error code
 */
int get_ns_symlink_list();

/**
 * @brief  opens a user or PID namespace symlink
 * (specified in 'ns_file')
 * for the process with the specified 'pid' and returns the resulting
 * file descriptor.
 * 
 * @param pid process id
 * @param ns_file the namespace file
 * @return fd file descriptor
 */
int open_ns_symlink(int pid, char* ns_file);

int add_ns_for_all_procs(ns_info_t *nsinfo, zclk_command* cmd);

int add_ns_for_one_proc(ns_info_t *nsinfo, char* pid, zclk_command* cmd);

int add_the_ns(ns_info_t *nsinfo, char *id, zclk_command *cmd);

int add_proc_ns(ns_info_t *nsinfo, char *pid, char *ns_file, zclk_command *cmd);

int add_pinned_ns(ns_info_t *nsinfo, char *pid, zclk_command *cmd);

zclk_res exns_main(zclk_command* cmd, void* handler_args)
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

    int nsfd = open_ns_symlink(getpid(), "mnt");
    ns_id_t *nsid = new_ns_id(nsfd);

    printf("fd is %d, dev=%jx, inode=%ju\n", nsfd, nsid->device, nsid->inode);

    if (nsfd > 0)
    {
        close(nsfd);
    }

    ns_info_t *nsinfo;
    new_ns_info(&nsinfo);
    res = add_ns_for_all_procs(nsinfo, cmd);

    return 0;
}

int main(int argc, char *argv[])
{
    zclk_command *cmd = new_zclk_command(argv[0], "exns",
                        "Linux Namespaces Explorer", &exns_main);

    zclk_command_flag_option(
        cmd,
        "all-pids",
        NULL,
        "For each displayed process, show PIDs in all namespaces of "
        "which the process is a member (used only in conjunction with "
        "\"--pidns\")."
    );

    zclk_command_flag_option(
        cmd,
        "--deep-scan",
        NULL,
        "Also show namespaces pinned into existence for reasons other"
        "than having member processes, being an owning user namespace,"
        "or being an ancestor (user or PID) namespace. This includes"
        "namespaces that are pinned into existence by bind mounts, by"
        "open file desciptors, and by 'pid_for_children' or"
        "'time_for_children' symlinks."
    );

    zclk_command_flag_option(
        cmd,
        "no-color",
        NULL,
        "Suppress the use of color in the displayed output."
    );

    zclk_command_flag_option(
        cmd,
        "no-pids",
        NULL,
        "Suppress the display of the processes that are members of each"
        "namespace."
    );

    zclk_command_flag_option(
        cmd,
        "pidns",
        NULL,
        "Display the PID namespace hierarchy (rather than the user"
        "namespace hierarchy)."
    );

    zclk_command_flag_option(
        cmd,
        "search-tasks",
        NULL,
        "Look for namespaces via /proc/PID/task/*/ns/* rather than"
        "/proc/PID/ns/*. (Does more work in order to find namespaces"
        "that may be occupied by noninitial threads.) Also causes"
        "member TIDs (rather than PIDs) to be displayed for each"
        "namespace."
    );

    zclk_command_flag_option(
        cmd,
        "show-comm",
        NULL,
        "Displays the command being run by each process."
    );

    zclk_command_string_argument(
        cmd,
        "namespaces",
        NULL,
        "Show just the listed namespace types when displaying the"
        "user namespace hierarchy. <list> is a comma-separated list"
        "containing one or more of \"cgroup\", \"ipc\", \"mnt\", \"net\", \"pid\","
        "\"time\", \"user\", and \"uts\". (The default is to include all"
        "nonuser namespace types in the display of the user namespace"
        "hierarchy.) To see just the user namespace hierarchy, use"
        "\"--namespaces=user\".",
        1
    );

    int res = zclk_command_exec(cmd, NULL, argc, argv);

    return res;
}

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

int open_ns_symlink(int pid, char* ns_file)
{
    snprintf(EXNS_PATH_STR, PATH_MAX, "/proc/%d/ns/%s", pid, ns_file);
    printf("Path is %s\n", EXNS_PATH_STR);

    int nsfd = open(EXNS_PATH_STR, O_RDONLY, 0);
    if(nsfd < 0)
    {
        fprintf(stderr,
                "Error finding namespace subtree for PID:%d at %s\n",
               pid,
               EXNS_PATH_STR);
        return -1;
    }
    return nsfd;
}

ns_id_t* new_ns_id(int nsfd)
{
    struct stat nsfd_stat;
    int res = fstat(nsfd, &nsfd_stat);
    if(res != 0)
    {
        fprintf(stderr, "Error getting stat for fd %d.\n", nsfd);
        return NULL;
    }

    ns_id_t *nsid = (ns_id_t *)calloc(1, sizeof(ns_id_t));
    if(nsid == NULL)
    {
        fprintf(stderr, "Unable to allocate struct ns_id_t!\n");
        return NULL;
    }

    nsid->device = nsfd_stat.st_dev;
    nsid->inode = nsfd_stat.st_ino;

    return nsid;
}

void free_ns_id(ns_id_t* nsid)
{
    free(nsid);
}

int new_ns_info(ns_info_t **nsinfo)
{
    ns_info_t *nsi = (ns_info_t *)calloc(1, sizeof(ns_info_t));
    if(nsi == NULL)
    {
        fprintf(stderr, "Error allocating ns_info_t.\n");
        return -1;
    }

    int res = arraylist_new(&nsi->ns_ls, 
                            (void (*)(void *))&free_ns_ls_entry);
    if(res != 0)
    {
        fprintf(stderr, "Error creating namespace list.\n");
        return -1;
    }

    return 0;
}

void free_ns_info(ns_info_t *nsinfo)
{

}

int new_ns_ls_entry(ns_ls_entry_t **ent)
{
    return 0;
}

void free_ns_ls_entry(ns_ls_entry_t *ent)
{
    //TODO: free members
    free(ent);
}

int add_ns_for_all_procs(ns_info_t *nsinfo, zclk_command* cmd)
{
    char *proc_dir = "/proc";
    DIR *dirp;
    struct dirent *dent;

    // open the /proc directory
    dirp = opendir(proc_dir);
    if (dirp == NULL)
    {
        fprintf(stderr, "Open directory failed for path %s.\n", proc_dir);
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

        if(dent->d_name[0] >= '1' && dent->d_name[0] <= '9')
        {
            printf("found pid dir %s\n", dent->d_name);
            add_ns_for_one_proc(nsinfo, dent->d_name, cmd);
        }
        //dent->d_name
    }

    // close the directory and return
    if (closedir(dirp) == -1)
    {
        fprintf(stderr, "Failed to close directory.\n");
        return -1;
    }

    return 0;
}

int add_ns_for_one_proc(ns_info_t *nsinfo, char* pid, zclk_command* cmd)
{
    int search_tasks = zclk_option_get_val_bool(
        zclk_command_get_option(cmd, "search-tasks")
    );

    if(search_tasks != 0)
    {
        snprintf(EXNS_PATH_STR, PATH_MAX, "/proc/%s/task", pid);
        DIR *dirp;
        struct dirent *dent;

        // open the /proc directory
        dirp = opendir(EXNS_PATH_STR);
        if (dirp == NULL)
        {
            fprintf(stderr,
                    "Open directory failed for path %s.\n", EXNS_PATH_STR);
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

            add_the_ns(nsinfo, dent->d_name, cmd);

            //dent->d_name
        }

        // close the directory and return
        if (closedir(dirp) == -1)
        {
            fprintf(stderr, "Failed to close directory.\n");
            return -1;
        }

    }
    else
    {
        printf("Use pids not tasks\n");
        add_the_ns(nsinfo, pid, cmd);
    }

    return 0;
}

int add_the_ns(ns_info_t *nsinfo, char *id, zclk_command *cmd)
{
    return 0;
}

int add_proc_ns(ns_info_t *nsinfo, char *pid, char *ns_file, zclk_command *cmd)
{
    return 0;
}

int add_pinned_ns(ns_info_t *nsinfo, char *pid, zclk_command *cmd)
{
    return 0;
}
