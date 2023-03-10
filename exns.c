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
#include <errno.h>
#include <sys/ioctl.h>

/* for NS_GET_NSTYPE */
#include <linux/nsfs.h>

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

/* some terminal display constants */
#define _TERM_ESC           ""
#define _TERM_RED           ESC + "[31m"
#define _TERM_YELLOW        ESC + "[93m"
#define _TERM_BOLD          ESC + "[1m"
#define _TERM_LIGHT_BLUE    ESC + "[38;5;51m"
#define _TERM_NORMAL        ESC + "(B" + ESC + "[m"
#define _TERM_PID_COLOR     LIGHT_BLUE
#define _TERM_USERNS_COLOR  YELLOW + BOLD

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

/**
 * @brief create a new namespace
 * 
 * @param ns namespace object to create and return
 * @return int result code
 */
int new_ns(ns_t **ns);

/**
 * @brief free the namespace object
 * 
 * @param ns namespace to free
 */
void free_ns(ns_t *ns);

typedef struct {
    ns_id_t* ns_id;
    ns_t* ns;
} ns_ls_entry_t;

/**
 * @brief create a new namespaces list entry
 *
 * @param ent namespace entry to create
 * @return error code
 */
int new_ns_ls_entry(ns_ls_entry_t **ent);

/**
 * @brief free the namespaces list entry
 *
 * @param ent entry to free
 */
void free_ns_ls_entry(ns_ls_entry_t *ent);

typedef struct {
    arraylist* ns_ls;
    ns_id_t* root_ns;
} ns_info_t;

/**
 * @brief Create a new namespace info
 *
 * @param nsinfo namespace info to create
 * @return error code
 */
int new_ns_info(ns_info_t **nsinfo);

/**
 * @brief free the namespace info
 *
 * @param nsinfo namespace info to free
 */
void free_ns_info(ns_info_t *nsinfo);

/**
 * @brief check if the given nsid is already in the info's ns list
 *
 * @param nsinfo info
 * @param nsid id to look for
 * @return boolean indicating wheter nsid was found
 */
int has_ns_id(ns_info_t *nsinfo, ns_id_t* nsid);

/**
 * @brief Get the ns corresponding to the values in the passed nsid
 * 
 * @param nsinfo info
 * @param nsid id to look for
 * @return ns_t* found ns (or NULL)
 */
ns_t *get_ns_for_id(ns_info_t *nsinfo, ns_id_t *nsid);

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

int add_proc_ns(ns_info_t *nsinfo, char *pid, char *ns_file, 
    zclk_command *cmd, int is_cmdline_arg);

int add_pinned_ns(ns_info_t *nsinfo, char *pid, zclk_command *cmd);

ns_id_t* add_ns(ns_info_t *nsinfo, int nsfd, int npid, zclk_command *cmd);

int add_ns_to_ls(ns_info_t *nsinfo, ns_id_t *nsid, 
    int nsfd, zclk_command *cmd);

/**
 * @brief Get the ns type of the given nsfd
 * 
 * @param nsfd namespace fd
 * @param fail_on_err whether to fail on error
 * @return int CLONE_NEW* constant for the given ns OR -1 if not found
 */
int get_ns_type(int nsfd, int fail_on_err);

/**
 * @brief Wrapper for ioctl call
 * 
 * @param fd file descriptor
 * @param op operation
 * @return int ioctl value
 */
int get_ioctl(int fd, int op);

/**
 * @brief get the creator UID of the user ns
 * 
 * @param nsfd fd of the namespace file
 * @return int creator uid
 */
int get_creator_uid(int nsfd);

/**
 * @brief Display the namespace info heirarchy on the terminal
 * 
 * @param nsinfo ns info to display
 * @param cmd the command line options
 */
void display_ns_heirarchies(ns_info_t *nsinfo, zclk_command *cmd);

/**
 * @brief recursively displays the namespace subtree inside nsinfo->ns_ls
 * 
 * @param nsinfo ns info to display
 * @param nsid_to_show the namespace id to display
 * @param level indentation level
 * @param cmd the command line options
 */
void display_ns_tree(ns_info_t *nsinfo, ns_id_t *nsid_to_show,
    int level, zclk_command *cmd);

/**
 * @brief Display the particular namespace
 * 
 * @param nsinfo ns info to display
 * @param nsid_to_show the namespace id to display
 * @param level indentation level
 * @param cmd the command line options
 */
void display_ns(ns_info_t *nsinfo, ns_id_t *nsid_to_show,
    int level, zclk_command *cmd);

/**
 * the invisible user ns, initialized to 0,0 in exns_main
 */
ns_id_t *invis_user_ns = NULL;

zclk_res exns_main(zclk_command* cmd, void* handler_args)
{
    int res;

    /* init the special ns id */
    invis_user_ns = (ns_id_t *)calloc(1, sizeof(ns_id_t));
    if(invis_user_ns == NULL)
    {
        fprintf(stderr, "Unable to allocate struct ns_id_t!\n");
        exit(1);
    }
    invis_user_ns->device = 0;
    invis_user_ns->inode = 0;

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

    /* create a new namespace info */
    ns_info_t *nsinfo;
    new_ns_info(&nsinfo);

    /* add namespaces to nsinfo for all processes according to options */
    res = add_ns_for_all_procs(nsinfo, cmd);

    /* display ns heirarchies */
    display_ns_heirarchies(nsinfo, cmd);

    /* free the namespace info */
    free_ns_info(nsinfo);

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
        " which the process is a member (used only in conjunction with "
        " \"--pidns\")."
    );

    zclk_command_flag_option(
        cmd,
        "deep-scan",
        NULL,
        "Also show namespaces pinned into existence for reasons other"
        " than having member processes, being an owning user namespace,"
        " or being an ancestor (user or PID) namespace. This includes"
        " namespaces that are pinned into existence by bind mounts, by"
        " open file desciptors, and by 'pid_for_children' or"
        " 'time_for_children' symlinks."
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
        " namespace."
    );

    zclk_command_flag_option(
        cmd,
        "pidns",
        NULL,
        "Display the PID namespace hierarchy (rather than the user"
        " namespace hierarchy)."
    );

    zclk_command_flag_option(
        cmd,
        "search-tasks",
        NULL,
        "Look for namespaces via /proc/PID/task/*/ns/* rather than"
        " /proc/PID/ns/*. (Does more work in order to find namespaces"
        " that may be occupied by noninitial threads.) Also causes"
        " member TIDs (rather than PIDs) to be displayed for each"
        " namespace."
    );

    zclk_command_flag_option(
        cmd,
        "show-comm",
        NULL,
        "Displays the command being run by each process."
    );

    zclk_command_string_option(
        cmd,
        "namespaces",
        NULL,
        "",
        "Show just the listed namespace types when displaying the"
        " user namespace hierarchy. <list> is a comma-separated list"
        " containing one or more of \"cgroup\", \"ipc\", \"mnt\", \"net\", \"pid\","
        " \"time\", \"user\", and \"uts\". (The default is to include all"
        " nonuser namespace types in the display of the user namespace"
        " hierarchy.) To see just the user namespace hierarchy, use"
        " \"--namespaces=user\"."
    );
    
    zclk_command_string_option(
        cmd,
        "subtree",
        NULL,
        "",
        "if the --subtree option is specified, then the"
        " program shows the subtree of the user or PID namespace"
        " hierarchy that is rooted at  the namespace of the specified"
        " PID."
    );

    zclk_command_string_argument(
        cmd,
        "pids",
        NULL,
        "Pids whose namespaces are to be listed.",
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

int new_ns(ns_t **ns)
{
    ns_t *nsobj = (ns_t *)calloc(1, sizeof(ns_t));
    if(nsobj == NULL)
    {
        fprintf(stderr, "Error allocating ns_t.\n");
        return -1;
    }

    int res = arraylist_new(&nsobj->pids, &free);
    if(res != 0)
    {
        fprintf(stderr, "Error creating pids list.\n");
        return -1;
    }

    // TODO: decide list member type
    res = arraylist_new(&nsobj->children, &free);
    if(res != 0)
    {
        fprintf(stderr, "Error creating children list.\n");
        return -1;
    }

    nsobj->gid_map = NULL;
    nsobj->uid_map = NULL;

    (*ns) = nsobj;

    return 0;
}

void free_ns(ns_t *ns)
{
    arraylist_free(ns->pids);
    arraylist_free(ns->children);
    if(ns->gid_map != NULL)
    {
        free(ns->gid_map);
    }
    if(ns->uid_map != NULL)
    {
        free(ns->uid_map);
    }
    free(ns);
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

    (*nsinfo) = nsi;

    return 0;
}

void free_ns_info(ns_info_t *nsinfo)
{
    arraylist_free(nsinfo->ns_ls);
    if(nsinfo->root_ns != NULL)
    {
        free(nsinfo->root_ns);
    }
    free(nsinfo);
}

int has_ns_id(ns_info_t *nsinfo, ns_id_t* nsid)
{
    size_t len, i;
    len = arraylist_length(nsinfo->ns_ls);
    for (i = 0; i < len; i++)
    {
        ns_ls_entry_t *entry = 
            (ns_ls_entry_t *)arraylist_get(nsinfo->ns_ls, i);
        if(entry != NULL)
        {
            ns_id_t *oth = entry->ns_id;
            if(oth->device == nsid->device 
                && oth->inode == nsid->inode)
            {
                //printf("********** found nsid %zu, %zu\n", 
                //    nsid->device, nsid->inode);
                return 1;
            }
        }
    }
    return 0;
}

ns_t *get_ns_for_id(ns_info_t *nsinfo, ns_id_t *nsid)
{
    size_t len, i;
    len = arraylist_length(nsinfo->ns_ls);
    for (i = 0; i < len; i++)
    {
        ns_ls_entry_t *entry = 
            (ns_ls_entry_t *)arraylist_get(nsinfo->ns_ls, i);
        if(entry != NULL)
        {
            ns_id_t *oth = entry->ns_id;
            if(oth->device == nsid->device 
                && oth->inode == nsid->inode)
            {
                return entry->ns;
            }
        }
    }
    return NULL;
}

int new_ns_ls_entry(ns_ls_entry_t **ent)
{
    ns_ls_entry_t *e = (ns_ls_entry_t *)calloc(1, sizeof(ns_ls_entry_t));
    if(e == NULL)
    {
        fprintf(stderr, "Error allocating ns_ls_entry_t.\n");
        return -1;
    }

    e->ns = NULL;
    e->ns_id = NULL;

    (*ent) = e;

    return 0;
}

void free_ns_ls_entry(ns_ls_entry_t *ent)
{
    if(ent->ns != NULL)
    {
        free_ns(ent->ns);
    }
    
    if(ent->ns_id != NULL)
    {
        free_ns_id(ent->ns_id);
    }

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
            printf("================ found pid dir %s\n", dent->d_name);
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
        printf("task folder -> %s\n", EXNS_PATH_STR);
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
    int res = 0;
    for(int i = 0; i < NAMESPACES_LEN+1; i++)
    {
        if(EXNS_SYS_NS[i] == NULL)
        {
            break;
        }
        //printf("pid=%s, ns=%s\n", id, EXNS_SYS_NS[i]);
        res = add_proc_ns(nsinfo, id, EXNS_SYS_NS[i], cmd, 0);
        if(res != 0)
        {
            return res;
        }
    }

    int deep_scan = zclk_option_get_val_bool(
        zclk_command_get_option(cmd, "deep-scan")
    );

    if (deep_scan != 0)
    {
        res = add_pinned_ns(nsinfo, id, cmd);
    }

    return res;
}

int add_proc_ns(ns_info_t *nsinfo, char *pid, char *ns_file, zclk_command *cmd, int is_cmdline_arg)
{
    snprintf(EXNS_PATH_STR, PATH_MAX, "/proc/%s/ns/%s", pid, ns_file);
    printf("Path is %s\n", EXNS_PATH_STR);

    int nsfd = open(EXNS_PATH_STR, O_RDONLY, 0);
    if(nsfd < 0)
    {
        if(errno == EACCES)
        {
            fprintf(stderr, "Cannot access %s, please run with root.\n",
                    EXNS_PATH_STR);
            return -1;
        }
        else
        {
            fprintf(stderr,
                 "Error finding namespace subtree for PID:%s at %s, errno=%d\n"
                 "Process %s terminated while parsing?\n",
                 pid,
                 EXNS_PATH_STR,
                 errno,
                 pid);
            return -1;
        }
    }

    int npid = atoi(pid);
    add_ns(nsinfo, nsfd, npid, cmd);

    close(nsfd);

    return 0;
}

ns_id_t* add_ns(ns_info_t *nsinfo, int nsfd, int npid, zclk_command *cmd)
{
    ns_id_t* nsid = new_ns_id(nsfd);

    int find = has_ns_id(nsinfo, nsid);
    //printf("&&&&&&&& found = %d.\n", find);
    if (find == 0)
    {
        add_ns_to_ls(nsinfo, nsid, nsfd, cmd);
    }

    if (npid > 0)
    {
        ns_t* ns = get_ns_for_id(nsinfo, nsid);
        int *pidptr = (int *)calloc(1, sizeof(int));
        *pidptr = npid;

        /* adding pid to existing ns */
        printf("Adding pid[%d] to namespace id [%zu %zu].\n",
            npid, nsid->device, nsid->inode);
        arraylist_add(ns->pids, pidptr);
    }

    // TODO: nsid is created extra in case it is not found
    // make sure to handle the deallocation at the appropriate time.
    return nsid;
}

int add_pinned_ns(ns_info_t *nsinfo, char *pid, zclk_command *cmd)
{
    return 0;
}

int add_ns_to_ls(ns_info_t *nsinfo, ns_id_t *nsid, 
    int nsfd, zclk_command *cmd)
{
    int res;
    ns_ls_entry_t *entry;
    ns_t *ns;
    int ioctl_op;
    int show_pids_heirarcy = zclk_option_get_val_bool(
        zclk_command_get_option(cmd, "pidns"));
    int parent_fd;
    
    /* create a new namespace list entry */
    res = new_ns_ls_entry(&entry);
    if(res != 0)
    {
        return res;
    }

    /* create a new namespace */
    res = new_ns(&ns);
    if(res != 0)
    {
        return res;
    }

    /* set namespace and id for entry */
    entry->ns = ns;
    entry->ns_id = nsid;

    /* add entry to the namespaces list */
    arraylist_add(nsinfo->ns_ls, entry);

    /* set namespace type of entry */
    entry->ns->ns_type = get_ns_type(nsfd, 1);
    printf("ns type is -> %d\n", entry->ns->ns_type);

    printf("--> Added %zu:%zu to namespaces list.\n", 
           nsid->device, nsid->inode);
    
    /* if this is a user ns, record user ID of the creator */
    if(entry->ns->ns_type == CLONE_NEWUSER)
    {
        printf("UUUUUUUUUUU -> This is a user ns.\n");
        entry->ns->creator_id = get_creator_uid(nsfd);
        printf("UUUUUUUUUUU -> creator uid is %d.\n",
               entry->ns->creator_id);
    }
    
    /* get parent ns (for pid heirarcy use differnt op) */
    ioctl_op = NS_GET_USERNS;
	if (show_pids_heirarcy)
    {
		ioctl_op = NS_GET_PARENT;
	}
	
	parent_fd = get_ioctl(nsfd, ioctl_op);
    
    if(parent_fd == -1)
    {
        // any error other than EPERM is unexpedted: exit with err
        
        if(errno != EPERM)
        {
            fprintf(stderr, "Error getting parent ns %d\n", errno);
            exit(1);
        }

        // we have an eperm error
        if(entry->ns->ns_type == CLONE_NEWUSER || ioctl_op == NS_GET_PARENT)
        {
            // If the current namespace is a user namespace and
			// NS_GET_USERNS fails with EPERM, or we are processing
			// only PID namespaces and NS_GET_PARENT fails with
			// EPERM, then this is the root namespace (or, at
			// least, the topmost visible namespace); remember it.

            nsinfo->root_ns = nsid;
        }
        else
        {
            // Otherwise, we are inspecting a nonuser namespace and
			// NS_GET_USERNS failed with EPERM, meaning that the
			// user namespace that owns this nonuser namespace is
			// not visible (i.e., is an ancestor user namespace).
			// Record these namespaces as children of a special
			// entry in the 'nsList' map. (For an example, use:
			// sudo unshare -Ur sh -c 'go run namespaces_of.go $$')

            int find = has_ns_id(nsinfo, invis_user_ns);
            ns_ls_entry_t *special_ns_entry;
            ns_t *special_ns;
            if(find == 0)
            {
                res = new_ns_ls_entry(&special_ns_entry);
                if(res != 0)
                {
                    return res;
                }

                res = new_ns(&special_ns);
                if(res != 0)
                {
                    return res;
                }

                special_ns_entry->ns = special_ns;
                special_ns_entry->ns_id = invis_user_ns;
                special_ns->ns_type = CLONE_NEWUSER;

                arraylist_add(nsinfo->ns_ls, special_ns_entry);
            }
            special_ns = get_ns_for_id(nsinfo, invis_user_ns);
            arraylist_add(special_ns->children, nsid);
        }
    }
    else
    {
		// The ioctl() operation successfully returned a parent/owning
		// namespace; make sure that namespace has an entry in the map.
		// Specify the 'pid' argument as -1, meaning that there is no
		// PID to be recorded as being a member of the parent/owning
		// namespace.

		ns_id_t* parent = add_ns(nsinfo, parent_fd, -1, cmd);

		// Make the current namespace entry a child of the
		// parent/owning namespace entry.

        arraylist_add(get_ns_for_id(nsinfo, parent)->children, nsid);
        close(parent_fd);
    }

    return 0;
}

int get_ns_type(int nsfd, int fail_on_err)
{
    int ns_type = get_ioctl(nsfd, NS_GET_NSTYPE);

    if(ns_type == -1)
    {
        fprintf(stderr, "ioctl(NS_GET_NSTYPE) error %d.\n", errno);
        if(fail_on_err != 0)
        {
            exit(1);
        }
        else
        {
            return -1;
        }
    }
    return ns_type;
}

int get_ioctl(int fd, int op)
{
    int ret = ioctl(fd, op, 0);
    return ret;
}

int get_creator_uid(int nsfd)
{
    int uid;
    
    int ret = ioctl(nsfd, NS_GET_OWNER_UID, &uid);
    if(ret == -1)
    {
        fprintf(stderr, 
                "Error getting NS_GET_OWNER_UID for fd %d.\n", 
                nsfd);
        exit(1);
    }
    
    return uid;
}

void display_ns_heirarchies(ns_info_t *nsinfo, zclk_command *cmd)
{
    printf("------------DISPLAY------------\n");

    // TODO: subtree pid is not added to command, add it
    // int subtree_pid;

    // if there is no subtree specified.

    display_ns_tree(nsinfo, nsinfo->root_ns, 0, cmd);

    // Display the namespaces owned by (invisible) ancestor user
    // namespaces.

    int find = has_ns_id(nsinfo, invis_user_ns);
    if(find != 0)
    {
        display_ns_tree(nsinfo, invis_user_ns, 0, cmd);
    }
}

void display_ns_tree(ns_info_t *nsinfo, ns_id_t *nsid_to_show,
    int level, zclk_command *cmd)
{
    ns_t *ns_to_show = get_ns_for_id(nsinfo, nsid_to_show);

    // Display 'nsid' if its type is one of those specified in
	// 'opts.namespaces', but always display user namespaces.

    if(ns_to_show->ns_type == CLONE_NEWUSER)
    {
        display_ns(nsinfo, nsid_to_show, level, cmd);
    }

    size_t len = arraylist_length(ns_to_show->children);
    for (size_t i = 0; i < len; i++)
    {
        ns_id_t *child = (ns_id_t *)arraylist_get(ns_to_show->children, i);
        display_ns_tree(nsinfo, child, level + 1, cmd);
    }
}

void display_ns(ns_info_t *nsinfo, ns_id_t *nsid_to_show,
    int level, zclk_command *cmd)
{
    printf("displaying ns with id[%zu:%zu]\n", 
        nsid_to_show->device, nsid_to_show->inode);
}
