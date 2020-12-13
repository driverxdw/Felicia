#include <sys/types.h>

#define MAX_BUFF_SIZE 128
#define NORMAL_BUFF_SIZE 32
#define HASH_LEN 32
#define EVENT_TYPE 16
#define MAX_MSGSIZE 256
#define PATH_MAX_1 1024
#define MD5_STR_LEN 32
#define READ_DATA_SIZE	1024
#define MD5_SIZE		16
#define PRG_SOCKET_PFX    "socket:["
#define PRG_SOCKET_PFXl (strlen(PRG_SOCKET_PFX))
#define PRG_SOCKET_PFX2   "[0000]:"
#define PRG_SOCKET_PFX2l  (strlen(PRG_SOCKET_PFX2))
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
#define ADDR_LEN INET6_ADDRSTRLEN + 1 + 5 + 1
#define MAXMSG 512

#define MAX_INT_LEN 10
#define MAX_PATH_LEN 19
#define BUFF_LEN 1024

typedef union iaddr iaddr;
union iaddr {
    unsigned u;
    unsigned char b[4];
};

struct ProcessEvent{
    char *evt;
    pid_t pid;
    pid_t ppid;
    char *path;
    char *cmdline;
    char *cwd; 
    char *ppath;
    char *pcmdline;
    char *pname;
    char *ppname;
    uid_t uid;
    gid_t gid;
    char *stdin;
    char *stdout;
    char *tty;
    time_t unixTime;
    char *hash[HASH_LEN];
    char *hostIdentifier;
    char *username;
    char *usergroup;
    pid_t tgid;
    pid_t pgid;
    pid_t sid;
};

struct ProcStat{
	pid_t ppid;
	pid_t pid;
	pid_t pgrp;
	pid_t session;
	int tty_nr;
};

struct ProcessEvent *procEvent;
struct plist* shellList;

int TtyStatParse(pid_t pid, struct ProcStat *procStat);
char *TtyGetName(pid_t pid);
extern void procMon();
void FormatOutput(struct ProcessEvent *procEvent);
void GetProcessEvent(pid_t pid,struct ProcessEvent *procEvent);
char *GetProcessCmdline(pid_t pid);
char * GetPnameFromPid(pid_t pid);