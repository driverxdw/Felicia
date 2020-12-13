struct ReverseShellEvent{
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
    char *username;
    char *usergroup;
    char *srcip;
    char *dstip;
    int srcport;
    int dstport;
};

struct PipeInOut{
    char *pipeIn;
    char *pipeOut;
};

struct ReverseShellEvent *rvShellEvt;
void ReverseShellCheckPlugin(struct ProcessEvent *procEvent);
int ReverseShellCheck_2(struct ProcessEvent *procEvent);
int ReverseShellCheck_3();
void GetInode_2(int inode);
int GetInode(char *pidFdPath);