struct WebRceEvent{
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
};
struct WebRceEvent *webRceEvt;

void WebRceCheckPlugin(struct ProcessEvent *procEvent);