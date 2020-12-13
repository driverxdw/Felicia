#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "felicia_process_monitor.h"
#include "felicia_process_handler.h"
#include "felicia_data_struct.h"

#define _LINUX_TIME_H

struct ProcessEvent *procEvent;
struct plist* shellList;

/*
 * connect to netlink
 * returns netlink socket, or -1 on error
 */

static int nl_connect()
{
    int rc;
    int nl_sock;
    struct sockaddr_nl sa_nl;

    nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_sock == -1) {
        perror("socket");
        return -1;
    }

    sa_nl.nl_family = AF_NETLINK;
    sa_nl.nl_groups = CN_IDX_PROC;
    sa_nl.nl_pid = getpid();

    rc = bind(nl_sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl));
    if (rc == -1) {
        perror("bind");
        close(nl_sock);
        return -1;
    }

    return nl_sock;
}

/*
 * subscribe on proc events (process notifications)
 */

static int set_proc_ev_listen(int nl_sock, bool enable)
{
    int rc;
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__)) {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
    } nlcn_msg;

    memset(&nlcn_msg, 0, sizeof(nlcn_msg));
    nlcn_msg.nl_hdr.nlmsg_len = sizeof(nlcn_msg);
    nlcn_msg.nl_hdr.nlmsg_pid = getpid();
    nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;

    nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;
    nlcn_msg.cn_msg.id.val = CN_VAL_PROC;
    nlcn_msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

    nlcn_msg.cn_mcast = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE;

    rc = send(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);
    if (rc == -1) {
        perror("netlink send");
        return -1;
    }
    return 0;
}

void GetProcessCwd(struct ProcessEvent *p){
	static char buf[PATH_MAX_1],proc_path[50];
	sprintf(proc_path,"/proc/%d/cwd",p->pid);
	int rslt = readlink(proc_path,buf,PATH_MAX_1);
	if ( rslt < 0 || rslt >= PATH_MAX_1 ) {
  		return ;
	}
	buf[rslt] = '\x00';
	// printf("cwd:%s\n",buf);
    p->cwd = strdup(buf);
}

void GetProcessSocket(struct ProcessEvent *p){
	pid_t pid = p->pid;
	static char stdin_socket_path[32]="",stdout_socket_path[32]="",stdin_socket[1024],stdout_socket[1024];
	memset(stdin_socket,0,sizeof(stdin_socket));
	memset(stdout_socket,0,sizeof(stdout_socket));
	sprintf(stdin_socket_path,"/proc/%d/fd/0",pid);
	sprintf(stdout_socket_path,"/proc/%d/fd/1",pid);
	p->stdout = strdup("");
	p->stdin = strdup("");
	int rslt1 = readlink(stdin_socket_path,stdin_socket,PATH_MAX_1);
	if ( rslt1 < 0 || rslt1 >= PATH_MAX_1 ) {
		// printf("readlink:%d\n",rslt1);
		// printf("open error!\n");
  		return;
	}
	int rslt2 = readlink(stdout_socket_path,stdout_socket,PATH_MAX_1);
	if ( rslt2 < 0 || rslt2 >= PATH_MAX_1 ) {
		// printf("open error2\n");
  		return;
	} 
	p->stdin = strdup(stdin_socket);
	p->stdout = strdup(stdout_socket);
}

char *GetProcessCmdline(pid_t pid){
	FILE *fp;
	int str_len,i = 0;
	static char proc_path[128],buf[128];
	sprintf(proc_path,"/proc/%d/cmdline",pid);
	// printf("%s\n",proc_path);
	fp = fopen(proc_path,"r");
	if(fp == NULL){
		// perror("open error");
		return "";
	}
	str_len = fread(buf,1,sizeof(buf),fp);
	while(i < str_len-1) {
		if(buf[i] == 0) {
			buf[i] = ' ';
		}
		i++;
	}
	fclose(fp);
	return buf;
}

char *GetProcessExe(pid_t pid){
	static char buf[PATH_MAX_1],proc_path[50];
	sprintf(proc_path,"/proc/%d/exe",pid);
	int rslt = readlink(proc_path,buf,PATH_MAX_1);
	if ( rslt < 0 || rslt >= PATH_MAX_1 ) {
		return "";
	}
	buf[rslt] = '\x00';
	return buf;	
}
char *TtyGetName(int pid){
	int retval;
	int i;
	char *name = NULL;
	char path[MAX_PATH_LEN + 1];
	char scratch[MAX_PATH_LEN + 1];
	DIR *dev_dir = NULL;
	struct dirent *dir_entry;
	struct stat dev_info;
	struct ProcStat procStat;
	if((retval = TtyStatParse(pid, &procStat)) == -1){
#ifdef DEBUG
		fprintf(stderr, "%s: ctty_get_name(): ctty_stat_parse(%d, %lx): %s\n", program_invocation_short_name, \
				pid, (unsigned long) &stat_info, \
				strerror(errno));
#endif
		goto CLEAN_UP;
	}
    if(procStat.tty_nr == 0){
        // return "";
        goto CLEAN_UP;
    }
	for(i = 0; i < 2; i++){
		memset(path, 0, sizeof(path));
		if(snprintf(path, sizeof(path), "/dev/") < 0){
			return(NULL);
		}
		if(i){
			if(snprintf(path + 5, sizeof(path) - 5, "pts/") < 0){
				return(NULL);
			}
		}
		if(!(dev_dir = opendir(path))){
#ifdef DEBUG
			fprintf(stderr, "%s: ctty_get_name(): opendir(%s): %s\n", program_invocation_short_name, \
					path, \
					strerror(errno));
#endif
			return(NULL);
		}
		while((dir_entry = readdir(dev_dir))){

			if(!i){
				if(strncmp(dir_entry->d_name, "tty", 3)){
					continue;
				}
			}
			memset(scratch, 0, sizeof(scratch));
			if(snprintf(scratch, sizeof(scratch), "%s%s", path, dir_entry->d_name) < 0){
				goto CLEAN_UP;
			}
			if(stat(scratch, &dev_info)){
#ifdef DEBUG
				fprintf(stderr, "%s: ctty_get_name(): stat(%s, %lx): %s\n", program_invocation_short_name, \
						scratch, (unsigned long) &dev_info, \
						strerror(errno));
#endif
				goto CLEAN_UP;
			}
			if(procStat.tty_nr == (int) dev_info.st_rdev){
				if((name = (char *) malloc(strlen(scratch) + 1)) == NULL){
#ifdef DEBUG
					fprintf(stderr, "%s: ctty_get_name(): malloc(%d): %s\n", program_invocation_short_name, \
							(int) strlen(scratch) + 1, \
							strerror(errno));
#endif
					goto CLEAN_UP;
				}
				memset(name, 0, strlen(scratch) + 1);
				strncpy(name, scratch, strlen(scratch));
				goto CLEAN_UP;
			}
		}
		closedir(dev_dir);
	}
CLEAN_UP:
	closedir(dev_dir);
    if(!name)
        return "";
	return name;
}

int TtyStatParse(int pid, struct ProcStat *procStat){
	int stat_fd;

	char scratch[BUFF_LEN];
	char *parse_ptr;

	memset(scratch, 0, BUFF_LEN);
	snprintf(scratch, BUFF_LEN, "/proc/%d/stat", pid);
	if((stat_fd = open(scratch, O_RDONLY)) == -1){
#ifdef DEBUG
		fprintf(stderr, "%s: ctty_stat_parse(): open(%s, %d): %s\n", program_invocation_short_name, \
				scratch, O_RDONLY, \
				strerror(errno));
#endif
		return(-1);
	}

	if((read(stat_fd, scratch, sizeof(scratch))) < 1){
#ifdef DEBUG
		fprintf(stderr, "%s: ctty_stat_parse(): read(%d, %lx, %d): %s\n", program_invocation_short_name, \
				stat_fd, (unsigned long) scratch, (int) sizeof(scratch), \
				strerror(errno));
#endif
		return(-1);
	}
	close(stat_fd);

	procStat->pid = strtol(scratch, NULL, 10);

	if((parse_ptr = strrchr(scratch, ')')) == NULL){
#ifdef DEBUG
		fprintf(stderr, "%s: ctty_stat_parse(): strrchr(%lx, %d): %s\n", program_invocation_short_name, \
				(unsigned long) scratch, ')', \
				strerror(errno));
#endif
		return(-1);
	}

	/* ppid starts 4 chars after the final ')'. */
	parse_ptr += 4;
	procStat->ppid = strtol(parse_ptr, &parse_ptr, 10);
	procStat->pgrp = strtol(parse_ptr, &parse_ptr, 10);
	procStat->session = strtol(parse_ptr, &parse_ptr, 10);
	procStat->tty_nr = strtol(parse_ptr, NULL, 10);
	return(0);
}

void GetProcessStatus(struct ProcessEvent *p){
	pid_t pid = p->pid,ppid;
	FILE *fp;
	char file_str[2048],pname[1024],tty_name[MAX_PATH_LEN];
	static char proc_path[50];
	uid_t uid;
	gid_t tgid,pgid;
	int sid;
	sprintf(proc_path,"/proc/%d/status",pid);
	fp = fopen(proc_path,"r");
	memset(file_str,0,sizeof(file_str));
	memset(pname,0,sizeof(pname));
    p->cmdline = strdup(GetProcessCmdline(p->pid));
    p->path = strdup(GetProcessExe(p->pid));
	if(fp == NULL){
		p->pname = strdup("");
		return;
	}
	while(fgets(file_str,sizeof(file_str),fp))
    {	
		// memset(file_str,0,sizeof(file_str));
		// memset(pname,0,sizeof(pname));
        if(strstr(file_str,"Uid")) 
        {   
            sscanf(file_str,"Uid:%d",&uid);
			p->uid = uid;
        }
		else if(strstr(file_str,"PPid")){
			sscanf(file_str,"PPid:%d",&ppid);
			p->ppid = ppid;
            p->pcmdline = strdup(GetProcessCmdline(p->ppid));
            p->ppath = strdup(GetProcessExe(p->ppid));
		}
		else if(strstr(file_str,"Name"))
		{
			sscanf(file_str, "Name:%s", pname);
			p->pname = strdup(pname);
		}
		else if(strstr(file_str,"Tgid"))
		{
			sscanf(file_str,"Tgid:%d",&tgid);
			p->tgid = tgid;
		}
		else if(strstr(file_str,"NSpgid"))
		{
			sscanf(file_str,"NSpgid:%d",&pgid);
			p->pgid = pgid;
		}
		else if(strstr(file_str,"NSsid"))
		{
			sscanf(file_str,"NSsid:%d",&sid);
			p->sid = sid;
		}
    }
    strcpy(tty_name,TtyGetName(p->pid));
    if(strcmp(tty_name,"")==0){
        p->tty = strdup(" ");
    }
    else p->tty = strdup(tty_name);
    fclose(fp);
}

char *GetPnameFromPid(pid_t pid){
	static char file_str[2048],pname[1024];
	FILE *fp;
	static char proc_path[50];
	sprintf(proc_path,"/proc/%d/status",pid);
	fp = fopen(proc_path,"r");
	memset(file_str,0,sizeof(file_str));
	memset(pname,0,sizeof(pname));
	if(fp == NULL){
		return "";
	}
	while(fgets(file_str,sizeof(file_str),fp)){
		if(strstr(file_str,"Name")){
			sscanf(file_str, "Name:%s", pname);
			return pname;
		}
	}
	return "";
    fclose(fp);
}

void FormatOutput(struct ProcessEvent *procEvent){
	printf("\nprocess event\n{\
    \n  'evt':'%s'\
    \n  'pid':'%d'\
    \n  'exe':'%s'\
    \n  'cmdline':'%s'\
    \n  'cwd':'%s'\
    \n  'ppid':'%d'\
    \n  'pexe':'%s'\
    \n  'pcmdline':'%s'\
    \n  'uid':'%d'\
    \n  'tgid':'%d'\
    \n  'pgid':'%d'\
    \n  'sid':'%d'\
    \n  'pname':'%s'\
    \n  'stdin':'%s'\
    \n  'stdout':'%s'\
    \n  'tty':'%s'\
    \n  'unixtime':'%ld'\n}\
    \n",\
	procEvent->evt,procEvent->pid,procEvent->path,\
	procEvent->cmdline,procEvent->cwd,procEvent->ppid,procEvent->ppath,\
	procEvent->pcmdline,procEvent->uid,procEvent->tgid,procEvent->pgid,procEvent->sid,
    procEvent->pname,procEvent->stdin,procEvent->stdout,procEvent->tty,procEvent->unixTime);
}

void GetEtcShells(struct plist* shellList){
    FILE *fp;
    char buf[BUFSIZ];
    fp = fopen("/etc/shells","r");
    if(fp == NULL){
        return;
    }
    fgets(buf, BUFSIZ, fp);
	while (fgets(buf, BUFSIZ, fp)){
        if(buf[0] != '/'){
            continue;
        }
        buf[strlen(buf)-1] = '\x00';
        ListAppend(shellList,buf);
    }
}


void GetProcessEvent(pid_t pid,struct ProcessEvent *procEvent){
    procEvent->pid = pid;
    procEvent->evt = strdup("process");
    GetProcessStatus(procEvent);
    GetProcessSocket(procEvent);
    GetProcessCwd(procEvent);
}

/*
 * handle a single process event
 */
static volatile bool need_exit = false;
static int handle_proc_ev(int nl_sock)
{
    int rc;
    int pid;
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__)) {
            struct cn_msg cn_msg;
            struct proc_event proc_ev;
        };
    } nlcn_msg;
    procEvent = (struct ProcessEvent *)malloc(sizeof(struct ProcessEvent));
    shellList = (struct plist*)malloc(sizeof(struct plist));
    GetEtcShells(shellList);
    while (!need_exit) {
        rc = recv(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);
        if (rc == 0) {
            /* shutdown? */
            return 0;
        } else if (rc == -1) {
            if (errno == EINTR) continue;
            perror("netlink recv");
            return -1;
        }
        switch (nlcn_msg.proc_ev.what) {
            case PROC_EVENT_NONE:
                // printf("set mcast listen ok\n");
                break;
            case PROC_EVENT_FORK:
                break;
            case PROC_EVENT_EXEC:
                // printf("exec: tid=%d pid=%d\n",
                //         nlcn_msg.proc_ev.event_data.exec.process_pid,
                //         nlcn_msg.proc_ev.event_data.exec.process_tgid);
                // pid = nlcn_msg.proc_ev.event_data.exec.process_tgid;
                GetProcessEvent(nlcn_msg.proc_ev.event_data.exec.process_tgid,procEvent);
				ProcessController(procEvent);
                break;
            case PROC_EVENT_UID:
                break;
            case PROC_EVENT_GID:
                break;
            case PROC_EVENT_EXIT:
                break;
            default:
                break;
        }
    }
    return 0;
}

static void on_sigint(int unused)
{
    need_exit = true;
}


void procMon(){
    int nl_sock;
    int rc = EXIT_SUCCESS;

    signal(SIGINT, &on_sigint);
    siginterrupt(SIGINT, true);
    nl_sock = nl_connect();
    if (nl_sock == -1)
        exit(EXIT_FAILURE);

    rc = set_proc_ev_listen(nl_sock, true);
    if (rc == -1) {
        rc = EXIT_FAILURE;
        goto out;
    }
    rc = handle_proc_ev(nl_sock);
    if (rc == -1) {
        rc = EXIT_FAILURE;
        goto out;
    }

	set_proc_ev_listen(nl_sock, false);

out:
    close(nl_sock);
    exit(rc); 
}
