#include <stdio.h>
#include <string.h>
#include "felicia_process_monitor.h"
#include "felicia_data_struct.h"
#include "felicia_plugin_reverse_shell.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <regex.h>
#include "cJSON.h"
#include "felicia_init.h"

struct ReverseShellEvent *rvShellEvt;

static void GetReverseShellEvent(char *lip,char *rip,int lport,int rport){
    rvShellEvt->srcip = strdup(lip);
    rvShellEvt->srcport = lport;
    rvShellEvt->dstip = strdup(rip);
    rvShellEvt->dstport = rport;
    rvShellEvt->pid = procEvent->pid;
    rvShellEvt->ppid = procEvent->ppid;
    // rvShellEvt->ppname = strdup(procEvent->ppname);
    rvShellEvt->pname = strdup(procEvent->pname);
    rvShellEvt->stdin = strdup(procEvent->stdin);
    rvShellEvt->stdout = strdup(procEvent->stdout);
    rvShellEvt->uid = procEvent->uid;
    rvShellEvt->unixTime = procEvent->unixTime;
    rvShellEvt->cmdline = strdup(procEvent->cmdline);
    rvShellEvt->cwd = strdup(procEvent->cwd);
    rvShellEvt->evt = strdup("rvshell");
    rvShellEvt->path = strdup(procEvent->path);
    rvShellEvt->ppath = strdup(procEvent->ppath);
    rvShellEvt->pcmdline = strdup(procEvent->pcmdline);
    rvShellEvt->tty = strdup(procEvent->tty);
}

static void RvShellEvtOutput(struct ReverseShellEvent *rvShellEvt){
	printf("\nreverse shell event\n{\
    \n  'evt':'%s'\
    \n  'pid':'%d'\
    \n  'exe':'%s'\
    \n  'cmdline':'%s'\
    \n  'cwd':'%s'\
    \n  'ppid':'%d'\
    \n  'pexe':'%s'\
    \n  'pcmdline':'%s'\
    \n  'uid':'%d'\
    \n  'pname':'%s'\
    \n  'stdin':'%s'\
    \n  'stdout':'%s'\
    \n  'srcip':'%s'\
    \n  'dstip':'%s'\
    \n  'srcport':'%d'\
    \n  'dstport':'%d'\
    \n  'tty':'%s'\
    \n  'unixtime':'%ld'\n}\
    \n",\
	rvShellEvt->evt,rvShellEvt->pid,rvShellEvt->path,\
	rvShellEvt->cmdline,rvShellEvt->cwd,rvShellEvt->ppid,rvShellEvt->ppath,\
	rvShellEvt->pcmdline,rvShellEvt->uid,rvShellEvt->pname,rvShellEvt->stdin,\
    rvShellEvt->stdout,rvShellEvt->srcip,rvShellEvt->dstip,rvShellEvt->srcport,\
    rvShellEvt->dstport,rvShellEvt->tty,rvShellEvt->unixTime);
}

static void Addr2Str(int af, const void *addr, unsigned port, char *buf)
{
    if (inet_ntop(af, addr, buf, ADDR_LEN) == NULL) {
        *buf = '\0';
        return;
    }
}

static int SocketJudge(struct ProcessEvent *procEvent){
	int inode = -1;
    if(strstr(procEvent->stdin,"socket:[")){
		sscanf(procEvent->stdin,"socket:[%d]",&inode);
        return inode;
	}
	else if(strstr(procEvent->stdout,"socket:["))
	{
		sscanf(procEvent->stdout,"socket:[%d]",&inode);
        return inode;
	}
    return inode;
}

static int SocketJudge_2(char *fd){
	int inode = -1;
    if(strstr(fd,"socket:[")){
		sscanf(fd,"socket:[%d]",&inode);
        return inode;
	}
    return inode;
}

struct PipeInOut *PipeJudege(struct ProcessEvent *procEvent){
    char *pipe_stdin,*pipe_stdout;
    struct PipeInOut *pipeio = (struct PipeInOut *)malloc(sizeof(struct PipeInOut));
    if(strstr(procEvent->stdin,"pipe:[")){
        pipeio->pipeIn = strdup(procEvent->stdin);
    }
    else pipeio->pipeIn = strdup("");
    if(strstr(procEvent->stdout,"pipe:[")){
        pipeio->pipeOut = strdup(procEvent->stdout);
    }
    else pipeio->pipeOut = strdup("");
    return pipeio;
}

int MatchSocketInfo(char *filename,long m_inode){
	long inode;
	FILE *fp = fopen(filename, "r");
	if (fp == NULL) return -1;
	char buf[BUFSIZ];
	fgets(buf, BUFSIZ, fp);
	while (fgets(buf, BUFSIZ, fp)){
		char lip[ADDR_LEN];
        char rip[ADDR_LEN];
		char more[512];
		iaddr laddr, raddr;
		unsigned lport, rport, state, txq, rxq, num, tr, tm_when, retrnsmt, uid;
		int timeout;
		sscanf(buf, " %d: %x:%x %x:%x %x %x:%x %x:%x %x %d %d %ld %512s",
			&num, &laddr.u, &lport, &raddr.u, &rport,
			&state, &txq, &rxq, &tr, &tm_when, &retrnsmt, &uid, &timeout, &inode, more);
		if(inode == m_inode){
			Addr2Str(AF_INET, &laddr, lport, lip);
            Addr2Str(AF_INET, &raddr, rport, rip);
            GetReverseShellEvent(lip,rip,lport,rport);
			return 0;
		}
	}
	fclose(fp);
	return -1;
}

int ReverseShellCheck_1(struct ProcessEvent *procEvent){
    int inode = -1;
    struct ProcessEvent *rvsProcEvt = (struct ProcessEvent *)malloc(sizeof(struct ProcessEvent));
    if((inode = SocketJudge(procEvent)) == -1){
        return inode;
    }
    if(strcmp(procEvent->tty," ") == 0){
        return -2;
    }
    GetInode_2(inode);
    return inode;
}

int PipeCmp(char *pidFdPath,struct PipeInOut *curPipeIo){
    DIR *d = opendir(pidFdPath);
    char fdName[MAX_BUFF_SIZE],fdPath[MAX_BUFF_SIZE];
    struct dirent *direproc, *direfd;
    int status = 0,inode;
    if(d == NULL) return -1;
    sleep(1);
    while(direfd = readdir(d)){
        if(strstr(direfd->d_name,".")) continue;
        memset(fdName,0,sizeof(fdName));
        sprintf(fdPath,"%s/%s",pidFdPath,direfd->d_name);
        readlink(fdPath,fdName,sizeof(fdName));
        if(strcmp(fdName,curPipeIo->pipeIn)==0 || strcmp(fdName,curPipeIo->pipeOut)==0){
            status = 1;
        }
        if(status == 1 && strstr(fdName,"socket:[")){
            inode = SocketJudge_2(fdName);
            return inode;
        }
    }
    closedir(d);
    return -1;
}

int ReverseShellCheck_2(struct ProcessEvent *procEvent){
    int inode = -1;
    char pidUpFdPath[MAX_PATH_LEN],pidDownFdPath[MAX_PATH_LEN];
    struct PipeInOut *curPipeIo = (struct PipeInOut *)malloc(sizeof(struct PipeInOut));
    curPipeIo = PipeJudege(procEvent);
    for(int i = 1; i <= 2 ; i++){
        sprintf(pidDownFdPath,"/proc/%d/fd",procEvent->pid-i);
        if((inode = PipeCmp(pidDownFdPath,curPipeIo)) != -1){
            GetInode_2(inode);
            return inode;
        };
    }
    for(int i = 1; i <= 2 ; i++){
        sprintf(pidUpFdPath,"/proc/%d/fd",procEvent->pid+i);
        if((inode = PipeCmp(pidUpFdPath,curPipeIo)) != -1){
            GetInode_2(inode);
            return inode;
        };
    }
    if(strcmp(curPipeIo->pipeIn,"")==0 && strcmp(curPipeIo->pipeOut,"")==0){
        return -1;
    }
    return -2;
}

int GetInode(char *pidFdPath){
    DIR *d = opendir(pidFdPath);
    char fdName[MAX_BUFF_SIZE],fdPath[MAX_BUFF_SIZE];
    struct dirent *direproc, *direfd;
    int status = 0,inode;
    if(d == NULL) return -1;
    // sleep(1);
    while(direfd = readdir(d)){
        if(strstr(direfd->d_name,".")) continue;
        memset(fdName,0,sizeof(fdName));
        sprintf(fdPath,"%s/%s",pidFdPath,direfd->d_name);
        readlink(fdPath,fdName,sizeof(fdName));
        if(strstr(fdName,"socket:[")){
            inode = SocketJudge_2(fdName);
            char *filename_tcp = strdup("/proc/net/tcp");
            char *filename_udp = strdup("/proc/net/udp");
            if(MatchSocketInfo(filename_tcp,inode) != -1){
                // RvShellEvtOutput(rvShellEvt);
                return inode;
            }
            else if(MatchSocketInfo(filename_udp,inode) != -1){
                // RvShellEvtOutput(rvShellEvt);
                return inode;
            }
        }
    }
    closedir(d);
    return -1;
}
void GetInode_2(int inode){
    char *filename_tcp,*filename_udp,*socket;
    filename_tcp = strdup("/proc/net/tcp");
    filename_udp = strdup("/proc/net/udp");
    if(MatchSocketInfo(filename_tcp,inode) != -1){
        // RvShellEvtOutput(rvShellEvt);
        return;
    }
    else if(MatchSocketInfo(filename_udp,inode) != -1){
        // RvShellEvtOutput(rvShellEvt);
        return;
    }
    else{
        return;
    }
}

int ReverseShellCheck_3(struct ProcessEvent *procEvent){
    // printf("the rule is:%s\n",cJSON_Print(revShellJson));
    char pidFdPath[MAX_BUFF_SIZE];
    regex_t compiled;
    int err;
    char errbuf[1024];
    const char *pattern;
    cJSON *test_arr = cJSON_GetObjectItem(revShellJson,"reverse_shell_rule");
    int arr_size = cJSON_GetArraySize(test_arr);
    cJSON *arr_item = test_arr->child;
    char ppidPath[MAX_PATH_LEN];
    int inode = -1;

    for(int i = 0; i <= arr_size-1; i++){
        // pattern = cJSON_Print(cJSON_GetObjectItem(arr_item,"regex"));
        pattern = cJSON_GetObjectItem(arr_item,"regex")->valuestring;
        if((err = regcomp(&compiled,pattern,REG_EXTENDED|REG_ICASE|REG_NEWLINE)) != 0){
            regerror(err,&compiled,errbuf,sizeof(errbuf));
            printf("err:%s\n",errbuf);
            return -1;
        }
        size_t nmatch = 12;
        regmatch_t pmatch[nmatch];
        // err = regexec(&compiled,buf,2,pmatch,0);
        err = regexec(&compiled,procEvent->pcmdline,nmatch,pmatch,0);
        if(err != 0)
        {
            return -1;
        }
        else{
            sprintf(pidFdPath,"/proc/%d/fd",procEvent->ppid);
            inode = GetInode(pidFdPath);
            if(inode != -1)
                return inode;
        }
        arr_item = arr_item->next;
    }
    return -1;
}

void ReverseShellCheckPlugin(struct ProcessEvent *procEvent){
    int inode = -1;
    rvShellEvt = (struct ReverseShellEvent *)malloc(sizeof(struct ReverseShellEvent));
    if(ListIn(shellList,procEvent->path)!=1){
        return;
    }
    inode = ReverseShellCheck_1(procEvent);
    if(inode == -1){
        inode = ReverseShellCheck_2(procEvent);
        if(inode == -1){
            inode = ReverseShellCheck_3(procEvent);
            if(inode == -1){
                return;
            }
        }
        else if(inode == -2){
            return;
        }
    }
    if(inode > 0){
        RvShellEvtOutput(rvShellEvt);
    }
}
