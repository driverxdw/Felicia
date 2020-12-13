#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include "cJSON.h"
#include "felicia_process_monitor.h"
#include "felicia_init.h"
#include "felicia_plugin_web_rce.h"

struct WebRceEvent *webRceEvt;

static void GetWebRceEvent(struct ProcessEvent *procEvent){
    webRceEvt->pid = procEvent->pid;
    webRceEvt->ppid = procEvent->ppid;
    // rvShellEvt->ppname = strdup(procEvent->ppname);
    webRceEvt->pname = strdup(procEvent->pname);
    webRceEvt->stdin = strdup(procEvent->stdin);
    webRceEvt->stdout = strdup(procEvent->stdout);
    webRceEvt->uid = procEvent->uid;
    webRceEvt->unixTime = procEvent->unixTime;
    webRceEvt->cmdline = strdup(procEvent->cmdline);
    webRceEvt->cwd = strdup(procEvent->cwd);
    webRceEvt->evt = strdup("webrce");
    webRceEvt->path = strdup(procEvent->path);
    webRceEvt->ppath = strdup(procEvent->ppath);
    webRceEvt->pcmdline = strdup(procEvent->pcmdline);
    webRceEvt->tty = strdup(procEvent->tty);
}

static void WebRceEvtOutput(struct WebRceEvent *webRceEvt){
	printf("\nweb rce event\n{\
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
    \n  'tty':'%s'\
    \n  'unixtime':'%ld'\n}\
    \n",\
	webRceEvt->evt,webRceEvt->pid,webRceEvt->path,\
	webRceEvt->cmdline,webRceEvt->cwd,webRceEvt->ppid,webRceEvt->ppath,\
	webRceEvt->pcmdline,webRceEvt->uid,webRceEvt->pname,webRceEvt->stdin,\
    webRceEvt->stdout,webRceEvt->tty,webRceEvt->unixTime);
}

int webRceRuleRegex(struct ProcessEvent *procEvent){
    char *pcmdline,*ppname;
    regex_t compiled_1,compiled_2;
    int err,status_1 = 0,status_2 = 0;
    char errbuf[1024];
    const char *pattern_1, *pattern_2,*contain;
    cJSON *test_arr = cJSON_GetObjectItem(webRceJson,"web_rce_rule");
    int arr_size = cJSON_GetArraySize(test_arr);
    cJSON *arr_item = test_arr->child;
    char ppidPath[MAX_PATH_LEN];
    for(int i = 0; i <= arr_size-1; i++){
        // pattern = cJSON_Print(cJSON_GetObjectItem(arr_item,"regex"));
        pattern_1 = cJSON_GetObjectItem(arr_item,"ppname")->valuestring;
        pattern_2 = cJSON_GetObjectItem(arr_item,"pname")->valuestring;
        contain = cJSON_GetObjectItem(arr_item,"contain")->valuestring;
        arr_item = arr_item->next;
        if((err = regcomp(&compiled_1,pattern_1,REG_EXTENDED|REG_ICASE|REG_NEWLINE)) != 0){
            regerror(err,&compiled_1,errbuf,sizeof(errbuf));
            printf("err:%s\n",errbuf);
            // return -1;
        }
        size_t nmatch = 12;
        regmatch_t pmatch[nmatch];
        ppname = strdup(GetPnameFromPid(procEvent->ppid));
        err = regexec(&compiled_1,ppname,nmatch,pmatch,0);
        if(err != 0)
        {
            // printf("regexr not fit !!!\n");
            continue;
        }
        else{
            if(strcmp(pattern_2,"")==0){
                status_1 = 1;
            }
            else{
                if((err = regcomp(&compiled_2,pattern_2,REG_EXTENDED|REG_ICASE|REG_NEWLINE)) != 0){
                    regerror(err,&compiled_2,errbuf,sizeof(errbuf));
                    printf("err:%s\n",errbuf);
                    return -1;
                }
                err = regexec(&compiled_2,procEvent->pname,nmatch,pmatch,0);
                if(err != 0){
                    // printf("regexr not fit !!!!\n");
                    continue;
                }
                else{
                    status_1 = 1;
                }
            }
        }
        if(status_1 == 1){
            pcmdline = strdup(GetProcessCmdline(procEvent->ppid));
            if(strcmp(contain,"")==0){
                status_2 = 1;
            }
            else if(strstr(pcmdline,contain)!=NULL){
                status_2 = 1;
            }
        }
        if(status_2 == 1){
            return 1;
        }
    }
    return -1;
}


void WebRceCheckPlugin(struct ProcessEvent *procEvent){
    webRceEvt = (struct WebRceEvent *)malloc(sizeof(struct WebRceEvent));
    int ret = -1;
    ret = webRceRuleRegex(procEvent);
    if(ret != -1){
        GetWebRceEvent(procEvent);
        WebRceEvtOutput(webRceEvt);
    }
    return;
}