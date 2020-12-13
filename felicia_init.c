#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"

cJSON *revShellJson;
cJSON *webRceJson;

void reverseShellRuleInit(){
    FILE *fp;
    char reverseShellRule[1024];
    fp = fopen("rule/reverse_shell_rule.json","r");
    if(fp == NULL){
        printf("rule init error !!!\n");
        return;
    }
    fread(reverseShellRule,1,sizeof(reverseShellRule),fp);
    fclose(fp);
    // printf("the rule json is :%s\n",reverseShellRule);

    revShellJson = cJSON_Parse(reverseShellRule);
    // char *json_data = NULL;
    // printf("data:%s\n",json_data = cJSON_Print(revShellJson));
    // free(json_data);
    return;
}

void webRceRuleInit(){
    FILE *fp;
    char webRceRule[1024];
    fp = fopen("rule/web_rce_rule.json","r");
    if(fp == NULL){
        printf("rule init error !!!\n");
        return;
    }
    fread(webRceRule,1,sizeof(webRceRule),fp);
    fclose(fp);
    // printf("the rule json is :%s\n",reverseShellRule);

    webRceJson = cJSON_Parse(webRceRule);
    return;    
}



void ruleInit(){
    reverseShellRuleInit();
    webRceRuleInit();
}



void init(){
    ruleInit();
}