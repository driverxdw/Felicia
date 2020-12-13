#include "felicia_process_monitor.h"
#include "felicia_plugin_reverse_shell.h"
#include "felicia_plugin_web_rce.h"

void ProcessController(struct ProcessEvent *procEvent){
    ReverseShellCheckPlugin(procEvent);
    WebRceCheckPlugin(procEvent);
    // RootkitCheckPlugin();
}