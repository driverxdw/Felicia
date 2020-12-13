demo:felicia_plugin_reverse_shell.c felicia_main.c felicia_data_struct.c felicia_process_monitor.c felicia_process_handler.c \
felicia_init.c felicia_plugin_web_rce.c cJSON.c
	gcc felicia_plugin_reverse_shell.c felicia_main.c felicia_data_struct.c felicia_process_monitor.c felicia_process_handler.c \
	felicia_init.c felicia_plugin_web_rce.c cJSON.c -o demo

test:test.c cJSON.c
	gcc test.c cJSON.c -o test
