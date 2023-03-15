# CTF Toolkit

## How-To
- run ctf_tool.py -f /absolute/path.pcap
- answer the question on what you are looking for (udp, http, user agent, icmp, dns)

## Tools to Use
- Kali (OS) (https://www.kali.org/)
- Parrot (OS) (https://www.parrotsec.org/download/)
- Ghidra (Debugging program) (https://ghidra-sre.org/)
- Volatilty3 (inspect ram) (git clone https://github.com/volatilityfoundation/volatility3.git)
- steghide (extract hidden attachments in photos) (sudo apt install steghide)
- gdb (program debugger) (sudo apt-get install gdb)
- pwntools (ctf toolkit) (pip install pwntools)
- hexedit (website to modify files) (https://hexed.it/?hl=en)
- OSINT Framework (OSINT tool) (https://osintframework.com/)

## Volatility Cheat Sheet

### How to detect malicious files ?
./vol.exe -f Triage-Memory.mem — profile=Win7SP1x64 -D <Output_Location> -p <PID >malfind

### What type of dump am I going to analyze ?
$ ./vol.exe -f Triage-Memory.mem imageinfo

### Which process are running
$ ./vol.exe -f Triage-Memory.mem --profile=MyProfile pslist
$ ./vol.exe -f Triage-Memory.mem --profile=MyProfile pstree
$ ./vol.exe -f Triage-Memory.mem --profile=MyProfile psxview

#### List open TCP/UDP connections
$ ./vol.exe -f Triage-Memory.mem --profile=MyProfile connscan
$ ./vol.exe -f Triage-Memory.mem --profile=MyProfile sockets
$ ./vol.exe -f Triage-Memory.mem --profile=MyProfile netscan

#### What commands were lastly run on the computer
$ ./vol.exe -f Triage-Memory.mem --profile=MyProfile cmdline
$ ./vol.exe -f Triage-Memory.mem --profile=MyProfile consoles
$ ./vol.exe -f Triage-Memory.mem --profile=MyProfile cmdscan

#### Dump processes exe and memory 
$ ./vol.exe -f Triage-Memory.mem --profile=MyProfile procdump -p MyPid --dump-dir .
$ ./vol.exe -f Triage-Memory.mem --profile=MyProfile memdump -p MyPid --dump-dir .

#### Hive and Registry key values
$ ./vol.exe -f Triage-Memory.mem --profile=MyProfile hivelist
$ ./vol.exe -f Triage-Memory.mem --profile=MyProfile printkey -K "MyPath"
