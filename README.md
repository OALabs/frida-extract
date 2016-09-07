# FridaExtract
FridaExtract is a [Frida.re](http://www.frida.re/) based [RunPE](http://www.adlice.com/runpe-hide-code-behind-legit-process/) extraction tool. RunPE type injection is a common technique used by malware to hide code within another process. It also happens to be the final stage in a lot of packers : )

NOTE: Frida now also supports extraction of injected PE files using the "MapViewOfSection" technique best [described here](http://blog.w4kfu.com/tag/duqu).

Using FridaExtract you can automatically extract and reconstruct a PE file that has been injected using the RunPE method... and bypass these packers! 

## Why Frida?
There are tons of great tools that already extract RunPE injected code, FridaExtract is **not** better than these. But it is easier to install, easier to build (lol), easier to run, and easier to hack. No compilers, no build environments, just a simple "pip install" and you're up and running.

The code is specifically commented and organized to act as a template for you to build your own Frida projects. This is more of a proof of concept that demonstrates how to setup hooks in a Windows environment. Please copy-paste-hack this any way you like!  

## Getting Started 

**Warning:** FridaExtract only works under Windows 32bit. There are currently some mystery bugs with wow64 so we recommend sticking to Windows7 32bit or Windows Server 2008 32bit.

* First start a VM (see warning above) if you are going to be unpacking malware.
* Install [Python 2.7](https://www.python.org/downloads/)
* Remember to [set your python and pip paths](http://docs.python-guide.org/en/latest/starting/install/win/) ; )
* Install Frida by typing `pip install frida` in cmd
* Clone this repository and you are ready to extract!

## Extracting PE Files

FridaExtract is only able to extract RunPE injected PE files so it is fairly limited. If you are using a VM that is easy to snapshot-run-revert then you can just try FridaExtract blindly on every malware sample and see what comes out but we don't recommend it. Instead, FridaExtract is good compliment to a sandbox (we <3 [malwr](https://malwr.com/)). First run the sample in a sandbox and note the API calls.

For RunPE technique if you see the following API calls then FridaExtract may be the tool for you:
* CreateProcess
* WriteVirtualMemory (to remote process)
* ResumeThread (in remote process)

For the MapViewOfSection technique if you see the following API calls then FridaExtract may be the tool for you:
* CreateProcess
* NtCreateSection
* NtUnmapViewOfSection (remote process)
* NtMapViewOfSection (remote process)


### Examples
By default FridaExtract will attempt to automatically extract the injected PE file, reconstruct it, and dump it to a file called `dump.bin`. 
```
python FridaExtract.py bad.exe
```

#### Dump To File
A dump file can be specified using the `--out_file` command.  
```
python FridaExtract.py bad.exe --out_file extracted.exe
```

#### Pass Arguments
If the packed PE file you are attempting to extract requires arguments you can pass them using the `--args` command. Multiple arguments can be passed as comma separated.
```
python FridaExtract.py bad.exe --args password
```

#### Dump Raw
FridaExtract will automatically attempt to reconstruct the dumped memory into a PE file. If this isn't working and you just want a raw dump of all memory written to the subprocess you can use the `--raw` command. Instead of writing the reconstructed PE to the dump file the raw memory segments will be written in order of address. 
```
python FridaExtract.py bad.exe --raw
```

#### Verbose
FridaExtract uses hooks on the following APIs to extract the injected PE file:
* ExitProcess
* NtWriteVirtualMemory
* NtCreateThread
* NtResumeThread
* NtDelayExecution
* CreateProcessInternalW
* NtMapViewOfSection
* NtUnmapViewOfSection
* NtCreateSection

To trace these APIs and print the results use the `-v` or `--verbose` command.
```
python FridaExtract.py bad.exe --verbose
```

## Caveats 

Frida uses userland hooks that can easily be bypassed. If you need a more robust DBI tool try PIN! A great example of using PIN to extract RunPE is provided by [here](http://jbremer.org/malware-unpacking-level-pintool/).

Frida injects a javascript runtime into the process you are analyzing, it is **not** stealthy. For a decent overview of how Frida may be detected by malware [check this out](https://crackinglandia.wordpress.com/2015/11/10/anti-instrumentation-techniques-i-know-youre-there-frida/).


## Acknowledgments

* Huge thanks to @oleavr for helping me with my endless questions about Frida
* Hat tip to @skier_t for his awesome PE rebuilding script and so much more!

## Feedback / Help
* Any questions, comments, requests hit us up on twitter: @herrcore or @seanmw
* Anything Frida specific find us lurking on IRC:  #frida at irc.freenode.net
* Pull requests welcome!
