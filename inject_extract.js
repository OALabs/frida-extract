/////////////////////////////////////////////////////////
//
// Use Frida to automatically extract injected PE files 
// (injected via RunPE method)
//
//
// Author: @herrcore
//
/////////////////////////////////////////////////////////

"use strict";


/////////////////////////////////////////////////////////
//
// GLOBAL CONSTANTS
//
/////////////////////////////////////////////////////////
const PAGE_EXECUTE = 0x10;
const PAGE_EXECUTE_READ = 0x20;
const PAGE_EXECUTE_READWRITE = 0x40;
const PAGE_EXECUTE_WRITECOPY = 0x80;
const PAGE_NOACCESS = 0x01;
const PAGE_READONLY = 0x02;
const PAGE_READWRITE = 0x04;
const PAGE_WRITECOPY = 0x08;
const PAGE_TARGETS_INVALID = 0x40000000;
const PAGE_TARGETS_NO_UPDATE = 0x40000000;

const CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
const CREATE_DEFAULT_ERROR_MODE = 0x04000000;
const CREATE_NEW_CONSOLE = 0x00000010;
const CREATE_NEW_PROCESS_GROUP = 0x00000200;
const CREATE_NO_WINDOW = 0x08000000;
const CREATE_PROTECTED_PROCESS = 0x00040000;
const CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000;
const CREATE_SEPARATE_WOW_VDM = 0x00000800;
const CREATE_SHARED_WOW_VDM = 0x00001000;
const CREATE_SUSPENDED = 0x00000004;
const CREATE_UNICODE_ENVIRONMENT = 0x00000400;
const DEBUG_ONLY_THIS_PROCESS = 0x00000002;
const DEBUG_PROCESS = 0x00000001;
const DETACHED_PROCESS = 0x00000008;
const EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
const INHERIT_PARENT_AFFINITY = 0x00010000;


/////////////////////////////////////////////////////////
//
// GLOBAL VARIABLES
//
/////////////////////////////////////////////////////////
var pids = [];
var current_pid = 0;
var DEBUG_FLAG = false;



/////////////////////////////////////////////////////////
//
// COMMS
//
/////////////////////////////////////////////////////////
//syncronous debug log 
function log(msg)
{
    if(DEBUG_FLAG == true){
        send({
            name: '+log',
            payload: msg
        });
        recv('+log-ack', function () {}).wait();
    }  
};


//syncronous dump memory as {"address":<virtual_address>}, data: binary_string
function dump(virtual_address, data)
{
    send({
        name: '+dump',
        address: virtual_address
    }, data);
    recv('+dump-ack', function () {}).wait();        
};


//Wait for flush message 
//Use to hold process open long enough for controller to receive messages
function performFlushBeforeExit() {
    send({
        name: '+flush',
        payload: ''
    });
    recv('+flush-ack', function () {}).wait();
}


//Emergency kill this process
function eKill(e) {
    send({
        name: '+kill',
        payload: e
    });
    recv('+kill-ack', function () {}).wait();
}


//Kill a process by PID
function pKill(pid) {
    send({
        name: '+pkill',
        payload: pid
    });
    recv('+pkill-ack', function () {}).wait();
}



/////////////////////////////////////////////////////////
//
// RPC INTERFACE
//
/////////////////////////////////////////////////////////
rpc.exports = {
    getmoduleranges: function(modulename, protection){
        return Module.enumerateRangesSync(modulename, protection);
    },
    setprotection: function(base, size, protection){
        Memory.protect(ptr(base), size, protection);
    },
    setverbose: function(debug_flag){
        DEBUG_FLAG = debug_flag;
    }
};



/////////////////////////////////////////////////////////
//
// HELPER FUNCTIONS
//
/////////////////////////////////////////////////////////
//Convert int to hex format string
function hexify(num){
    if(num < 0){
        return "-0x" + Math.abs(num).toString(16);
    }
    else{
        return "0x" + num.toString(16);
    }
};


//convert byte array to string
function bin2String(array) {
  var result = "";
  for (var i = 0; i < array.length; i++) {
    result += String.fromCharCode(parseInt(array[i], 2));
  }
  return result;
}


//check memory protection
function getProtectionStr(flag){
    if(flag & PAGE_EXECUTE){
        return "PAGE_EXECUTE"
    }
    else if(flag & PAGE_EXECUTE_READ){
        return "PAGE_EXECUTE_READ";
    }
    else if(flag & PAGE_EXECUTE_READWRITE){
        return "PAGE_EXECUTE_READWRITE";
    }
    else if(flag & PAGE_EXECUTE_WRITECOPY){
        return "PAGE_EXECUTE_WRITECOPY";
    }
    else if(flag & PAGE_NOACCESS){
        return "PAGE_NOACCESS";
    }
    else if(flag & PAGE_READONLY){
        return "PAGE_READONLY";
    }
    else if(flag & PAGE_READWRITE){
        return "PAGE_READWRITE";
    }
    else if(flag & PAGE_WRITECOPY){
        return "PAGE_WRITECOPY";
    }
    else if(flag & PAGE_TARGETS_INVALID){
        return "PAGE_TARGETS_INVALID";
    }
    else if(flag & PAGE_TARGETS_NO_UPDATE){
        return "PAGE_TARGETS_NO_UPDATE";
    }
    else{
        return hexify(flag);
    }
}

//check process create flags
function getCreateFlagStr(flag){
    var flagArr = [];
    if(flag & CREATE_BREAKAWAY_FROM_JOB){
        flagArr.push("CREATE_BREAKAWAY_FROM_JOB");
    }
    if(flag & CREATE_DEFAULT_ERROR_MODE){
        flagArr.push("CREATE_DEFAULT_ERROR_MODE");
    }
    if(flag & CREATE_NEW_CONSOLE){
        flagArr.push("CREATE_NEW_CONSOLE");
    }
    if(flag & CREATE_NEW_PROCESS_GROUP){
        flagArr.push("CREATE_NEW_PROCESS_GROUP");
    }
    if(flag & CREATE_NO_WINDOW){
        flagArr.push("CREATE_NO_WINDOW");
    }
    if(flag & CREATE_PROTECTED_PROCESS){
        flagArr.push("CREATE_PROTECTED_PROCESS");
    }
    if(flag & CREATE_PRESERVE_CODE_AUTHZ_LEVEL){
        flagArr.push("CREATE_PRESERVE_CODE_AUTHZ_LEVEL");
    }
    if(flag & CREATE_SEPARATE_WOW_VDM){
        flagArr.push("CREATE_SEPARATE_WOW_VDM");
    }
    if(flag & CREATE_SHARED_WOW_VDM){
        flagArr.push("CREATE_SHARED_WOW_VDM");
    }
    if(flag & CREATE_SUSPENDED){
        flagArr.push("CREATE_SUSPENDED");
    }
    if(flag & CREATE_UNICODE_ENVIRONMENT){
        flagArr.push("CREATE_UNICODE_ENVIRONMENT");
    }
    if(flag & DEBUG_ONLY_THIS_PROCESS){
        flagArr.push("DEBUG_ONLY_THIS_PROCESS");
    }
    if(flag & DEBUG_PROCESS){
        flagArr.push("DEBUG_PROCESS");
    }
    if(flag & DETACHED_PROCESS){
        flagArr.push("DETACHED_PROCESS");
    }
    if(flag & EXTENDED_STARTUPINFO_PRESENT){
        flagArr.push("EXTENDED_STARTUPINFO_PRESENT");
    }
    if(flag & INHERIT_PARENT_AFFINITY){
        flagArr.push("INHERIT_PARENT_AFFINITY");
    }

    if(flagArr.length > 0){
        return flagArr.join(" | ");
    }
    else{
        return hexify(flag);
    }
}




/////////////////////////////////////////////////////////
//
// SETUP NATIVE FUNCTIONS
//
/////////////////////////////////////////////////////////

// DWORD WINAPI GetProcessId(
//   _In_ HANDLE Process
// );
var GetProcessId = new NativeFunction(Module.findExportByName("KERNEL32.DLL", "GetProcessId"), 'uint', ['uint'], 'stdcall');

// DWORD WINAPI GetProcessIdOfThread(
//   _In_ HANDLE Thread
// );
var GetProcessIdOfThread = new NativeFunction(Module.findExportByName("KERNEL32.DLL", "GetProcessIdOfThread"), 'uint', ['uint'], 'stdcall');

//DWORD WINAPI GetCurrentProcessId(void);
var GetCurrentProcessId = new NativeFunction(Module.findExportByName("KERNEL32.DLL", "GetCurrentProcessId"), 'uint', [], 'stdcall');

//store current process ID
current_pid = GetCurrentProcessId();


/////////////////////////////////////////////////////////
//
// SET HOOKS
//
/////////////////////////////////////////////////////////

// VOID WINAPI ExitProcess(
//  _In_ UINT uExitCode );
var ptrExitProcess= Module.findExportByName("KERNEL32.DLL", "ExitProcess");
var ExitProcess = new NativeFunction(ptrExitProcess, 'void', ['uint'], 'stdcall');
Interceptor.replace(ptrExitProcess, new NativeCallback(function (uExitCode) {
    
    log("Exit");
    performFlushBeforeExit();
    return  ExitProcess(uExitCode);
}, 'void', ['uint'], 'stdcall'));


// NtWriteVirtualMemory(
// IN HANDLE               ProcessHandle,
// IN PVOID                BaseAddress,
// IN PVOID                Buff,
// IN ULONG                NumberOfBytesToWrite,
// OUT PULONG              NumberOfBytesWritten OPTIONAL );
var ptrNtWriteVirtualMemory = Module.findExportByName("NTDLL.DLL", "NtWriteVirtualMemory");
var NtWriteVirtualMemory = new NativeFunction(ptrNtWriteVirtualMemory, 'uint', ['uint', 'pointer', 'pointer','ulong','pointer'], 'stdcall');
Interceptor.replace(ptrNtWriteVirtualMemory, new NativeCallback(function (ProcessHandle, BaseAddress, Buff, NumberOfBytesToWrite, NumberOfBytesWritten) {
    var RetNTAPI = NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buff, NumberOfBytesToWrite, NumberOfBytesWritten);

    var strRetNTAPI = hexify(RetNTAPI);

    var strProcessHandle = hexify(ProcessHandle);
    var strBaseAddress = hexify(BaseAddress);

    var strBuffer= hexify(Buff);

    var strNumberOfBytesToWrite = hexify(NumberOfBytesToWrite);
    //Optional args ptr
    if(NumberOfBytesWritten == 0){
        var strNumberOfBytesWritten = hexify(NumberOfBytesWritten);
    }
    else{
        var strNumberOfBytesWritten = hexify(Memory.readULong(NumberOfBytesWritten));
    }

    log("NtWriteVirtualMemory("+strProcessHandle+", "+strBaseAddress+", "+strBuffer+", "+strNumberOfBytesToWrite+", "+strNumberOfBytesWritten+") -> " + strRetNTAPI);
    log("NtWriteVirtualMemory pid: " + String(GetProcessId(ProcessHandle)));

    //dump if written to remote proc
    //TODO: handle writes to multiple processes (anti-unpacker)
    var mem_pid = GetProcessId(ProcessHandle);
    var arr_len = pids.length;
    for (var i = 0; i < arr_len; i++) {
        if(mem_pid == pids[i]){
            var memstart = Buff.toInt32();
            var size = NumberOfBytesToWrite;
            var rawArr = Memory.readByteArray(ptr(memstart),size);
            dump(BaseAddress.toInt32(),rawArr);
        }
    }

    return RetNTAPI;
}, 'uint', ['uint', 'pointer', 'pointer','ulong','pointer'], 'stdcall'));


// NtCreateThread(
//   OUT PHANDLE             ThreadHandle,
//   IN ACCESS_MASK          DesiredAccess,
//   IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
//   IN HANDLE               ProcessHandle,
//   OUT PCLIENT_ID          ClientId,
//   IN PCONTEXT             ThreadContext,
//   IN PINITIAL_TEB         InitialTeb,
//   IN BOOLEAN              CreateSuspended );
var ptrNtCreateThread = Module.findExportByName("NTDLL.DLL", "NtCreateThread");
var NtCreateThread = new NativeFunction(ptrNtCreateThread, 'uint', ['pointer', 'uint', 'pointer','uint','pointer','pointer','pointer','uchar'], 'stdcall');
Interceptor.replace(ptrNtCreateThread, new NativeCallback(function (ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended) {
    var RetNTAPI = NtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);

    var strRetNTAPI = hexify(RetNTAPI);
    
    var strThreadHandle =  hexify(Memory.readU32(ThreadHandle));
    var strDesiredAccess =  hexify(DesiredAccess);
    //Optional arg ptr
    if(ObjectAttributes == 0){
        var strObjectAttributes =  hexify(ObjectAttributes);
    }
    else{
        var strObjectAttributes =  hexify(Memory.readU32(ObjectAttributes));
    }
    var strProcessHandle = hexify(ProcessHandle);
    var strClientId =  hexify(Memory.readU32(ClientId));
    var strThreadContext =  hexify(Memory.readU32(ThreadContext));
    var strInitialTeb =  hexify(Memory.readU32(InitialTeb));
    var strCreateSuspended = hexify(CreateSuspended);

    log("NtCreateThread("+strThreadHandle+", "+strDesiredAccess+", "+strObjectAttributes+", "+strProcessHandle+", "+strClientId+", "+strThreadContext+", "+strInitialTeb+", "+strCreateSuspended+") -> " + strRetNTAPI);

    return RetNTAPI;

}, 'uint', ['pointer', 'uint', 'pointer','uint','pointer','pointer','pointer','uchar'], 'stdcall'));



// NtResumeThread(
//   IN HANDLE               ThreadHandle,
//   OUT PULONG              SuspendCount OPTIONAL );
var ptrNtResumeThread = Module.findExportByName("NTDLL.DLL", "NtResumeThread");
var NtResumeThread = new NativeFunction(ptrNtResumeThread, 'uint', ['uint', 'pointer'], 'stdcall');
Interceptor.replace(ptrNtResumeThread, new NativeCallback(function (ThreadHandle, SuspendCount) {
    var RetNTAPI = NtResumeThread(ThreadHandle, SuspendCount);

    var strRetNTAPI = hexify(RetNTAPI);

    var strThreadHandle = hexify(ThreadHandle);
    //Optional arg ptr
    if(SuspendCount == 0){
        var strSuspendCount = hexify(SuspendCount);
    }
    else{
        var strSuspendCount =  hexify(Memory.readULong(SuspendCount));
    }

    log("NtResumeThread("+strThreadHandle+", "+strSuspendCount+") -> " + strRetNTAPI);
    log("NtResumeThread pid: " + String(GetProcessIdOfThread(ThreadHandle)));

    //kill everything if remote thread resumed
    var thread_pid = GetProcessIdOfThread(ThreadHandle);
    var arr_len = pids.length;
    for (var i = 0; i < arr_len; i++) {
        if(thread_pid == pids[i]){
            pKill(thread_pid);
            eKill("Completed dumping");
        }
    }
    return RetNTAPI;

}, 'uint', ['uint', 'pointer'], 'stdcall'));


// NtDelayExecution(
//   IN BOOLEAN              Alertable,
//   IN PLARGE_INTEGER       DelayInterval );
var ptrNtDelayExecution = Module.findExportByName("NTDLL.DLL", "NtDelayExecution");
var NtDelayExecution = new NativeFunction(ptrNtDelayExecution, 'uint', ['uchar', 'pointer'], 'stdcall');
Interceptor.replace(ptrNtDelayExecution, new NativeCallback(function (Alertable, DelayInterval) {

    var strRetNTAPI = hexify(RetNTAPI);
    var strAlertable = hexify(Alertable);
    var strDelayInterval = hexify(Memory.readU32(DelayInterval));

    //set delay to 1 nanosec
    //TODO: hook time ticks and add in lost time
    log("Squashed delay!");
    Memory.writeU32(DelayInterval, 1);
    var RetNTAPI = NtDelayExecution(Alertable, DelayInterval);

    log("NtDelayExecution("+strAlertable+", "+strDelayInterval+") -> " + strRetNTAPI);
    return RetNTAPI;

}, 'uint', ['uchar', 'pointer'], 'stdcall'));


// CreateProcessInternalW(
//     HANDLE Token
//     LPCWSTR ApplicationName OPTIONAL
//     LPWSTR CommandLine OPTIONAL
//     LPSECURITY_ATTRIBUTES ProcessAttributes OPTIONAL
//     LPSECURITY_ATTRIBUTES ThreadAttributes OPTIONAL
//     BOOL InheritHandles
//     DWORD CreationFlags
//     LPVOID Environment OPTIONAL
//     LPCWSTR CurrentDirectory OPTIONAL
//     LPSTARTUPINFOW StartupInfo
//     LPPROCESS_INFORMATION ProcessInformation
//     PHANDLE NewToken);

var ptrCreateProcessInternalW = Module.findExportByName("KERNEL32.DLL", "CreateProcessInternalW");
var CreateProcessInternalW = new NativeFunction(ptrCreateProcessInternalW, 'uint', ['uint', 'pointer', 'pointer', 'pointer', 'pointer', 'uchar', 'uint', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer' ], 'stdcall');
Interceptor.replace(ptrCreateProcessInternalW, new NativeCallback(function (Token, ApplicationName, CommandLine, ProcessAttributes, ThreadAttributes, InheritHandles, CreationFlags, Environment, CurrentDirectory, StartupInfo, ProcessInformation, NewToken) {
    var RetNTAPI = CreateProcessInternalW(Token, ApplicationName, CommandLine, ProcessAttributes, ThreadAttributes, InheritHandles, CreationFlags, Environment, CurrentDirectory, StartupInfo, ProcessInformation, NewToken);

    var strRetNTAPI = hexify(RetNTAPI);

    var strToken = hexify(Token);
    //Optional arg ptr
    if(ApplicationName == 0){
        var strApplicationName = "null";
    }
    else{
        var strApplicationName = Memory.readUtf16String(ApplicationName);
    }
    
    //Optional arg ptr
    if(CommandLine == 0){
        var strCommandLine = "null";
    }
    else{
        var strCommandLine =  Memory.readUtf16String(CommandLine);
    }
    
    //Optional arg ptr
    if(ProcessAttributes == 0){
        var strProcessAttributes = hexify(ProcessAttributes);
    }
    else{
        var strProcessAttributes =  hexify(Memory.readU32(ProcessAttributes));
    }

    //Optional arg ptr
    if(ThreadAttributes == 0){
        var strThreadAttributes = hexify(ThreadAttributes);
    }
    else{
        var strThreadAttributes =  hexify(Memory.readU32(ThreadAttributes));
    }
    var strInheritHandles = hexify(InheritHandles);
    var strCreationFlags = getCreateFlagStr(CreationFlags);

    //Optional arg ptr
    if(Environment == 0){
        var strEnvironment = hexify(Environment);
    }
    else{
        var strEnvironment =  hexify(Memory.readU32(Environment));
    }

    //Optional arg ptr
    if(CurrentDirectory == 0){
        var strCurrentDirectory = hexify(CurrentDirectory);
    }
    else{
        var strCurrentDirectory =  hexify(Memory.readU32(CurrentDirectory));
    }

    var strStartupInfo =  hexify(Memory.readU32(ptr(StartupInfo)));
    var strProcessInformation =  hexify(Memory.readU32(ProcessInformation));

    //parse PROCESS_INFORMTION struct
    var strProcessHandle =  hexify(Memory.readU32(ProcessInformation));

    //typedef struct _PROCESS_INFORMATION {
    //HANDLE hProcess;
    //HANDLE hThread;
    //DWORD  dwProcessId;
    //DWORD  dwThreadId;
    //}
    var strThreadHandle =  hexify(Memory.readU32(ptr(ProcessInformation.toInt32()+4)));
    

    //Optional arg ptr
    if(NewToken == 0){
        var strNewToken = hexify(NewToken);
    }
    else{
        var strNewToken =  hexify(Memory.readU32(NewToken));
    }

    log("CreateProcessInternalW("+strToken+", "+strApplicationName+", "+strCommandLine+", "+strProcessAttributes+", "+strThreadAttributes+", "+strInheritHandles+", "+strCreationFlags+", "+strEnvironment+", "+strCurrentDirectory+", "+strStartupInfo+", "+strProcessInformation+", "+strNewToken+") -> " + strRetNTAPI);
    log("CreateProcessInternalW pid: " + String(GetProcessId(Memory.readU32(ProcessInformation))));

    //save new process PID
    pids.push(GetProcessId(Memory.readU32(ProcessInformation)));
    //ensure each PID is unique
    pids = Array.from(new Set(pids));
    return RetNTAPI;

}, 'uint', ['uint', 'pointer', 'pointer', 'pointer', 'pointer', 'uchar', 'uint', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer' ], 'stdcall'));   


/////////////////////////////////////////////////////////
//
// EXCEPTION HANDLER
//
/////////////////////////////////////////////////////////
Process.setExceptionHandler(function (ex) {
    log("Exception: " +  String(ex));
});







