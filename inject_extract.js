/////////////////////////////////////////////////////////
//
// Use Frida to automatically extract injected PE files 
// (injected via RunPE method and MapViewOfSection method)
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

const SEC_FILE = 0x800000;
const SEC_IMAGE = 0x1000000;
const SEC_VLM = 0x2000000;
const SEC_RESERVE = 0x4000000;
const SEC_COMMIT = 0x8000000;
const SEC_NOCACHE = 0x10000000;

const STANDARD_RIGHTS_REQUIRED = 0x000F0000;
const SECTION_QUERY = 0x0001;
const SECTION_MAP_WRITE = 0x0002;
const SECTION_MAP_READ = 0x0004;
const SECTION_MAP_EXECUTE = 0x0008;
const SECTION_EXTEND_SIZE = 0x0010;

const MEMORY_INFORMATION_CLASS_MemoryBasicInformation = 0x00; // MEMORY_BASIC_INFORMATION
const MEMORY_INFORMATION_CLASS_MemoryWorkingSetInformation = 0x01; // MEMORY_WORKING_SET_INFORMATION
const MEMORY_INFORMATION_CLASS_MemoryMappedFilenameInformation = 0x02; // UNICODE_STRING
const MEMORY_INFORMATION_CLASS_MemoryRegionInformation = 0x03; // MEMORY_REGION_INFORMATION
const MEMORY_INFORMATION_CLASS_MemoryWorkingSetExInformation = 0x04; // MEMORY_WORKING_SET_EX_INFORMATION
const MEMORY_INFORMATION_CLASS_MemorySharedCommitInformation = 0x05; // MEMORY_SHARED_COMMIT_INFORMATION


/////////////////////////////////////////////////////////
//
// GLOBAL VARIABLES
//
/////////////////////////////////////////////////////////
var pids = [];
var current_pid = 0;
//TODO: warning this schema only supports one mapped remote view per section 
//[<SectionHandle>: {BaseAddress = 0x00, ViewSize = 0x00, RemotePID: 0x00, RemoteBaseAddress:0x00]
var sections = [];
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


//check Allocation Attributes
function getAllocationAttributesStr(flag){
    var flagArr = [];
    if(flag & SEC_FILE){
        flagArr.push("SEC_FILE");
    }
    if(flag & SEC_IMAGE){
        flagArr.push("SEC_IMAGE");
    }
    if(flag & SEC_VLM){
        flagArr.push("SEC_VLM");
    }
    if(flag & SEC_RESERVE){
        flagArr.push("SEC_RESERVE");
    }
    if(flag & SEC_COMMIT){
        flagArr.push("SEC_COMMIT");
    }
    if(flag & SEC_NOCACHE){
        flagArr.push("SEC_NOCACHE");
    }


    if(flagArr.length > 0){
        return flagArr.join(" | ");
    }
    else{
        return hexify(flag);
    }
}

//check Access
function getAccessStr(flag){
    var flagArr = [];
    if(flag & STANDARD_RIGHTS_REQUIRED){
        flagArr.push("STANDARD_RIGHTS_REQUIRED");
    }
    if(flag & SECTION_QUERY){
        flagArr.push("SECTION_QUERY");
    }
    if(flag & SECTION_MAP_WRITE){
        flagArr.push("SECTION_MAP_WRITE");
    }
    if(flag & SECTION_MAP_READ){
        flagArr.push("SECTION_MAP_READ");
    }
    if(flag & SECTION_MAP_EXECUTE){
        flagArr.push("SECTION_MAP_EXECUTE");
    }
    if(flag & SECTION_EXTEND_SIZE){
        flagArr.push("SECTION_EXTEND_SIZE");
    }

    if (flagArr.length == 6){
        return "SECTION_ALL_ACCESS";
    }
    else if(flagArr.length > 0){
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

// NTSTATUS NtQueryVirtualMemory(
//   _In_      HANDLE                   ProcessHandle,
//   _In_opt_  PVOID                    BaseAddress,
//   _In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
//   _Out_     PVOID                    MemoryInformation,
//   _In_      SIZE_T                   MemoryInformationLength,
//   _Out_opt_ PSIZE_T                  ReturnLength
// );
var NtQueryVirtualMemory = new NativeFunction(Module.findExportByName("NTDLL.DLL", "NtQueryVirtualMemory"), 'uint', ['uint','pointer','uint','pointer','uint','pointer'], 'stdcall');


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
// SETUP WRAPPER FUNCTIONS
//
/////////////////////////////////////////////////////////

function getMemoryInfo(processHandle, address){
    var out={};    

    var len_memory_basic_information = 28;
    var memory_basic_information = Memory.alloc(len_memory_basic_information);
    var out_buff_size = Memory.alloc(4);

    // NTSTATUS NtQueryVirtualMemory(
    //   _In_      HANDLE                   ProcessHandle,
    //   _In_opt_  PVOID                    BaseAddress,
    //   _In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
    //   _Out_     PVOID                    MemoryInformation,
    //   _In_      SIZE_T                   MemoryInformationLength,
    //   _Out_opt_ PSIZE_T                  ReturnLength
    // );
    var ntstatus = NtQueryVirtualMemory(processHandle,ptr(address),MEMORY_INFORMATION_CLASS_MemoryBasicInformation,memory_basic_information,len_memory_basic_information,out_buff_size);

    if(ntstatus == 0){
        //Extract information from struct:
        // typedef struct _MEMORY_BASIC_INFORMATION {
        //   PVOID  BaseAddress;
        //   PVOID  AllocationBase;
        //   DWORD  AllocationProtect;
        //   SIZE_T RegionSize;
        //   DWORD  State;
        //   DWORD  Protect;
        //   DWORD  Type;
        // } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

        out["base_address"] = Memory.readU32(ptr(memory_basic_information.toInt32()));
        out["allocation_base"] = Memory.readU32(ptr(memory_basic_information.toInt32()+4));
        out["allocation_protect"] = Memory.readU32(ptr(memory_basic_information.toInt32()+8));
        out["region_size"] = Memory.readU32(ptr(memory_basic_information.toInt32()+12));
        out["state"] = Memory.readU32(ptr(memory_basic_information.toInt32()+16));
        out["protect"] = Memory.readU32(ptr(memory_basic_information.toInt32()+20));
        out["type"] = Memory.readU32(ptr(memory_basic_information.toInt32()+24));
    }

    return out;
}



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


// NTSTATUS NtCreateFile(
//   _Out_    PHANDLE            FileHandle,
//   _In_     ACCESS_MASK        DesiredAccess,
//   _In_     POBJECT_ATTRIBUTES ObjectAttributes,
//   _Out_    PIO_STATUS_BLOCK   IoStatusBlock,
//   _In_opt_ PLARGE_INTEGER     AllocationSize,
//   _In_     ULONG              FileAttributes,
//   _In_     ULONG              ShareAccess,
//   _In_     ULONG              CreateDisposition,
//   _In_     ULONG              CreateOptions,
//   _In_     PVOID              EaBuffer,
//   _In_     ULONG              EaLength
// );

// TODO: hook NtCreateFile


// NTSTATUS NtMapViewOfSection(
//   _In_        HANDLE          SectionHandle,
//   _In_        HANDLE          ProcessHandle,
//   _Inout_     PVOID           *BaseAddress,
//   _In_        ULONG_PTR       ZeroBits,
//   _In_        SIZE_T          CommitSize,
//   _Inout_opt_ PLARGE_INTEGER  SectionOffset,
//   _Inout_     PSIZE_T         ViewSize,
//   _In_        SECTION_INHERIT InheritDisposition,
//   _In_        ULONG           AllocationType,
//   _In_        ULONG           Win32Protect
// );
var ptrNtMapViewOfSection= Module.findExportByName("NTDLL.DLL", "NtMapViewOfSection");
var NtMapViewOfSection = new NativeFunction(ptrNtMapViewOfSection, 'uint', ['uint', 'uint', 'pointer', 'pointer', 'uint', 'pointer', 'pointer', 'uint', 'ulong', 'ulong' ], 'stdcall');
Interceptor.replace(ptrNtMapViewOfSection, new NativeCallback(function (SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType,  Win32Protect) {
    var RetNTAPI = NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType,  Win32Protect);
    if(RetNTAPI ==0){
        var strRetNTAPI = hexify(RetNTAPI);
        var strSectionHandle = hexify(SectionHandle);
        var strProcessHandle = hexify(ProcessHandle);
        var strBaseAddress = hexify(Memory.readU32(BaseAddress));
        var strZeroBits = hexify(ZeroBits.toInt32());
        var strCommitSize = hexify(CommitSize);

        var strSectionOffset = "NULL";
        try{
            strSectionOffset = hexify(Memory.readLong(SectionOffset));
        }
        catch (e){
            //log("NtMapViewOfSection: error reading ptr SectionOffset");
        }

        var strViewSize = hexify(Memory.readU32(ViewSize));
        var strInheritDisposition = hexify(InheritDisposition);
        var strAllocationType = hexify(AllocationType);
        var strWin32Protect = getProtectionStr(Win32Protect);
        log("NtMapViewOfSection("+strSectionHandle+", "+strProcessHandle+", "+strBaseAddress+", "+strZeroBits+", "+strCommitSize+", "+strSectionOffset+", "+strViewSize+", "+strInheritDisposition+", "+strAllocationType+", "+strWin32Protect+") -> " + strRetNTAPI);
        log("NtMapViewOfSection pid: " + String(GetProcessId(ProcessHandle)));

        //TODO: this will fail if SectionOffset is used instead of ViewSize ... this shouldn't happen for injection
        //test to see if mapped to local process
        if(ProcessHandle == 0xffffffff){
            //does entry already exist for section
            if(sections.hasOwnProperty(SectionHandle)){
                sections[SectionHandle]["BaseAddress"] = Memory.readU32(BaseAddress);
                sections[SectionHandle]["ViewSize"] = Memory.readU32(ViewSize);
            }
            else{
                var section_entry = {"BaseAddress": Memory.readU32(BaseAddress), "ViewSize": Memory.readU32(ViewSize), "RemotePID": null, "RemoteBaseAddress": null};
                sections[SectionHandle] = section_entry;
            }
        } 
        else{
            //does entry already exist for section
            if(sections.hasOwnProperty(SectionHandle)){
                sections[SectionHandle]["RemotePID"] = GetProcessId(ProcessHandle);
                sections[SectionHandle]["RemoteBaseAddress"] = Memory.readU32(BaseAddress);
            }
            else{
                var section_entry = {"BaseAddress": null, "ViewSize": null, "RemotePID": GetProcessId(ProcessHandle), "RemoteBaseAddress": Memory.readU32(BaseAddress)};
                sections[SectionHandle] = section_entry;
            }
        }
    }
    else{
        log("NtMapViewOfSection error: " + hexify(RetNTAPI));
    }
    return RetNTAPI;

}, 'uint', ['uint', 'uint', 'pointer', 'pointer', 'uint', 'pointer', 'pointer', 'uint', 'ulong', 'ulong' ], 'stdcall'));


// NTSTATUS NtUnmapViewOfSection(
//   _In_     HANDLE ProcessHandle,
//   _In_opt_ PVOID  BaseAddress
// );
var ptrNtUnmapViewOfSection= Module.findExportByName("NTDLL.DLL", "NtUnmapViewOfSection");
var NtUnmapViewOfSection = new NativeFunction(ptrNtUnmapViewOfSection, 'uint', ['uint', 'pointer'], 'stdcall');
Interceptor.replace(ptrNtUnmapViewOfSection, new NativeCallback(function (ProcessHandle, BaseAddress) {
    //if section that has been remote mapped is being unmapped locally dump it!
    if(ProcessHandle == 0xffffffff){
        for(var i in sections){
            //find section at base
            if(sections[i]["BaseAddress"] == BaseAddress.toInt32()){
                //check if section was remotely mapped
                if(sections[i]["RemotePID"] != null){
                    var raw_data = Memory.readByteArray(ptr(sections[i]["BaseAddress"]),sections[i]["ViewSize"]);
                    dump(sections[i]["RemoteBaseAddress"],raw_data);
                    sections.splice(i,1);
                    break;
                }
            } 
        }
    }

    var RetNTAPI = NtUnmapViewOfSection(ProcessHandle, BaseAddress);
    if(RetNTAPI ==0 ){
        var strRetNTAPI = hexify(RetNTAPI);
        var strProcessHandle = hexify(ProcessHandle);
        var strBaseAddress = hexify(BaseAddress.toInt32());

        log("NtUnmapViewOfSection("+strProcessHandle+", "+strBaseAddress+") -> " + strRetNTAPI);
        log("NtUnmapViewOfSection pid: " + String(GetProcessId(ProcessHandle)));
    }
    else{
        log("NtMapViewOfSection error: " + hexify(RetNTAPI));
    }
    return RetNTAPI;

}, 'uint', ['uint', 'pointer'], 'stdcall'));


// NTSTATUS NtCreateSection(
//   _Out_    PHANDLE            SectionHandle,
//   _In_     ACCESS_MASK        DesiredAccess,
//   _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
//   _In_opt_ PLARGE_INTEGER     MaximumSize,
//   _In_     ULONG              SectionPageProtection,
//   _In_     ULONG              AllocationAttributes,
//   _In_opt_ HANDLE             FileHandle
// );
var ptrNtCreateSection= Module.findExportByName("NTDLL.DLL", "NtCreateSection");
var NtCreateSection = new NativeFunction(ptrNtCreateSection, 'uint', ['pointer', 'uint', 'pointer', 'pointer', 'ulong', 'ulong', 'uint'], 'stdcall');
Interceptor.replace(ptrNtCreateSection, new NativeCallback(function (SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle) {
    var RetNTAPI = NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    
    if(RetNTAPI ==0){
        var strRetNTAPI = hexify(RetNTAPI);
        var strSectionHandle = hexify(Memory.readU32(SectionHandle));
        var strDesiredAccess= getAccessStr(DesiredAccess);

        var strObjectAttributes = "NULL";
        try{
            strObjectAttributes = hexify(Memory.readU32(ObjectAttributes));
        }
        catch (e){
            //log("NtCreateSection: error reading ptr ObjectAttributes");
        }

        var strMaximumSize = "NULL";
        try{
            strMaximumSize = hexify(Memory.readLong(MaximumSize));
        }
        catch (e){
            //log("NtCreateSection: error reading ptr MaximumSize");
        }

        var strSectionPageProtection = getProtectionStr(SectionPageProtection);
        var strAllocationAttributes = getAllocationAttributesStr(AllocationAttributes);
        var strFileHandle = hexify(FileHandle);

        log("NtCreateSection("+strSectionHandle+", "+strDesiredAccess+", "+strObjectAttributes+", "+strMaximumSize+", "+strSectionPageProtection+", "+strAllocationAttributes+", "+strFileHandle+") -> " + strRetNTAPI);
    }
    else{
        log("NtCreateSection error: " + hexify(RetNTAPI));
    }
    return RetNTAPI;

}, 'uint',  ['pointer', 'uint', 'pointer', 'pointer', 'ulong', 'ulong', 'uint'], 'stdcall'));


// NtWriteVirtualMemory(
// IN HANDLE               ProcessHandle,
// IN PVOID                BaseAddress,
// IN PVOID                Buff,
// IN ULONG                NumberOfBytesToWrite,
// OUT PULONG              NumberOfBytesWritten OPTIONAL );
var ptrNtWriteVirtualMemory = Module.findExportByName("NTDLL.DLL", "NtWriteVirtualMemory");
var NtWriteVirtualMemory = new NativeFunction(ptrNtWriteVirtualMemory, 'uint', ['uint', 'pointer', 'pointer','ulong','pointer'], 'stdcall');
Interceptor.replace(ptrNtWriteVirtualMemory, new NativeCallback(function (ProcessHandle, BaseAddress, Buff, NumberOfBytesToWrite, NumberOfBytesWritten) {
    try{
    var RetNTAPI = NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buff, NumberOfBytesToWrite, NumberOfBytesWritten);
    }
    catch(e){
        log(String(e));
        log("NtWriteVirtualMemory Error!");
        eKill("NtWriteVirtualMemory Error!");
    }

    if(RetNTAPI ==0 ){ 
        var strRetNTAPI = hexify(RetNTAPI);

        var strProcessHandle = hexify(ProcessHandle);
        var strBaseAddress = hexify(BaseAddress.toInt32());

        var strBuffer= hexify(Buff.toInt32());

        var strNumberOfBytesToWrite = hexify(NumberOfBytesToWrite);

        var strNumberOfBytesWritten = "NULL";
        try{
            strNumberOfBytesWritten = hexify(Memory.readULong(NumberOfBytesWritten));
        }
        catch (e){
            //log("NtWriteVirtualMemory: error reading ptr NumberOfBytesWritten");
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
    }
    else{
        log("NtWriteVirtualMemory error: " + hexify(RetNTAPI));
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

    if(RetNTAPI == 0){
        var strRetNTAPI = hexify(RetNTAPI);
        
        var strThreadHandle =  hexify(Memory.readU32(ThreadHandle));
        var strDesiredAccess =  hexify(DesiredAccess);

        var strObjectAttributes = "NULL";
        try{
            strObjectAttributes = hexify(Memory.readU32(ObjectAttributes));
        }
        catch (e){
            //log("NtCreateThread: error reading ptr ObjectAttributes");
        }

        var strProcessHandle = hexify(ProcessHandle);
        var strClientId =  hexify(Memory.readU32(ClientId));
        var strThreadContext =  hexify(Memory.readU32(ThreadContext));
        var strInitialTeb =  hexify(Memory.readU32(InitialTeb));
        var strCreateSuspended = Boolean(CreateSuspended).toString();

        log("NtCreateThread("+strThreadHandle+", "+strDesiredAccess+", "+strObjectAttributes+", "+strProcessHandle+", "+strClientId+", "+strThreadContext+", "+strInitialTeb+", "+strCreateSuspended+") -> " + strRetNTAPI);
    }
    else{
        log("NtCreateThread error: " + hexify(RetNTAPI));
    }
    return RetNTAPI;

}, 'uint', ['pointer', 'uint', 'pointer','uint','pointer','pointer','pointer','uchar'], 'stdcall'));



// NtResumeThread(
//   IN HANDLE               ThreadHandle,
//   OUT PULONG              SuspendCount OPTIONAL );
var ptrNtResumeThread = Module.findExportByName("NTDLL.DLL", "NtResumeThread");
var NtResumeThread = new NativeFunction(ptrNtResumeThread, 'uint', ['uint', 'pointer'], 'stdcall');
Interceptor.replace(ptrNtResumeThread, new NativeCallback(function (ThreadHandle, SuspendCount) {
    //kill everything if remote thread resumed
    var thread_pid = GetProcessIdOfThread(ThreadHandle);
    log("NtResumeThread pid: " + String(thread_pid));

    var arr_len = pids.length;
    for (var i = 0; i < arr_len; i++) {
        if(thread_pid == pids[i]){
            //check to see if any remote mapped sections in process and dump them!
            //they should already be caught by unmap locally but maybe they weren't unmapped
            for(var i in sections){
                //find sections remote mapped
                if(sections[i]["RemotePID"] == thread_pid){
                    var raw_data = Memory.readByteArray(ptr(sections[i]["BaseAddress"]),sections[i]["ViewSize"]);
                    dump(sections[i]["RemoteBaseAddress"],raw_data);
                } 
            }
            //kill remote process and kill this process we are done!
            pKill(thread_pid);
            eKill("Completed dumping");
        }
    }
    //We should never get here if this is a local thread
    var RetNTAPI = NtResumeThread(ThreadHandle, SuspendCount);

    if(RetNTAPI ==0){
        var strRetNTAPI = hexify(RetNTAPI);

        var strThreadHandle = hexify(ThreadHandle);

        var strSuspendCount = "NULL";
        try{
            strSuspendCount = hexify(Memory.readULong(SuspendCount));
        }
        catch (e){
            //log("NtResumeThread: error reading ptr SuspendCount");
        }

        log("NtResumeThread("+strThreadHandle+", "+strSuspendCount+") -> " + strRetNTAPI);
    }
    else{
        log("NtResumeThread error: " + hexify(RetNTAPI));
    }
    return RetNTAPI;

}, 'uint', ['uint', 'pointer'], 'stdcall'));


// NtDelayExecution(
//   IN BOOLEAN              Alertable,
//   IN PLARGE_INTEGER       DelayInterval );
var ptrNtDelayExecution = Module.findExportByName("NTDLL.DLL", "NtDelayExecution");
var NtDelayExecution = new NativeFunction(ptrNtDelayExecution, 'uint', ['uchar', 'pointer'], 'stdcall');
Interceptor.replace(ptrNtDelayExecution, new NativeCallback(function (Alertable, DelayInterval) {

    //TODO: hook and kill delay, add time ticks to lost time
    var strDelayInterval  = "NULL";
    try{
        strDelayInterval = Memory.readLong(DelayInterval);
    }
    catch (e){
        //log("NtResumeThread: error reading ptr SuspendCount");
    }
    log("NtDelayExecution: " + String(strDelayInterval));
    var RetNTAPI = NtDelayExecution(Alertable, DelayInterval);
    var strRetNTAPI = hexify(RetNTAPI);
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
    try{
        var RetNTAPI = CreateProcessInternalW(Token, ApplicationName, CommandLine, ProcessAttributes, ThreadAttributes, InheritHandles, CreationFlags, Environment, CurrentDirectory, StartupInfo, ProcessInformation, NewToken);
    }
    catch(e){
        log(String(e));
        log("CreateProcessInternalW Error!");
        log("token " + hexify(Token));
        log("ApplicationName " + hexify(ApplicationName.toInt32()));
        log("CommandLine " + hexify(CommandLine.toInt32()));
        log("ProcessAttributes " + hexify(ProcessAttributes.toInt32()));
        log("ThreadAttributes " + hexify(ThreadAttributes.toInt32()));
        log("InheritHandles " + hexify(InheritHandles));
        log("CreationFlags " + hexify(CreationFlags));
        log("Environment " + hexify(Environment.toInt32()));
        log("CurrentDirectory " + hexify(CurrentDirectory.toInt32()));
        log("StartupInfo " + hexify(StartupInfo.toInt32()));
        log("ProcessInformation " + hexify(ProcessInformation.toInt32()));
        log("NewToken " + hexify(NewToken.toInt32()));
        eKill("CreateProcessInternalW Error!");
    }
    var strRetNTAPI = hexify(RetNTAPI);

    var strToken = hexify(Token);


    var strApplicationName = "NULL";
    try{
        strApplicationName = Memory.readUtf16String(ApplicationName);
    }
    catch (e){
        //log("CreateProcessInternalW: error reading ptr ApplicationName");
    }

    
    var strCommandLine = "NULL";
    try{
        strCommandLine =  Memory.readUtf16String(CommandLine);
    }
    catch (e){
        //log("CreateProcessInternalW: error reading ptr CommandLine");
    }
        

    var strProcessAttributes = "NULL";
    try{
        strProcessAttributes =  hexify(Memory.readU32(ProcessAttributes));
    }
    catch (e){
        //log("CreateProcessInternalW: error reading ptr ProcessAttributes");
    }
   

    var strThreadAttributes = "NULL";
    try{
        strThreadAttributes =  hexify(Memory.readU32(ThreadAttributes));
    }
    catch (e){
        //log("CreateProcessInternalW: error reading ptr ThreadAttributes");
    }


    var strInheritHandles = Boolean(InheritHandles).toString();
    var strCreationFlags = getCreateFlagStr(CreationFlags);


    var strEnvironment = "NULL";
    try{
        strEnvironment =  hexify(Memory.readU32(Environment));
    }
    catch (e){
        //log("CreateProcessInternalW: error reading ptr Environment");
    }


    var strCurrentDirectory = "NULL";
    try{
        strCurrentDirectory =  hexify(Memory.readU32(CurrentDirectory));
    }
    catch (e){
        //log("CreateProcessInternalW: error reading ptr CurrentDirectory");
    }


    var strStartupInfo =  hexify(Memory.readU32(StartupInfo));
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
    

    var strNewToken = "NULL";
    try{
        strNewToken =  hexify(Memory.readU32(NewToken));
    }
    catch (e){
        //log("CreateProcessInternalW: error reading ptr NewToken");
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
// *Warning: causes a flood of
//  msgs when a packer uses SEH for control flow.
//
/////////////////////////////////////////////////////////

Process.setExceptionHandler(function (ex) {
    log("Exception: " +  ex);
    //Mark memory as executable for execute access-violations
     if(ex["type"].toUpperCase() == "access-violation".toUpperCase()){
        if(ex['memory']['operation'].toUpperCase() == "execute".toUpperCase()){
            var xptr = ex["memory"]["address"].toInt32();
            log("Access-violation: Execute 0x" + xptr.toString(16));            
            var mem_info = getMemoryInfo(0xffffffff, xptr);
            if(mem_info.hasOwnProperty("base_address") && mem_info.hasOwnProperty("region_size")){
                Memory.protect(ptr(mem_info['base_address']), mem_info['region_size'], 'rwx')
                return true;
            }
            return false;
        }

    }
});




