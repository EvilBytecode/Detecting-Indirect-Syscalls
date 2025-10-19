#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(x) ((x) >= 0)

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* pNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* pNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* pNtClose)(HANDLE);
typedef NTSTATUS(NTAPI* pNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* pNtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PCLIENT_ID);

namespace nt {
    pNtOpenProcess open_process;
    pNtAllocateVirtualMemory alloc;
    pNtWriteVirtualMemory write;
    pNtReadVirtualMemory read;
    pNtCreateThreadEx create_thread;
    pNtWaitForSingleObject wait;
    pNtClose close;
    pNtDelayExecution delay;
    pNtResumeThread resume;
    pNtQueryInformationProcess query;
    pRtlCreateUserThread create_user_thread;

    void init() {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        open_process = (pNtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
        alloc = (pNtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
        write = (pNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
        read = (pNtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");
        create_thread = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
        wait = (pNtWaitForSingleObject)GetProcAddress(ntdll, "NtWaitForSingleObject");
        close = (pNtClose)GetProcAddress(ntdll, "NtClose");
        delay = (pNtDelayExecution)GetProcAddress(ntdll, "NtDelayExecution");
        resume = (pNtResumeThread)GetProcAddress(ntdll, "NtResumeThread");
        query = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
        create_user_thread = (pRtlCreateUserThread)GetProcAddress(ntdll, "RtlCreateUserThread");
    }

    void sleep(DWORD ms) {
        LARGE_INTEGER interval;
        interval.QuadPart = -(LONGLONG)ms * 10000;
        delay(FALSE, &interval);
    }

    HANDLE open_proc(DWORD pid) {
        HANDLE proc = NULL;
        CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, NULL };
        OBJECT_ATTRIBUTES oa = { sizeof(oa) };
        open_process(&proc, PROCESS_ALL_ACCESS, &oa, &cid);
        return proc;
    }

    LPVOID find_module(HANDLE proc, const wchar_t* name) {
        PROCESS_BASIC_INFORMATION pbi = { 0 };
        query(proc, 0, &pbi, sizeof(pbi), NULL);

        PEB peb = { 0 };
        read(proc, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);

        PEB_LDR_DATA ldr = { 0 };
        read(proc, peb.Ldr, &ldr, sizeof(ldr), NULL);

        LIST_ENTRY* head = ldr.InMemoryOrderModuleList.Flink;
        LIST_ENTRY* current = head;

        do {
            LDR_DATA_TABLE_ENTRY entry = { 0 };
            read(proc, CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &entry, sizeof(entry), NULL);

            wchar_t buffer[MAX_PATH] = { 0 };
            read(proc, entry.BaseDllName.Buffer, buffer, entry.BaseDllName.Length, NULL);

            if (_wcsicmp(buffer, name) == 0) {
                return entry.DllBase;
            }

            current = entry.InMemoryOrderLinks.Flink;
        } while (current != head);

        return NULL;
    }
}

namespace injector {
    LPVOID inject(DWORD pid, const char* path) {
        HANDLE proc = nt::open_proc(pid);
        if (!proc) return NULL;

        wchar_t wpath[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH);

        SIZE_T len = (wcslen(wpath) + 1) * sizeof(wchar_t);
        PVOID mem = NULL;
        SIZE_T region = len;
        nt::alloc(proc, &mem, 0, &region, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        nt::write(proc, mem, wpath, len, NULL);

        HMODULE kernel = GetModuleHandleA("kernel32.dll");
        PVOID loadlib = GetProcAddress(kernel, "LoadLibraryW");

        HANDLE thread = NULL;
        nt::create_thread(&thread, THREAD_ALL_ACCESS, NULL, proc, loadlib, mem, 0, 0, 0, 0, NULL);

        LARGE_INTEGER timeout;
        timeout.QuadPart = -100000000LL;
        nt::wait(thread, FALSE, &timeout);

        nt::close(thread);
        nt::close(proc);
        return mem;
    }

    void start_thread(DWORD pid, LPVOID base, const char* dll_path) {
        HANDLE proc = nt::open_proc(pid);

        HMODULE local = LoadLibraryA(dll_path);
        LPVOID func = GetProcAddress(local, "startdetection");
        DWORD64 offset = (DWORD64)func - (DWORD64)local;
        LPVOID remote = (LPVOID)((DWORD64)base + offset);
        FreeLibrary(local);

        HANDLE thread = NULL;
        nt::create_thread(&thread, THREAD_ALL_ACCESS, NULL, proc, remote, NULL, 0, 0, 0, 0, NULL);
        nt::close(thread);
        nt::close(proc);
    }
}

int main() {
    nt::init();

    const char* exe = "YOUR EXE TO TEST IN HERE, PUT YOUR FILEPATH";
    const char* dll = "THE COMPILED DLL, PUT IT IN HERE AS A FILEPATH.";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    CreateProcessA(exe, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    printf("pid: %d\n", pi.dwProcessId);
    nt::sleep(500);

    injector::inject(pi.dwProcessId, dll);
    nt::sleep(2000);

    LPVOID base = nt::find_module(pi.hProcess, L"detectindirectsyscalls.dll");
    printf("base: 0x%p\n", base);

    injector::start_thread(pi.dwProcessId, base, dll);
    nt::sleep(5000);

    nt::resume(pi.hThread, NULL);

    LARGE_INTEGER timeout;
    timeout.QuadPart = -300000000LL;
    nt::wait(pi.hProcess, FALSE, &timeout);

    nt::close(pi.hProcess);
    nt::close(pi.hThread);
    return 0;
}