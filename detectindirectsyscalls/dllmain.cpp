#include "pch.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#define nt_success(x) ((x) >= 0)
#define max_events 1000
#define max_syscalls 2
#define log(msg) OutputDebugStringA(msg)
#define logf(buf, fmt, ...) sprintf_s(buf, fmt, __VA_ARGS__); OutputDebugStringA(buf)
#define writef(f, fmt, ...) fprintf(f, fmt, __VA_ARGS__)
#define evt_log(f, i) writef(f, "%-5d %-30s %-10u 0x%016llx 0x%016llx %-15llu\n", i+1, g_events[i].syscallname, g_events[i].tid, g_events[i].returnaddr, g_events[i].instructionptr, g_events[i].timestamp)
#define alert_detect(buf, idx) logf(buf, "\n[!!! alert !!!] indirect syscall detected #%d\n  syscall: %s\n  tid: %u\n  return: 0x%llx (untrusted)\n  rip: 0x%llx\n\n", idx+1, g_events[idx].syscallname, g_events[idx].tid, g_events[idx].returnaddr, g_events[idx].instructionptr)

typedef struct _my_client_id {
    HANDLE uniqueprocess;
    HANDLE uniquethread;
} my_client_id, * pmy_client_id;

typedef struct _my_object_attributes {
    ULONG length;
    HANDLE rootdirectory;
    PVOID objectname;
    ULONG attributes;
    PVOID securitydescriptor;
    PVOID securityqualityofservice;
} my_object_attributes, * pmy_object_attributes;

typedef LONG(WINAPI* rtlsuspendthread)(HANDLE, PULONG);
typedef LONG(WINAPI* rtlresumethread)(HANDLE, PULONG);
typedef LONG(WINAPI* rtlgetcontext)(HANDLE, PCONTEXT);
typedef LONG(WINAPI* rtlsetcontext)(HANDLE, PCONTEXT);
typedef LONG(WINAPI* rtlopenthread)(PHANDLE, ACCESS_MASK, pmy_object_attributes, pmy_client_id);
typedef LONG(WINAPI* rtlclose)(HANDLE);

struct range {
    DWORD64 start;
    DWORD64 end;
};

struct event {
    DWORD pid;
    DWORD tid;
    DWORD64 returnaddr;
    DWORD64 instructionptr;
    DWORD64 timestamp;
    char syscallname[32];
};

#pragma data_seg(".shared")
volatile LONG g_eventcount = 0;
event g_events[max_events] = {};
volatile LONG g_running = 0;
volatile LONG g_totaldetections = 0;
volatile LONG g_initcomplete = 0;
#pragma data_seg()
#pragma comment(linker, "/section:.shared,RWS")

class detectordll {
private:
    range* ranges;
    DWORD rangecount;
    DWORD64 targets[max_syscalls];
    char targetnames[max_syscalls][32];
    DWORD targetcount;
    PVOID veh;

    rtlsuspendthread ntsuspend;
    rtlresumethread ntresume;
    rtlgetcontext ntgetctx;
    rtlsetcontext ntsetctx;
    rtlopenthread ntopen;
    rtlclose ntclose_;

    static detectordll* inst;

public:
    detectordll() : ranges(nullptr), rangecount(0), targetcount(0), veh(nullptr) {
        inst = this;
        ZeroMemory(targets, sizeof(targets));
        ZeroMemory(targetnames, sizeof(targetnames));

        HMODULE nt = GetModuleHandleA("ntdll.dll");
        ntsuspend = (rtlsuspendthread)GetProcAddress(nt, "NtSuspendThread");
        ntresume = (rtlresumethread)GetProcAddress(nt, "NtResumeThread");
        ntgetctx = (rtlgetcontext)GetProcAddress(nt, "NtGetContextThread");
        ntsetctx = (rtlsetcontext)GetProcAddress(nt, "NtSetContextThread");
        ntopen = (rtlopenthread)GetProcAddress(nt, "NtOpenThread");
        ntclose_ = (rtlclose)GetProcAddress(nt, "NtClose");
    }

    ~detectordll() {
        if (veh) RemoveVectoredExceptionHandler(veh);
        if (ranges) delete[] ranges;
    }

    bool init() {
        log("[detector] === initialization started ===\n");
        buildtrustedranges();
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        const char* funcs[] = {"NtAllocateVirtualMemory","NtProtectVirtualMemory"};
        targetcount = 0;
        for (int i = 0; i < 4 && targetcount < max_syscalls; i++) {
            FARPROC f = GetProcAddress(nt, funcs[i]);
            if (f) {
                DWORD64 syscalladdr = findsyscallinstruction((DWORD64)f);
                if (syscalladdr) {
                    targets[targetcount] = syscalladdr;
                    strcpy_s(targetnames[targetcount], funcs[i]);

                    char buf[256];
                    logf(buf, "[detector] [dr%d] %s @ 0x%llx\n", targetcount, funcs[i], syscalladdr);

                    targetcount++;
                }
            }
        }

        if (targetcount == 0) {
            log("[detector] error: no syscalls found!\n");
            return false;
        }

        char buf[256];
        logf(buf, "[detector] mapped %u syscalls, %u trusted ranges\n", targetcount, rangecount);

        veh = AddVectoredExceptionHandler(1, vectoredexceptionhandler);
        if (!veh) {
            log("[detector] error: failed to register veh\n");
            return false;
        }

        InterlockedExchange(&g_running, 1);
        InterlockedExchange(&g_initcomplete, 1);

        log("[detector] === initialization complete ===\n");
        return true;
    }

    bool instrumentcurrentprocess() {
        log("[detector] === thread instrumentation started ===\n");

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            log("[detector] error: failed to create thread snapshot\n");
            return false;
        }

        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        DWORD pid = GetCurrentProcessId();
        DWORD currenttid = GetCurrentThreadId();
        int successcount = 0;
        int failcount = 0;

        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    if (instrumentthread(te.th32ThreadID)) {
                        successcount++;
                        char buf[256];
                        logf(buf, "[detector] [ok] tid:%u%s\n", te.th32ThreadID,
                            te.th32ThreadID == currenttid ? " [current]" : "");
                    }
                    else {
                        failcount++;
                    }
                }
            } while (Thread32Next(snap, &te));
        }

        CloseHandle(snap);

        char buf[256];
        logf(buf, "[detector] instrumentation: %d success, %d failed\n", successcount, failcount);

        return successcount > 0;
    }

    const char* getsyscallname(DWORD64 addr) {
        for (DWORD i = 0; i < targetcount; i++) {
            if (targets[i] == addr) {
                return targetnames[i];
            }
        }
        return "unknown";
    }

private:
    void buildtrustedranges() {
        const char* trustedmodules[] = {"ntdll.dll"};

        DWORD totalfunctions = 0;

        for (int m = 0; m < sizeof(trustedmodules) / sizeof(trustedmodules[0]); m++) {
            HMODULE h = GetModuleHandleA(trustedmodules[m]);
            if (!h) continue;

            __try {
                IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)h;
                if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;

                IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)h + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

                IMAGE_DATA_DIRECTORY* exportdir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (exportdir->VirtualAddress == 0) continue;

                IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)h + exportdir->VirtualAddress);
                totalfunctions += exp->NumberOfFunctions;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }

        ranges = new range[totalfunctions];
        rangecount = 0;

        for (int m = 0; m < sizeof(trustedmodules) / sizeof(trustedmodules[0]); m++) {
            HMODULE h = GetModuleHandleA(trustedmodules[m]);
            if (!h) continue;

            __try {
                IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)h;
                if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;

                IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)h + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

                IMAGE_DATA_DIRECTORY* exportdir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (exportdir->VirtualAddress == 0) continue;

                IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)h + exportdir->VirtualAddress);
                DWORD* funcs = (DWORD*)((BYTE*)h + exp->AddressOfFunctions);

                for (DWORD i = 0; i < exp->NumberOfFunctions && rangecount < totalfunctions; i++) {
                    if (funcs[i]) {
                        ranges[rangecount].start = (DWORD64)h + funcs[i];
                        ranges[rangecount].end = (DWORD64)h + funcs[i] + 0x100;
                        rangecount++;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }
    }

    DWORD64 findsyscallinstruction(DWORD64 addr) {
        __try {
            BYTE* p = (BYTE*)addr;
            for (int i = 0; i < 64; i++) {
                if (p[i] == 0x0f && p[i + 1] == 0x05) {
                    return (DWORD64)&p[i];
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
        return 0;
    }

    bool istrustedcaller(DWORD64 addr) {
        if (addr == 0 || addr < 0x10000) return false;

        for (DWORD i = 0; i < rangecount; i++) {
            if (addr >= ranges[i].start && addr <= ranges[i].end) {
                return true;
            }
        }
        return false;
    }

    bool instrumentthread(DWORD tid) {
        HANDLE h;
        my_object_attributes oa = {};
        oa.length = sizeof(my_object_attributes);

        my_client_id cid = {};
        cid.uniqueprocess = NULL;
        cid.uniquethread = (HANDLE)(ULONG_PTR)tid;

        LONG status = ntopen(&h, THREAD_ALL_ACCESS, &oa, &cid);
        if (!nt_success(status)) {
            return false;
        }

        bool iscurrentthread = (tid == GetCurrentThreadId());

        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        ULONG prevsuspendcount = 0;

        if (iscurrentthread) {
            if (!GetThreadContext(h, &ctx)) {
                ntclose_(h);
                return false;
            }
        }
        else {
            status = ntsuspend(h, &prevsuspendcount);
            if (!nt_success(status)) {
                ntclose_(h);
                return false;
            }

            status = ntgetctx(h, &ctx);
            if (!nt_success(status)) {
                ntresume(h, &prevsuspendcount);
                ntclose_(h);
                return false;
            }
        }

        if (targetcount > 0) ctx.Dr0 = targets[0];
        if (targetcount > 1) ctx.Dr1 = targets[1];
        if (targetcount > 2) ctx.Dr2 = targets[2];
        if (targetcount > 3) ctx.Dr3 = targets[3];

        ctx.Dr7 = 0;
        for (DWORD i = 0; i < targetcount; i++) {
            ctx.Dr7 |= (1ull << (i * 2));
            ctx.Dr7 &= ~(3ull << (16 + i * 4));
            ctx.Dr7 &= ~(3ull << (18 + i * 4));
        }

        bool setsuccess = false;
        if (iscurrentthread) {
            setsuccess = SetThreadContext(h, &ctx);
        }
        else {
            status = ntsetctx(h, &ctx);
            setsuccess = nt_success(status);
            ntresume(h, &prevsuspendcount);
        }

        ntclose_(h);
        return setsuccess;
    }

    static DWORD64 safereadptr(DWORD64 addr) {
        if (addr == 0 || addr < 0x1000 || addr > 0x7fffffffffff) {
            return 0;
        }

        __try {
            return *(DWORD64*)addr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
    }

    static LONG CALLBACK vectoredexceptionhandler(PEXCEPTION_POINTERS exceptioninfo) {
        if (!inst || !InterlockedCompareExchange(&g_running, 1, 1)) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        if (exceptioninfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        CONTEXT* ctx = exceptioninfo->ContextRecord;

        __try {
            if (ctx->Rip == 0 || ctx->Rsp == 0) {
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        bool issyscallbreakpoint = false;
        DWORD syscallindex = 0;

        for (DWORD i = 0; i < inst->targetcount; i++) {
            if (ctx->Rip == inst->targets[i]) {
                issyscallbreakpoint = true;
                syscallindex = i;
                break;
            }
        }

        if (issyscallbreakpoint) {
            DWORD64 returnaddr = safereadptr(ctx->Rsp);

            if (returnaddr && !inst->istrustedcaller(returnaddr)) {
                InterlockedIncrement(&g_totaldetections);
                LONG eventidx = InterlockedIncrement(&g_eventcount) - 1;

                if (eventidx < max_events) {
                    g_events[eventidx].pid = GetCurrentProcessId();
                    g_events[eventidx].tid = GetCurrentThreadId();
                    g_events[eventidx].returnaddr = returnaddr;
                    g_events[eventidx].instructionptr = ctx->Rip;
                    g_events[eventidx].timestamp = GetTickCount64();
                    strcpy_s(g_events[eventidx].syscallname, inst->getsyscallname(ctx->Rip));

                    char alertbuf[512];
                    alert_detect(alertbuf, eventidx);
                }
            }

            ctx->Dr7 = 0;
            ctx->EFlags |= 0x100;
        }
        else if (ctx->EFlags & 0x100) {
            ctx->EFlags &= ~0x100;

            ctx->Dr7 = 0;
            for (DWORD i = 0; i < inst->targetcount; i++) {
                ctx->Dr7 |= (1ull << (i * 2));
                ctx->Dr7 &= ~(3ull << (16 + i * 4));
                ctx->Dr7 &= ~(3ull << (18 + i * 4));
            }
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }
};

detectordll* detectordll::inst = nullptr;
static detectordll* g_detector = nullptr;

extern "C" __declspec(dllexport) DWORD WINAPI startdetection(LPVOID param) {
    log("\n========================================\n");
    log("  indirect syscall detector v2.4\n");
    log("========================================\n");

    Sleep(2000);

    g_detector = new detectordll();
    if (!g_detector) {
        log("[critical] failed to allocate detector object\n");
        return 1;
    }

    if (!g_detector->init()) {
        log("[critical] detector initialization failed\n");
        delete g_detector;
        g_detector = nullptr;
        return 1;
    }

    Sleep(500);

    if (!g_detector->instrumentcurrentprocess()) {
        log("[warning] no threads were instrumented!\n");
    }

    Sleep(500);
    log("[detector] performing secondary thread scan...\n");
    g_detector->instrumentcurrentprocess();

    log("[detector] === active and monitoring ===\n");
    log("[detector] detector is ready. check debugview for detections.\n");

    while (InterlockedCompareExchange(&g_running, 1, 1)) {
        Sleep(100);
    }

    log("[detector] detection loop terminated\n");
    return 0;
}

extern "C" __declspec(dllexport) void stopdetection() {
    InterlockedExchange(&g_running, 0);

    char buf[256];
    logf(buf, "[detector] stopped. total detections: %d\n",
        InterlockedCompareExchange(&g_totaldetections, 0, 0));
}

extern "C" __declspec(dllexport) LONG geteventcount() {
    return InterlockedCompareExchange(&g_eventcount, 0, 0);
}

extern "C" __declspec(dllexport) LONG gettotaldetections() {
    return InterlockedCompareExchange(&g_totaldetections, 0, 0);
}

extern "C" __declspec(dllexport) BOOL getevent(LONG index, event* evt) {
    if (!evt || index < 0 || index >= g_eventcount || index >= max_events) {
        return FALSE;
    }
    *evt = g_events[index];
    return TRUE;
}

extern "C" __declspec(dllexport) void dumpallevents() {
    char buf[512];
    LONG count = InterlockedCompareExchange(&g_eventcount, 0, 0);
    logf(buf, "\n=== detection report ===\ntotal events: %d\n\n", count);

    for (LONG i = 0; i < min(count, (LONG)max_events); i++) {
        logf(buf,
            "[%d] %s - tid:%u return:0x%llx rip:0x%llx time:%llu\n",
            i + 1,
            g_events[i].syscallname,
            g_events[i].tid,
            g_events[i].returnaddr,
            g_events[i].instructionptr,
            g_events[i].timestamp);
    }
}

extern "C" __declspec(dllexport) void exporttofile(const char* filename) {
    FILE* f = nullptr;
    fopen_s(&f, filename ? filename : "c:\\detector_report.txt", "w");
    if (!f) return;

    LONG count = InterlockedCompareExchange(&g_eventcount, 0, 0);
    LONG total = InterlockedCompareExchange(&g_totaldetections, 0, 0);

    fprintf(f, "=== indirect syscall detection report ===\n");
    fprintf(f, "generated: %llu\n", GetTickCount64());
    fprintf(f, "total detections: %d\n", total);
    fprintf(f, "events logged: %d/%d\n\n", min(count, (LONG)max_events), max_events);

    fprintf(f, "%-5s %-30s %-10s %-18s %-18s %-15s\n",
        "#", "syscall", "tid", "return addr", "instruction ptr", "timestamp");
    fprintf(f, "=================================================================\n");

    for (LONG i = 0; i < min(count, (LONG)max_events); i++) {
        evt_log(f, i);
    }

    fclose(f);

    char msg[256];
    logf(msg, "[detector] report exported to: %s\n",
        filename ? filename : "c:\\detect.txt");
}

BOOL APIENTRY DllMain(HMODULE hmodule, DWORD ul_reason_for_call, LPVOID lpreserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hmodule);
        log("[detector] dll_process_attach\n");
        break;

    case DLL_PROCESS_DETACH:
        if (g_detector) {
            delete g_detector;
            g_detector = nullptr;
        }

        LONG total = InterlockedCompareExchange(&g_totaldetections, 0, 0);
        LONG count = InterlockedCompareExchange(&g_eventcount, 0, 0);

        char buf[256];
        logf(buf, "[detector] dll_process_detach - detections: %d, events: %d\n",
            total, min(count, (LONG)max_events));
        break;
    }
    return TRUE;
}