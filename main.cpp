/**
 * @file main.cpp
 * @author Hud (https://github.com/Hudzilla123)
 * @brief Basic DLL
 * @version 0.1
 * @date 2022-10-16
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

// Get Process ID by looping thru snapshot of loaded processes
DWORD GetProcId(const char* procName)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Gets process list

    // Checks if hSnap is a good Snapshot (not null or invalid (-1))
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry; // create Proc entry
        procEntry.dwSize = sizeof(procEntry); // size of struct in bytes

        if (Process32First(hSnap, &procEntry)) // receive each Proc entry from the Snapshot
        {
            // loop through Proc entries
            do
            {
                // compare name (insensitive, does not care about caps) of executable file  to process name
                if (!_stricmp(reinterpret_cast<const char*>(procEntry.szExeFile), procName)) 
                {
                    procId = procEntry.th32ProcessID; // grab process id when we find it, break, and return
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap); // destroys handle
    return procId;
}

int main()
{
    const char* dllPath = "C:\\Users\\me\\Desktop\\dll.dll"; // individual path
    const char* procName = "RobloxPlayer.exe"; // example process
    DWORD procId = 0;

    while (!procId) // while the procId is not found
    {
        procId = GetProcId(procName); // get process ID of our process name

        std::string displayProcessId = "Process Injecting...";
        LPCWSTR display = reinterpret_cast<LPCWSTR>(&displayProcessId);
        MessageBox(NULL, reinterpret_cast<LPCWSTR>(&procId), display, MB_OK); // Display Process ID for example
        Sleep(30); // sleep for 30 milliseconds
    }

    /**
     * @brief 
     * Opens existing local process object
     * Params: 
            [1] access to process object checked against security descriptor for object
            [2] BOOL value : if TRUE (1), processes created by this process will inherit the handle.
                if FALSE (0), processes do not inherit the handle
            [3] identifier of local process to be opened
     * Returns: open handle to specified process (if success), otherwise null
     */

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

    // Check to make sure process is good
    if (hProc && hProc != INVALID_HANDLE_VALUE)
    {
        /**
         * @brief 
         * VirtualAllocEx() reserves, commits, or changes the state of a region of memory
         * within the virtual address space of a specified process.
         * Initializes the memory it allocates to 0.
         * Params:
         * [1] hProcess : handle to a process, function allocates memory within virtual address
         * space of this process. Must have PROCESS_VM_OPERATION access right.
         * [2] (optional) lpAddress : pointer that specifies a desired starting address for the region
         * of pages you want to allocate. If reserving memory, function allocates down to the nearest
         * multiple of allocation granularity. If committing memory that is already reserved, function
         * rounds this address down to the nearest page boundary (can use GetSystemInfo to determine size of page
         * and allocation granularity on host computer). If NULL, function determines where to allocate region.
         * There are more situations that will not be covered here. 
         * [3] dwSize : Size of the region of memory to allocate, in bytes. If NULL, rounds dwSize up to the next page
         * boundary. If not NULL, allocates all pages containing one or more bytes in the range from lpAddress to 
         * lpAddress + dwSize. 
         * [4] Allocation type (can research diff constants)
         * [5] flProtect : Memory protection for the region of pages to be allocated. When allocating dynamic memory,
         * flProtect must be PAGE_READWRITE or PAGE_EXECUTE_READWRITE.
         * Returns: base address of allocated region of pages (if success), NULL (if failure)
         */
        // allocates memory in external process via handle and size of memory
        // MAX_PATH : longest length for a string that represents path
        void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 

        /**
         * @brief 
         * WriteProcessMemory() writes data to an area of memory in a specified process. Entire area to be written
         * to must be accessible or the operation fails.
         * Params:
         * [1] hProcess : handle to the process memory to be modified. Handle must have PROCESS_VM_WRITE and 
         * PROCESS_VM_OPERATION access to the process.
         * [2] lpBaseAddress : A pointer to the base address in the specified process to which data is written. 
         * Before data transfer occurs, the system verifies that all data in the base address and memory of the
         * specified size is accessible for write access, and if it is not accessible, the function fails.
         * [3] nSize : The number of bytes to be written to the specified process.
         * [4] (optional) lpNumberOfBytesWritten : A pointer to a variable that receives the number of bytes transferred
         * into the specified process. If NULL, ignored.
         * Returns: nonzero if successful, zero if fail
         */
        // Write the path to memory and put the path in memory 
        // because we create a remote thread in the target process that calls LoadLibraryA with loc as parameter (path to DLL)
        if (loc)
        {
            WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0);
        }

        /**
         * @brief 
         * CreateRemoteThread() creates a thread that runs in the virtual address space of another process.
         * (To create a thread that runs in the virtual address space of another process, use CreateRemoteThreadEx())
         * Params:
         * [1] hProcess : handle to the process in which the thread is to be created. Must have PROCESS_CREATE_THREAD,
         * PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, and PROCESS_VM_READ access rights (may fail without)
         * [2] lpThreadAttributes : pointer to a SECURITY_ATTRIBUTES structure that specifies security descriptor for new thread
         * and determines whether child processes an inherit the returned handle. If NULL, thread gets default security descriptor
         * and handle cannot be inherited. 
         * [3] dwStackSize : initial size of the stack, in bytes. System rounds this value to the nearest page. If 0 (zero), new thread uses 
         * default size for the executable.
         * [4] lpStartAddress : pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed by the thread and
         * represents the starting address of the thread in the remote process. Function must exist in the remote process.
         * [5] lpParameter : pointer to a variable to be passed to the thread function
         * [6] dwCreationFlags : flags that control the creation of the thread
         * [7] lpThreadId : pointer to a variable that receives the thread identifier. If NULL, thread identifier is not returned.
         * Returns: handle to new thread (success), NULL (failure)
         */
        // Causes new thread of execution to begin in the address space of the specified process, having access to all objects
        // that the process opens. 
        // LoadLibraryA loads specified module into the address space of the caling process, may cause other modules to be loaded.
        // Returns a handle to the module (success) or NULL (failure)
        // Used to load a library module into the address space of the process and return a handle that can be used in GetProcAddress()
        // to get the address of a DLL function. Can also be used to load other executable modules
        HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);

        if (hThread)
        {
            CloseHandle(hThread); // close thread
        }
    }

    if (hProc)
    {
        CloseHandle(hProc); // close process handle
    }

    return 0;
}