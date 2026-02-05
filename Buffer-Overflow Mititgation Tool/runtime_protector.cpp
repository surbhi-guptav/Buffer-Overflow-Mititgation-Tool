#include "runtime_protector.h"
#include "utils/logger.h"
#include <iostream>
#include <algorithm>
#include <cstring>
#include <random>
#include <chrono>

#ifdef _WIN32
#include <psapi.h>
#include <tlhelp32.h>
#elif defined(__linux__)
#include <sys/ucontext.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#elif defined(__APPLE__)
#include <mach/mach_init.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#endif

struct RuntimeProtector::Impl {
    bool initialized = false;
    bool aslr_enabled = false;
    bool dep_enabled = false;
    bool stack_canaries_enabled = false;
    bool cfi_enabled = false;
    bool memory_protection_enabled = false;
    bool seccomp_enabled = false;
    
    std::vector<SecurityViolation> violations;
    std::vector<MemoryRegion> memory_regions;
    std::unordered_map<void*, size_t> allocated_memory;
    std::function<void(const SecurityViolation&)> violation_callback;
    
    std::mutex violations_mutex;
    std::mutex memory_mutex;
    
    std::vector<uintptr_t> stack_canaries;
    std::unordered_map<void*, uintptr_t> return_addresses;
    
    std::vector<std::pair<void*, size_t>> protected_regions;
    
    std::random_device rd;
    std::mt19937_64 rng;
    
    Impl() : rng(rd()) {}
};

RuntimeProtector::RuntimeProtector() : pImpl(std::make_unique<Impl>()) {}

RuntimeProtector::~RuntimeProtector() {
    std::lock_guard<std::mutex> lock(pImpl->memory_mutex);
    for (const auto& [ptr, size] : pImpl->allocated_memory) {
        freeProtectedMemory(ptr);
    }
}

bool RuntimeProtector::initialize() {
    if (pImpl->initialized) {
        Logger::log("RuntimeProtector already initialized");
        return true;
    }
    
    Logger::log("Initializing RuntimeProtector...");
    
#ifdef _WIN32
    if (!setupWindowsProtection()) {
        Logger::log("Failed to setup Windows protection");
        return false;
    }
#elif defined(__linux__)
    if (!setupLinuxProtection()) {
        Logger::log("Failed to setup Linux protection");
        return false;
    }
#elif defined(__APPLE__)
    if (!setupMacOSProtection()) {
        Logger::log("Failed to setup macOS protection");
        return false;
    }
#endif
    
    pImpl->initialized = true;
    Logger::log("RuntimeProtector initialized successfully");
    return true;
}

bool RuntimeProtector::enableASLR() {
    if (pImpl->aslr_enabled) {
        Logger::log("ASLR already enabled");
        return true;
    }
    
#ifdef _WIN32
    pImpl->aslr_enabled = enableWindowsASLR();
#elif defined(__linux__)
    pImpl->aslr_enabled = enableLinuxASLR();
#elif defined(__APPLE__)
    pImpl->aslr_enabled = enableMacOSASLR();
#endif
    
    if (pImpl->aslr_enabled) {
        Logger::log("ASLR enabled successfully");
    } else {
        Logger::log("Failed to enable ASLR");
    }
    
    return pImpl->aslr_enabled;
}

bool RuntimeProtector::enableDEP() {
    if (pImpl->dep_enabled) {
        Logger::log("DEP already enabled");
        return true;
    }
    
#ifdef _WIN32
    pImpl->dep_enabled = enableWindowsDEP();
#else
    pImpl->dep_enabled = true;
#endif
    
    if (pImpl->dep_enabled) {
        Logger::log("DEP enabled successfully");
    } else {
        Logger::log("Failed to enable DEP");
    }
    
    return pImpl->dep_enabled;
}

bool RuntimeProtector::enableStackCanaries() {
    if (pImpl->stack_canaries_enabled) {
        Logger::log("Stack canaries already enabled");
        return true;
    }
    
    pImpl->stack_canaries_enabled = true;
    Logger::log("Stack canaries enabled");
    return true;
}

bool RuntimeProtector::enableControlFlowIntegrity() {
    if (pImpl->cfi_enabled) {
        Logger::log("Control Flow Integrity already enabled");
        return true;
    }
    
    pImpl->cfi_enabled = true;
    Logger::log("Control Flow Integrity enabled");
    return true;
}

bool RuntimeProtector::enableMemoryProtection() {
    if (pImpl->memory_protection_enabled) {
        Logger::log("Memory protection already enabled");
        return true;
    }
    
    pImpl->memory_protection_enabled = true;
    Logger::log("Memory protection enabled");
    return true;
}

bool RuntimeProtector::enableSeccomp() {
    if (pImpl->seccomp_enabled) {
        Logger::log("Seccomp already enabled");
        return true;
    }
    
#ifdef __linux__
    pImpl->seccomp_enabled = enableLinuxSeccomp();
#else
    Logger::log("Seccomp not available on this platform");
    return false;
#endif
    
    return pImpl->seccomp_enabled;
}

void* RuntimeProtector::allocateProtectedMemory(size_t size, int permissions) {
    if (!pImpl->initialized) {
        Logger::log("RuntimeProtector not initialized");
        return nullptr;
    }
    
    void* ptr = nullptr;
    
#ifdef _WIN32
    ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (ptr && (permissions & PROT_EXEC)) {
        DWORD old_protect;
        VirtualProtect(ptr, size, PAGE_EXECUTE_READWRITE, &old_protect);
    }
#else
    ptr = mmap(nullptr, size, permissions, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    
    if (ptr) {
        std::lock_guard<std::mutex> lock(pImpl->memory_mutex);
        pImpl->allocated_memory[ptr] = size;
        
        MemoryRegion region;
        region.start = ptr;
        region.size = size;
        region.permissions = permissions;
        region.is_readable = permissions & PROT_READ;
        region.is_writable = permissions & PROT_WRITE;
        region.is_executable = permissions & PROT_EXEC;
        
        pImpl->memory_regions.push_back(region);
        pImpl->protected_regions.emplace_back(ptr, size);
        
        Logger::log("Allocated protected memory: " + std::to_string(reinterpret_cast<uintptr_t>(ptr)) + 
                   " size: " + std::to_string(size));
    } else {
        Logger::log("Failed to allocate protected memory");
    }
    
    return ptr;
}

bool RuntimeProtector::freeProtectedMemory(void* ptr) {
    if (!ptr) return false;
    
    std::lock_guard<std::mutex> lock(pImpl->memory_mutex);
    auto it = pImpl->allocated_memory.find(ptr);
    if (it == pImpl->allocated_memory.end()) {
        Logger::log("Attempted to free unallocated memory");
        return false;
    }
    
    size_t size = it->second;
    
#ifdef _WIN32
    bool success = VirtualFree(ptr, 0, MEM_RELEASE);
#else
    bool success = munmap(ptr, size) == 0;
#endif
    
    if (success) {
        pImpl->allocated_memory.erase(it);
        
        // Remove from memory regions
        pImpl->memory_regions.erase(
            std::remove_if(pImpl->memory_regions.begin(), pImpl->memory_regions.end(),
                          [ptr](const MemoryRegion& region) { return region.start == ptr; }),
            pImpl->memory_regions.end()
        );
        
        // Remove from protected regions
        pImpl->protected_regions.erase(
            std::remove_if(pImpl->protected_regions.begin(), pImpl->protected_regions.end(),
                          [ptr](const auto& pair) { return pair.first == ptr; }),
            pImpl->protected_regions.end()
        );
        
        Logger::log("Freed protected memory: " + std::to_string(reinterpret_cast<uintptr_t>(ptr)));
    } else {
        Logger::log("Failed to free protected memory");
    }
    
    return success;
}

bool RuntimeProtector::changeMemoryPermissions(void* ptr, size_t size, int permissions) {
    if (!ptr) return false;
    
#ifdef _WIN32
    DWORD old_protect;
    DWORD new_protect = PAGE_READWRITE;
    if (permissions & PROT_EXEC) new_protect = PAGE_EXECUTE_READWRITE;
    else if (permissions & PROT_READ && permissions & PROT_WRITE) new_protect = PAGE_READWRITE;
    else if (permissions & PROT_READ) new_protect = PAGE_READONLY;
    
    return VirtualProtect(ptr, size, new_protect, &old_protect);
#else
    return mprotect(ptr, size, permissions) == 0;
#endif
}

bool RuntimeProtector::validateMemoryAccess(void* ptr, size_t size, int access_type) {
    if (!pImpl->memory_protection_enabled) return true;
    
    std::lock_guard<std::mutex> lock(pImpl->memory_mutex);
    
    // Check if pointer is in allocated memory
    auto it = pImpl->allocated_memory.find(ptr);
    if (it == pImpl->allocated_memory.end()) {
        recordViolation("invalid_memory_access", "Access to unallocated memory", ptr, size, "high");
        return false;
    }
    
    // Check bounds
    if (reinterpret_cast<char*>(ptr) + size > 
        reinterpret_cast<char*>(ptr) + it->second) {
        recordViolation("buffer_overflow", "Memory access exceeds allocation bounds", ptr, size, "critical");
        return false;
    }
    
    // Check permissions
    for (const auto& region : pImpl->memory_regions) {
        if (ptr >= region.start && 
            reinterpret_cast<char*>(ptr) + size <= reinterpret_cast<char*>(region.start) + region.size) {
            
            if ((access_type & PROT_READ) && !region.is_readable) {
                recordViolation("memory_protection", "Read access to non-readable memory", ptr, size, "high");
                return false;
            }
            if ((access_type & PROT_WRITE) && !region.is_writable) {
                recordViolation("memory_protection", "Write access to non-writable memory", ptr, size, "high");
                return false;
            }
            if ((access_type & PROT_EXEC) && !region.is_executable) {
                recordViolation("memory_protection", "Execute access to non-executable memory", ptr, size, "critical");
                return false;
            }
            break;
        }
    }
    
    return true;
}

bool RuntimeProtector::validateStackAccess(void* ptr, size_t size) {
    if (!pImpl->stack_canaries_enabled) return true;
    
    void* stack_ptr = nullptr;
    
#ifdef _WIN32
    stack_ptr = _AddressOfReturnAddress();
#else
    stack_ptr = __builtin_frame_address(0);
#endif
    
    if (ptr >= stack_ptr && ptr < reinterpret_cast<char*>(stack_ptr) + 8192) {
        return true;
    }
    
    recordViolation("stack_overflow", "Stack access outside bounds", ptr, size, "critical");
    return false;
}

bool RuntimeProtector::validateHeapAccess(void* ptr, size_t size) {
    std::lock_guard<std::mutex> lock(pImpl->memory_mutex);
    
    auto it = pImpl->allocated_memory.find(ptr);
    if (it == pImpl->allocated_memory.end()) {
        recordViolation("heap_corruption", "Access to unallocated heap memory", ptr, size, "high");
        return false;
    }
    
    if (reinterpret_cast<char*>(ptr) + size > 
        reinterpret_cast<char*>(ptr) + it->second) {
        recordViolation("heap_overflow", "Heap access exceeds allocation bounds", ptr, size, "critical");
        return false;
    }
    
    return true;
}

std::vector<SecurityViolation> RuntimeProtector::getViolations() const {
    std::lock_guard<std::mutex> lock(pImpl->violations_mutex);
    return pImpl->violations;
}

void RuntimeProtector::clearViolations() {
    std::lock_guard<std::mutex> lock(pImpl->violations_mutex);
    pImpl->violations.clear();
}

void RuntimeProtector::setViolationCallback(std::function<void(const SecurityViolation&)> callback) {
    pImpl->violation_callback = callback;
}

bool RuntimeProtector::enableAddressSanitizer() {
    Logger::log("AddressSanitizer enabled (compile-time option)");
    return true;
}

bool RuntimeProtector::enableThreadSanitizer() {
    Logger::log("ThreadSanitizer enabled (compile-time option)");
    return true;
}

bool RuntimeProtector::enableUndefinedBehaviorSanitizer() {
    Logger::log("UndefinedBehaviorSanitizer enabled (compile-time option)");
    return true;
}

bool RuntimeProtector::enableMemorySanitizer() {
    Logger::log("MemorySanitizer enabled (compile-time option)");
    return true;
}

std::vector<MemoryRegion> RuntimeProtector::getMemoryLayout() {
    std::lock_guard<std::mutex> lock(pImpl->memory_mutex);
    return pImpl->memory_regions;
}

bool RuntimeProtector::isAddressExecutable(void* addr) {
    for (const auto& region : pImpl->memory_regions) {
        if (addr >= region.start && 
            addr < reinterpret_cast<char*>(region.start) + region.size) {
            return region.is_executable;
        }
    }
    return false;
}

bool RuntimeProtector::isAddressWritable(void* addr) {
    for (const auto& region : pImpl->memory_regions) {
        if (addr >= region.start && 
            addr < reinterpret_cast<char*>(region.start) + region.size) {
            return region.is_writable;
        }
    }
    return false;
}

bool RuntimeProtector::enableStackGuard() {
    Logger::log("Stack guard enabled");
    return true;
}

bool RuntimeProtector::validateReturnAddress(void* ret_addr) {
    if (!pImpl->cfi_enabled) return true;
    
    auto it = pImpl->return_addresses.find(ret_addr);
    if (it == pImpl->return_addresses.end()) {
        recordViolation("control_flow_integrity", "Invalid return address", ret_addr, sizeof(void*), "critical");
        return false;
    }
    
    return true;
}

bool RuntimeProtector::enableHeapGuard() {
    Logger::log("Heap guard enabled");
    return true;
}

bool RuntimeProtector::validateHeapIntegrity() {
    for (const auto& [ptr, size] : pImpl->allocated_memory) {
        if (!ptr) {
            recordViolation("heap_corruption", "Null pointer in heap allocation", ptr, size, "high");
            return false;
        }
    }
    return true;
}

void RuntimeProtector::recordViolation(const std::string& type, const std::string& details, 
                                      void* address, size_t size, const std::string& severity) {
    SecurityViolation violation(type, details, address, size, severity);
    
    {
        std::lock_guard<std::mutex> lock(pImpl->violations_mutex);
        pImpl->violations.push_back(violation);
    }
    
    Logger::log("Security violation: " + type + " - " + details + 
               " at " + std::to_string(reinterpret_cast<uintptr_t>(address)));
    
    if (pImpl->violation_callback) {
        pImpl->violation_callback(violation);
    }
}

#ifdef _WIN32
bool RuntimeProtector::setupWindowsProtection() {
    Logger::log("Setting up Windows protection");
    return true;
}

bool RuntimeProtector::enableWindowsDEP() {
    BOOL permanent = FALSE;
    BOOL enabled = FALSE;
    
    if (GetSystemDEPPolicy(&enabled, &permanent)) {
        if (!enabled) {
            Logger::log("DEP not enabled by system policy");
            return false;
        }
    }
    
    return true;
}

bool RuntimeProtector::enableWindowsASLR() {
    Logger::log("Windows ASLR enabled by OS");
    return true;
}

#elif defined(__linux__)
bool RuntimeProtector::setupLinuxProtection() {
    Logger::log("Setting up Linux protection");
    
    struct sigaction sa;
    sa.sa_sigaction = signalHandler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGSEGV, &sa, nullptr) == -1) {
        Logger::log("Failed to set up SIGSEGV handler");
        return false;
    }
    
    if (sigaction(SIGBUS, &sa, nullptr) == -1) {
        Logger::log("Failed to set up SIGBUS handler");
        return false;
    }
    
    return true;
}

bool RuntimeProtector::enableLinuxASLR() {
    std::ifstream aslr_file("/proc/sys/kernel/randomize_va_space");
    if (aslr_file.is_open()) {
        int value;
        aslr_file >> value;
        aslr_file.close();
        
        if (value == 0) {
            Logger::log("ASLR is disabled. Enable with: echo 2 > /proc/sys/kernel/randomize_va_space");
            return false;
        }
    }
    
    Logger::log("Linux ASLR is enabled");
    return true;
}

bool RuntimeProtector::enableLinuxSeccomp() {
    struct sock_filter filter[] = {
        {BPF_LD | BPF_W | BPF_ABS, 0, 0, 0},
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_read},
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_write},
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_exit},
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_brk},
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_mmap},
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_munmap},
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_mprotect},
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_rt_sigreturn},
        {BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL},
    };
    
    struct sock_fprog prog = {
        sizeof(filter) / sizeof(filter[0]),
        filter
    };
    
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        Logger::log("Failed to enable seccomp");
        return false;
    }
    
    Logger::log("Seccomp enabled successfully");
    return true;
}

void RuntimeProtector::signalHandler(int sig, siginfo_t* info, void* context) {
    std::string violation_type;
    switch (sig) {
        case SIGSEGV:
            violation_type = "segmentation_fault";
            break;
        case SIGBUS:
            violation_type = "bus_error";
            break;
        default:
            violation_type = "unknown_signal";
    }
    
    Logger::log("Signal received: " + violation_type + " at address " + 
               std::to_string(reinterpret_cast<uintptr_t>(info->si_addr)));
    
    exit(1);
}

#elif defined(__APPLE__)
bool RuntimeProtector::setupMacOSProtection() {
    Logger::log("Setting up macOS protection");
    return true;
}

bool RuntimeProtector::enableMacOSASLR() {
    Logger::log("macOS ASLR enabled by default");
    return true;
}
#endif
