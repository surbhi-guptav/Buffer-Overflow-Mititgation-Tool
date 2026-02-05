#ifndef RUNTIME_PROTECTOR_H
#define RUNTIME_PROTECTOR_H

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#elif defined(__linux__)
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <unistd.h>
#include <signal.h>
#elif defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

struct MemoryRegion {
    void* start;
    size_t size;
    int permissions;
    bool is_executable;
    bool is_writable;
    bool is_readable;
    
    MemoryRegion() : start(nullptr), size(0), permissions(0), 
                     is_executable(false), is_writable(false), is_readable(false) {}
};

struct SecurityViolation {
    std::string type;
    std::string details;
    void* address;
    size_t size;
    std::string severity;
    
    SecurityViolation() : address(nullptr), size(0) {}
    SecurityViolation(const std::string& t, const std::string& d, void* addr, size_t sz, const std::string& s)
        : type(t), details(d), address(addr), size(sz), severity(s) {}
};

class RuntimeProtector {
public:
    RuntimeProtector();
    ~RuntimeProtector();

    bool initialize();
    bool enableASLR();
    bool enableDEP();
    bool enableStackCanaries();
    bool enableControlFlowIntegrity();
    bool enableMemoryProtection();
    bool enableSeccomp();
    
    void* allocateProtectedMemory(size_t size, int permissions = PROT_READ | PROT_WRITE);
    bool freeProtectedMemory(void* ptr);
    bool changeMemoryPermissions(void* ptr, size_t size, int permissions);
    
    bool validateMemoryAccess(void* ptr, size_t size, int access_type);
    bool validateStackAccess(void* ptr, size_t size);
    bool validateHeapAccess(void* ptr, size_t size);
    
    std::vector<SecurityViolation> getViolations() const;
    void clearViolations();
    
    void setViolationCallback(std::function<void(const SecurityViolation&)> callback);
    
    // Advanced protection features
    bool enableAddressSanitizer();
    bool enableThreadSanitizer();
    bool enableUndefinedBehaviorSanitizer();
    bool enableMemorySanitizer();
    
    // Memory layout analysis
    std::vector<MemoryRegion> getMemoryLayout();
    bool isAddressExecutable(void* addr);
    bool isAddressWritable(void* addr);
    
    // Stack protection
    bool enableStackGuard();
    bool validateReturnAddress(void* ret_addr);
    
    // Heap protection
    bool enableHeapGuard();
    bool validateHeapIntegrity();

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
    
    void recordViolation(const std::string& type, const std::string& details, 
                        void* address, size_t size, const std::string& severity);
    
#ifdef _WIN32
    bool setupWindowsProtection();
    bool enableWindowsDEP();
    bool enableWindowsASLR();
#elif defined(__linux__)
    bool setupLinuxProtection();
    bool enableLinuxASLR();
    bool enableLinuxSeccomp();
    static void signalHandler(int sig, siginfo_t* info, void* context);
#elif defined(__APPLE__)
    bool setupMacOSProtection();
    bool enableMacOSASLR();
#endif
};

#endif // RUNTIME_PROTECTOR_H
