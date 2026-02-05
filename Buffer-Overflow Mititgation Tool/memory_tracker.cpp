#include "analyzer/memory_tracker.h"
#include "utils/logger.h"

MemoryTracker::MemoryTracker() {}

MemoryTracker::~MemoryTracker() {}

void MemoryTracker::registerAllocation(void* ptr, size_t size) {
    allocations[ptr] = size;
    Logger::log("Registered allocation at " + std::to_string(reinterpret_cast<uintptr_t>(ptr)) + 
                " with size " + std::to_string(size));
}

bool MemoryTracker::isValidAccess(void* ptr, size_t size) {
    auto it = allocations.find(ptr);
    if (it == allocations.end()) {
        Logger::log("Access to unregistered memory at " + std::to_string(reinterpret_cast<uintptr_t>(ptr)));
        return false;
    }
    if (size > it->second) {
        Logger::log("Access exceeds allocation size at " + std::to_string(reinterpret_cast<uintptr_t>(ptr)));
        return false;
    }
    Logger::log("Valid access to " + std::to_string(reinterpret_cast<uintptr_t>(ptr)));
    return true;
}