#ifndef MEMORY_ALLOCATOR_H
#define MEMORY_ALLOCATOR_H

#include <cstddef>

class MemoryAllocator {
public:
    MemoryAllocator();
    ~MemoryAllocator();

    // Allocate memory with tracking
    void* allocate(size_t size);

    // Free allocated memory
    void deallocate(void* ptr);

private:
    // Could track allocations if needed
};

#endif // MEMORY_ALLOCATOR_H