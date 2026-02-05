#ifndef SHADOW_STACK_H
#define SHADOW_STACK_H
#include <memory>
#include <vector>
#include <string>

struct Vulnerability;  // Forward declaration

class ShadowStack {
public:
    ShadowStack();
    ~ShadowStack();

    bool initialize();
    void pushReturnAddress(void* address);  // Existing method
    bool validateReturnAddress(void* address);  // Existing method
    std::vector<Vulnerability> verifyStackProtection(const std::string& executable_path);  // New method

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

#endif // SHADOW_STACK_H