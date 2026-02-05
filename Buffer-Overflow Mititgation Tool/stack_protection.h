
#pragma once
#include <string>
#include <vector>
#include <memory>

namespace ScannerComponent {

// Add your declarations here

class stack_protection {
public:
    stack_protection();
    ~stack_protection();

    bool initialize();

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace ScannerComponent
