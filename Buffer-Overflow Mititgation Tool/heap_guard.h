
#pragma once
#include <string>
#include <vector>
#include <memory>

namespace ScannerComponent {

// Add your declarations here

class heap_guard {
public:
    heap_guard();
    ~heap_guard();

    bool initialize();

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace ScannerComponent
