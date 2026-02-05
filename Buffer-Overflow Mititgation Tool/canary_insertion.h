
#pragma once
#include <string>
#include <vector>
#include <memory>

namespace MitigatorComponent {

// Add your declarations here

class canary_insertion {
public:
    canary_insertion();
    ~canary_insertion();

    bool initialize();

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace MitigatorComponent
