
#pragma once
#include <string>
#include <vector>
#include <memory>

namespace MitigatorComponent {

// Add your declarations here

class boundary_checker {
public:
    boundary_checker();
    ~boundary_checker();

    bool initialize();

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace MitigatorComponent
