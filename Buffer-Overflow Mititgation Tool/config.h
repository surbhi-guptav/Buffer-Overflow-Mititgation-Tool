
#pragma once
#include <string>
#include <vector>
#include <memory>

namespace UtilsComponent {

// Add your declarations here

class config {
public:
    config();
    ~config();

    bool initialize();

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace UtilsComponent
