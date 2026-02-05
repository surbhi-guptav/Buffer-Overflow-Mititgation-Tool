
#pragma once
#include <string>
#include <vector>
#include <memory>

namespace UtilsComponent {

// Add your declarations here

class signal_handler {
public:
    signal_handler();
    ~signal_handler();

    bool initialize();

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace UtilsComponent
