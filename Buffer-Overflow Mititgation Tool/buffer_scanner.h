#ifndef BUFFER_SCANNER_H
#define BUFFER_SCANNER_H
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

struct Vulnerability;  // Forward declaration

class BufferScanner {
public:
    BufferScanner();
    ~BufferScanner();

    bool initialize();
    bool scanBuffer(void* buffer, size_t bufferSize, size_t accessSize);
    std::vector<Vulnerability> scanExecutable(const std::string& executable_path);

private:
    struct Impl;  // Forward declaration only
    std::unique_ptr<Impl> pImpl;
};

#endif // BUFFER_SCANNER_H