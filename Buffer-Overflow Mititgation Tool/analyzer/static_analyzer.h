#ifndef STATIC_ANALYZER_H
#define STATIC_ANALYZER_H

#include <string>
#include <vector>
#include <memory>

struct Vulnerability {
    std::string type;
    std::string details;
    int line_number;
    std::string severity;
    std::string suggested_fix;
    
    Vulnerability() : line_number(0) {}
    Vulnerability(const std::string& t, const std::string& d, int ln, const std::string& s, const std::string& sf = "")
        : type(t), details(d), line_number(ln), severity(s), suggested_fix(sf) {}
};

class StaticAnalyzer {
public:
    StaticAnalyzer();
    ~StaticAnalyzer();

    bool initialize();
    std::vector<Vulnerability> analyze(const std::string& code);

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
    
    std::string getSuggestedFix(const std::string& function);
    void analyzeCrossFunctionVulnerabilities(const std::string& code, std::vector<Vulnerability>& vulnerabilities);
};

#endif // STATIC_ANALYZER_H
