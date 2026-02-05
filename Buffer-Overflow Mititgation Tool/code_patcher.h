#ifndef CODE_PATCHER_H
#define CODE_PATCHER_H
#include <memory>
#include <string>
#include <vector>
#include "analyzer/static_analyzer.h"  // For Vulnerability

class CodePatcher {
public:
    CodePatcher();
    ~CodePatcher();

    bool initialize();
    void patchFunction(void* address, const std::string& instruction);

    struct Mitigation {
        Vulnerability vuln;
        std::string suggested_fix;
        std::string patched_code;
        double confidence;
        
        Mitigation() : confidence(0.0) {}
    };
    
    std::vector<Mitigation> suggestPatches(const std::vector<Vulnerability>& vulns);
    std::string generateSecureCodeTemplate();
    std::string applySecurityHeaders(const std::string& code);
    std::string generateCompilationFlags();

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
    
    std::string generateFix(const Vulnerability& vuln);
    std::string generatePatchedCode(const Vulnerability& vuln);
    double calculateConfidence(const Vulnerability& vuln);
};

#endif // CODE_PATCHER_H