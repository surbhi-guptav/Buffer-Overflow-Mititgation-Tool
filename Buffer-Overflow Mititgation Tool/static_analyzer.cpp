#include "analyzer/static_analyzer.h"
#include "utils/logger.h"
#include <algorithm>
#include <sstream>
#include <regex>
#include <unordered_set>
#include <fstream>

StaticAnalyzer::StaticAnalyzer() : pImpl(std::make_unique<Impl>()) {
    pImpl->unsafeFunctions = {
        "strcpy", "gets", "sprintf", "strcat", "scanf", "fscanf", "sscanf",
        "vsprintf", "vsnprintf", "strncpy", "strncat", "snprintf"
    };
    
    pImpl->unsafeCppPatterns = {
        "std::copy", "std::memcpy", "std::memmove", "std::memset"
    };
    
    pImpl->sqlInjectionPatterns = {
        "SELECT.*WHERE.*\\+", "INSERT.*VALUES.*\\+", "UPDATE.*SET.*\\+",
        "DELETE.*WHERE.*\\+", "EXEC.*\\+", "EXECUTE.*\\+"
    };
    
    pImpl->xssPatterns = {
        "innerHTML.*\\+", "document\\.write.*\\+", "eval\\(.*\\+",
        "setTimeout.*\\+", "setInterval.*\\+"
    };
}

StaticAnalyzer::~StaticAnalyzer() = default;

bool StaticAnalyzer::initialize() {
    if (pImpl->initialized) {
        Logger::log("StaticAnalyzer already initialized");
        return true;
    }
    pImpl->initialized = true;
    Logger::log("StaticAnalyzer initialized with enhanced patterns");
    return true;
}

std::vector<Vulnerability> StaticAnalyzer::analyze(const std::string& code) {
    if (!pImpl->initialized) {
        Logger::log("StaticAnalyzer not initialized, initializing now");
        initialize();
    }

    std::vector<Vulnerability> vulnerabilities;
    std::istringstream stream(code);
    std::string line;
    int line_number = 0;
    std::unordered_set<std::string> functions;
    std::unordered_set<std::string> variables;

    std::regex unsafe_funcs("(gets|strcpy|strcat|sprintf|scanf|fscanf|sscanf|vsprintf|vsnprintf|strncpy|strncat|snprintf)\\s*\\(");
    std::regex format_string("(printf|fprintf|sprintf|snprintf|vsprintf|vsnprintf)\\s*\\(\\s*[^\"]*[^)]*\\)");
    std::regex uninit_var("\\b(int|char|float|double|long|short|unsigned)\\s+\\w+\\s*;");
    std::regex new_no_delete("\\bnew\\s+\\w+\\s*\\[[^]]+\\]");
    std::regex recursion("\\b\\w+\\s*\\(\\s*\\w+\\s*\\+\\s*\\d+\\s*\\)");
    std::regex null_deref("\\*\\s*\\w+\\s*;");
    std::regex getenv_no_check("getenv\\s*\\(\\s*\"[^\"]+\"\\s*\\)");
    std::regex infinite_loop("while\\s*\\(\\s*true\\s*\\)|for\\s*\\(\\s*;\\s*;\\s*\\)");
    std::regex sql_injection("(SELECT|INSERT|UPDATE|DELETE|EXEC|EXECUTE)\\s+.*\\+.*\\w+");
    std::regex xss_pattern("(innerHTML|document\\.write|eval|setTimeout|setInterval)\\s*=\\s*.*\\+");
    std::regex command_injection("(system|popen|exec|execl|execlp|execle|execv|execvp|execvpe)\\s*\\(");
    std::regex path_traversal("(\\.\\./|\\.\\\\|%2e%2e%2f|%2e%2e%5c)");
    std::regex integer_overflow("\\b\\w+\\s*\\+\\s*\\w+\\s*[<>]");
    std::regex use_after_free("delete\\s+\\w+\\s*;\\s*\\w+\\s*\\.");
    std::regex double_free("delete\\s+\\w+\\s*;\\s*delete\\s+\\w+\\s*;");
    std::regex race_condition("\\b\\w+\\s*=\\s*\\w+\\s*\\+\\s*1\\s*;");
    std::regex weak_crypto("(md5|sha1|des|rc4)\\s*\\(");
    std::regex hardcoded_secrets("(password|secret|key|token)\\s*=\\s*\"[^\"]+\"");
    std::regex unsafe_random("rand\\(\\)|random\\(\\)");
    std::regex buffer_overflow_risk("\\w+\\[\\w+\\+\\d+\\]\\s*=");
    std::regex stack_overflow_risk("char\\s+\\w+\\[\\d{4,}\\]");

    while (std::getline(stream, line)) {
        line_number++;
        std::string trimmed_line = line;
        trimmed_line.erase(0, trimmed_line.find_first_not_of(" \t"));
        if (trimmed_line.empty() || trimmed_line[0] == '#') continue;

        for (const auto& func : pImpl->unsafeFunctions) {
            if (line.find(func) != std::string::npos) {
                Vulnerability vuln;
                vuln.type = (func == "strcpy" || func == "strcat" || func == "strncpy" || func == "strncat") ? "buffer_overflow" : 
                            (func == "gets" || func == "scanf" || func == "fscanf" || func == "sscanf") ? "input_vulnerability" : 
                            (func == "sprintf" || func == "vsprintf" || func == "snprintf" || func == "vsnprintf") ? "format_string" : "unsafe_function";
                vuln.details = "Use of unsafe function " + func + " - consider using safer alternatives";
                vuln.line_number = line_number;
                vuln.severity = (func == "gets" || func == "scanf") ? "critical" : 
                               (func == "strcpy" || func == "sprintf") ? "high" : "medium";
                vuln.suggested_fix = getSuggestedFix(func);
                vulnerabilities.push_back(vuln);
                Logger::log("Detected unsafe function: " + func + " at line " + std::to_string(line_number));
            }
        }

        if (std::regex_search(line, unsafe_funcs)) {
            vulnerabilities.push_back({"input_vulnerability", "Use of unsafe function detected", line_number, "high", "Replace with bounds-checked alternatives"});
        }
        if (std::regex_search(line, format_string)) {
            vulnerabilities.push_back({"format_string", "Uncontrolled format string - potential format string attack", line_number, "high", "Use format string validation or safer alternatives"});
        }
        if (std::regex_search(line, uninit_var) && line.find("=") == std::string::npos) {
            vulnerabilities.push_back({"uninitialized_variable", "Variable declared without initialization", line_number, "medium", "Initialize variables before use"});
        }
        if (std::regex_search(line, new_no_delete)) {
            vulnerabilities.push_back({"memory_leak", "Dynamic allocation without corresponding deallocation", line_number, "medium", "Use smart pointers or ensure proper cleanup"});
        }
        if (std::regex_search(line, recursion)) {
            vulnerabilities.push_back({"stack_overflow", "Possible infinite recursion detected", line_number, "high", "Add recursion depth limits or use iteration"});
        }
        if (std::regex_search(line, null_deref) && line.find("NULL") != std::string::npos) {
            vulnerabilities.push_back({"null_pointer", "Potential null pointer dereference", line_number, "high", "Add null pointer checks before dereferencing"});
        }
        if (std::regex_search(line, getenv_no_check)) {
            vulnerabilities.push_back({"env_vulnerability", "Unsafe environment variable access without NULL check", line_number, "medium", "Check return value for NULL before use"});
        }
        if (std::regex_search(line, infinite_loop)) {
            vulnerabilities.push_back({"infinite_loop", "Potential denial of service from infinite loop", line_number, "high", "Add loop termination conditions"});
        }
        if (std::regex_search(line, sql_injection)) {
            vulnerabilities.push_back({"sql_injection", "Potential SQL injection vulnerability", line_number, "critical", "Use parameterized queries or input validation"});
        }
        if (std::regex_search(line, xss_pattern)) {
            vulnerabilities.push_back({"xss", "Potential Cross-Site Scripting vulnerability", line_number, "critical", "Sanitize user input and use safe DOM methods"});
        }
        if (std::regex_search(line, command_injection)) {
            vulnerabilities.push_back({"command_injection", "Potential command injection vulnerability", line_number, "critical", "Avoid command execution or use safe alternatives"});
        }
        if (std::regex_search(line, path_traversal)) {
            vulnerabilities.push_back({"path_traversal", "Potential path traversal vulnerability", line_number, "high", "Validate and sanitize file paths"});
        }
        if (std::regex_search(line, integer_overflow)) {
            vulnerabilities.push_back({"integer_overflow", "Potential integer overflow", line_number, "medium", "Use checked arithmetic operations"});
        }
        if (std::regex_search(line, use_after_free)) {
            vulnerabilities.push_back({"use_after_free", "Potential use-after-free vulnerability", line_number, "high", "Set pointer to nullptr after deletion"});
        }
        if (std::regex_search(line, double_free)) {
            vulnerabilities.push_back({"double_free", "Potential double-free vulnerability", line_number, "high", "Set pointer to nullptr after deletion"});
        }
        if (std::regex_search(line, race_condition)) {
            vulnerabilities.push_back({"race_condition", "Potential race condition", line_number, "medium", "Use synchronization primitives"});
        }
        if (std::regex_search(line, weak_crypto)) {
            vulnerabilities.push_back({"weak_cryptography", "Use of weak cryptographic algorithm", line_number, "high", "Use modern cryptographic algorithms (AES, SHA-256, etc.)"});
        }
        if (std::regex_search(line, hardcoded_secrets)) {
            vulnerabilities.push_back({"hardcoded_secret", "Hardcoded secret detected", line_number, "high", "Use environment variables or secure key management"});
        }
        if (std::regex_search(line, unsafe_random)) {
            vulnerabilities.push_back({"weak_random", "Use of weak random number generator", line_number, "medium", "Use cryptographically secure random generators"});
        }
        if (std::regex_search(line, buffer_overflow_risk)) {
            vulnerabilities.push_back({"buffer_overflow_risk", "Potential buffer overflow risk", line_number, "high", "Add bounds checking before array access"});
        }
        if (std::regex_search(line, stack_overflow_risk)) {
            vulnerabilities.push_back({"stack_overflow_risk", "Large stack allocation detected", line_number, "medium", "Consider heap allocation for large buffers"});
        }
    }

    analyzeCrossFunctionVulnerabilities(code, vulnerabilities);

    if (vulnerabilities.empty()) {
        Logger::log("No vulnerabilities found in code");
    } else {
        Logger::log("Found " + std::to_string(vulnerabilities.size()) + " vulnerabilities");
    }
    return vulnerabilities;
}

std::string StaticAnalyzer::getSuggestedFix(const std::string& function) {
    static std::unordered_map<std::string, std::string> fixes = {
        {"strcpy", "Use strncpy with proper bounds checking or std::string"},
        {"strcat", "Use strncat with proper bounds checking or std::string::append"},
        {"gets", "Use fgets with buffer size limit or std::getline"},
        {"sprintf", "Use snprintf with buffer size limit or std::format (C++20)"},
        {"scanf", "Use fgets + sscanf or std::cin with validation"},
        {"strncpy", "Use std::string or ensure null termination"},
        {"strncat", "Use std::string::append or ensure null termination"},
        {"snprintf", "Use std::format (C++20) or ensure proper buffer sizing"},
        {"vsprintf", "Use vsnprintf with buffer size limit"},
        {"vsnprintf", "Use std::format (C++20) or ensure proper buffer sizing"},
        {"fscanf", "Use std::cin with validation or fgets + parsing"},
        {"sscanf", "Use std::stringstream or manual parsing with validation"}
    };
    
    auto it = fixes.find(function);
    return it != fixes.end() ? it->second : "Use bounds-checked alternatives";
}

void StaticAnalyzer::analyzeCrossFunctionVulnerabilities(const std::string& code, std::vector<Vulnerability>& vulnerabilities) {
    std::regex function_def("\\b\\w+\\s+\\w+\\s*\\([^)]*\\)\\s*\\{");
    std::regex return_stmt("return\\s+\\w+\\s*;");
    
    std::istringstream stream(code);
    std::string line;
    int line_number = 0;
    std::string current_function = "global";
    
    while (std::getline(stream, line)) {
        line_number++;
        
        if (std::regex_search(line, function_def)) {
            std::smatch match;
            if (std::regex_search(line, match, std::regex("\\b(\\w+)\\s*\\([^)]*\\)"))) {
                current_function = match[1];
            }
        }
        
        if (std::regex_search(line, std::regex("\\bint\\s+\\w+\\s*\\(")) && 
            current_function != "global" && 
            code.find("return", line.find("{")) == std::string::npos) {
            vulnerabilities.push_back({
                "missing_return", 
                "Function " + current_function + " may not return a value", 
                line_number, 
                "medium",
                "Add return statement or change return type to void"
            });
        }
    }
}
