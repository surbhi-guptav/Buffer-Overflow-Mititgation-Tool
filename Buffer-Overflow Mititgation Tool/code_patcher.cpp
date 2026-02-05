#include "code_patcher.h"
#include "utils/logger.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <unordered_map>
#include <algorithm>

struct CodePatcher::Impl {
    bool initialized = false;
    std::unordered_map<std::string, std::string> function_replacements;
    std::unordered_map<std::string, std::string> pattern_replacements;
    std::vector<std::string> security_headers;
    std::vector<std::string> security_macros;
    
    Impl() {
        function_replacements = {
            {"strcpy", "strncpy"},
            {"strcat", "strncat"},
            {"gets", "fgets"},
            {"sprintf", "snprintf"},
            {"scanf", "fgets + sscanf"},
            {"fscanf", "fgets + parsing"},
            {"sscanf", "manual parsing with validation"},
            {"vsprintf", "vsnprintf"},
            {"vsnprintf", "std::format (C++20)"},
            {"strncpy", "std::string"},
            {"strncat", "std::string::append"},
            {"snprintf", "std::format (C++20)"}
        };
        
        pattern_replacements = {
            {"rand\\(\\)", "std::random_device"},
            {"system\\s*\\(", "avoid command execution"},
            {"popen\\s*\\(", "avoid command execution"},
            {"eval\\s*\\(", "avoid dynamic code execution"},
            {"innerHTML\\s*=", "textContent = or safe DOM manipulation"},
            {"document\\.write\\s*\\(", "safe DOM manipulation"},
            {"md5\\s*\\(", "SHA-256 or bcrypt"},
            {"sha1\\s*\\(", "SHA-256 or bcrypt"},
            {"password\\s*=\\s*\"[^\"]+\"", "use environment variables"},
            {"secret\\s*=\\s*\"[^\"]+\"", "use secure key management"}
        };
        
        security_headers = {
            "#include <string>",
            "#include <memory>",
            "#include <limits>",
            "#include <stdexcept>",
            "#include <cstring>",
            "#include <algorithm>"
        };
        
        security_macros = {
            "#define SAFE_STRING_COPY(dest, src, size) strncpy(dest, src, size - 1); dest[size - 1] = '\\0'",
            "#define BOUNDS_CHECK(ptr, size, max_size) ((ptr) && (size) <= (max_size))",
            "#define NULL_CHECK(ptr) ((ptr) != nullptr)",
            "#define SAFE_DELETE(ptr) delete (ptr); (ptr) = nullptr",
            "#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))"
        };
    }
};

CodePatcher::CodePatcher() : pImpl(std::make_unique<Impl>()) {}

CodePatcher::~CodePatcher() = default;

bool CodePatcher::initialize() {
    if (pImpl->initialized) {
        Logger::log("CodePatcher already initialized");
        return true;
    }
    
    pImpl->initialized = true;
    Logger::log("CodePatcher initialized with " + std::to_string(pImpl->function_replacements.size()) + " function replacements");
    return true;
}

void CodePatcher::patchFunction(void* address, const std::string& instruction) {
    Logger::log("Patching function at " + std::to_string(reinterpret_cast<uintptr_t>(address)) + 
               " with instruction: " + instruction);
}

std::vector<CodePatcher::Mitigation> CodePatcher::suggestPatches(const std::vector<Vulnerability>& vulns) {
    std::vector<Mitigation> mitigations;
    
    for (const auto& vuln : vulns) {
        Mitigation mitigation;
        mitigation.vuln = vuln;
        mitigation.suggested_fix = generateFix(vuln);
        mitigation.patched_code = generatePatchedCode(vuln);
        mitigation.confidence = calculateConfidence(vuln);
        mitigations.push_back(mitigation);
    }
    
    Logger::log("Generated " + std::to_string(mitigations.size()) + " mitigation suggestions");
    return mitigations;
}

std::string CodePatcher::generateFix(const Vulnerability& vuln) {
    if (vuln.type == "buffer_overflow") {
        if (vuln.details.find("strcpy") != std::string::npos) {
            return "Replace strcpy with strncpy and ensure null termination";
        } else if (vuln.details.find("strcat") != std::string::npos) {
            return "Replace strcat with strncat and ensure null termination";
        } else if (vuln.details.find("gets") != std::string::npos) {
            return "Replace gets with fgets and specify buffer size";
        } else if (vuln.details.find("sprintf") != std::string::npos) {
            return "Replace sprintf with snprintf and specify buffer size";
        }
    } else if (vuln.type == "format_string") {
        return "Use format string validation or safer alternatives like std::format (C++20)";
    } else if (vuln.type == "sql_injection") {
        return "Use parameterized queries or input validation and sanitization";
    } else if (vuln.type == "xss") {
        return "Sanitize user input and use safe DOM manipulation methods";
    } else if (vuln.type == "command_injection") {
        return "Avoid command execution or use safe alternatives with proper validation";
    } else if (vuln.type == "path_traversal") {
        return "Validate and sanitize file paths, use absolute paths";
    } else if (vuln.type == "integer_overflow") {
        return "Use checked arithmetic operations or larger data types";
    } else if (vuln.type == "use_after_free") {
        return "Set pointer to nullptr after deletion and use smart pointers";
    } else if (vuln.type == "double_free") {
        return "Set pointer to nullptr after deletion and use smart pointers";
    } else if (vuln.type == "race_condition") {
        return "Use synchronization primitives (mutex, atomic operations)";
    } else if (vuln.type == "weak_cryptography") {
        return "Use modern cryptographic algorithms (AES, SHA-256, bcrypt)";
    } else if (vuln.type == "hardcoded_secret") {
        return "Use environment variables or secure key management systems";
    } else if (vuln.type == "weak_random") {
        return "Use cryptographically secure random generators";
    } else if (vuln.type == "memory_leak") {
        return "Use smart pointers or ensure proper cleanup in destructors";
    } else if (vuln.type == "null_pointer") {
        return "Add null pointer checks before dereferencing";
    } else if (vuln.type == "uninitialized_variable") {
        return "Initialize variables before use";
    }
    
    return "Review and fix according to security best practices";
}

std::string CodePatcher::generatePatchedCode(const Vulnerability& vuln) {
    std::string original_line = vuln.details;
    std::string patched_line = original_line;
    
    for (const auto& [old_func, new_func] : pImpl->function_replacements) {
        if (original_line.find(old_func) != std::string::npos) {
            if (old_func == "strcpy") {
                patched_line = std::regex_replace(patched_line, 
                    std::regex("strcpy\\s*\\(\\s*([^,]+)\\s*,\\s*([^)]+)\\s*\\)"),
                    "strncpy($1, $2, sizeof($1) - 1); $1[sizeof($1) - 1] = '\\0'");
            } else if (old_func == "strcat") {
                patched_line = std::regex_replace(patched_line,
                    std::regex("strcat\\s*\\(\\s*([^,]+)\\s*,\\s*([^)]+)\\s*\\)"),
                    "strncat($1, $2, sizeof($1) - strlen($1) - 1)");
            } else if (old_func == "gets") {
                patched_line = std::regex_replace(patched_line,
                    std::regex("gets\\s*\\(\\s*([^)]+)\\s*\\)"),
                    "fgets($1, sizeof($1), stdin)");
            } else if (old_func == "sprintf") {
                patched_line = std::regex_replace(patched_line,
                    std::regex("sprintf\\s*\\(\\s*([^,]+)\\s*,"),
                    "snprintf($1, sizeof($1),");
            } else {
                patched_line = std::regex_replace(patched_line, 
                    std::regex(old_func), new_func);
            }
        }
    }
    
    for (const auto& [pattern, replacement] : pImpl->pattern_replacements) {
        if (std::regex_search(original_line, std::regex(pattern))) {
            patched_line = std::regex_replace(patched_line, std::regex(pattern), replacement);
        }
    }
    
    if (vuln.type == "null_pointer") {
        patched_line = "if (" + patched_line + " != nullptr) { " + patched_line + "; }";
    } else if (vuln.type == "buffer_overflow_risk") {
        patched_line = "if (index < buffer_size) { " + patched_line + "; }";
    } else if (vuln.type == "integer_overflow") {
        patched_line = "if (__builtin_add_overflow(a, b, &result)) { /* handle overflow */ } else { " + patched_line + "; }";
    }
    
    return patched_line;
}

double CodePatcher::calculateConfidence(const Vulnerability& vuln) {
    if (vuln.type == "buffer_overflow" && 
        (vuln.details.find("strcpy") != std::string::npos || 
         vuln.details.find("gets") != std::string::npos)) {
        return 0.95;
    } else if (vuln.type == "format_string") {
        return 0.90;
    } else if (vuln.type == "sql_injection") {
        return 0.85;
    } else if (vuln.type == "xss") {
        return 0.80;
    } else if (vuln.type == "command_injection") {
        return 0.85;
    } else if (vuln.type == "use_after_free" || vuln.type == "double_free") {
        return 0.75;
    } else if (vuln.type == "memory_leak") {
        return 0.70;
    } else if (vuln.type == "null_pointer") {
        return 0.65;
    } else if (vuln.type == "uninitialized_variable") {
        return 0.60;
    }
    
    return 0.50;
}

std::string CodePatcher::generateSecureCodeTemplate() {
    std::stringstream template_code;
    
    template_code << "// Secure C++ Code Template\n";
    template_code << "// Generated by Buffer Overflow Mitigation Tool\n\n";
    for (const auto& header : pImpl->security_headers) {
        template_code << header << "\n";
    }
    template_code << "\n";
    for (const auto& macro : pImpl->security_macros) {
        template_code << macro << "\n";
    }
    template_code << "\n";
    
    template_code << "// Secure Coding Guidelines:\n";
    template_code << "// 1. Always validate input\n";
    template_code << "// 2. Use bounds checking\n";
    template_code << "// 3. Initialize variables\n";
    template_code << "// 4. Use smart pointers\n";
    template_code << "// 5. Check return values\n";
    template_code << "// 6. Use RAII principles\n";
    template_code << "// 7. Avoid raw pointers when possible\n";
    template_code << "// 8. Use const correctness\n";
    template_code << "// 9. Handle exceptions properly\n";
    template_code << "// 10. Use secure random number generators\n\n";
    
    template_code << "class SecureBuffer {\n";
    template_code << "private:\n";
    template_code << "    std::unique_ptr<char[]> buffer;\n";
    template_code << "    size_t size;\n";
    template_code << "\n";
    template_code << "public:\n";
    template_code << "    SecureBuffer(size_t buffer_size) : size(buffer_size) {\n";
    template_code << "        if (buffer_size == 0 || buffer_size > MAX_BUFFER_SIZE) {\n";
    template_code << "            throw std::invalid_argument(\"Invalid buffer size\");\n";
    template_code << "        }\n";
    template_code << "        buffer = std::make_unique<char[]>(buffer_size);\n";
    template_code << "        std::fill(buffer.get(), buffer.get() + buffer_size, '\\0');\n";
    template_code << "    }\n";
    template_code << "\n";
    template_code << "    bool copyString(const std::string& source) {\n";
    template_code << "        if (source.length() >= size) {\n";
    template_code << "            return false; // Buffer too small\n";
    template_code << "        }\n";
    template_code << "        std::copy(source.begin(), source.end(), buffer.get());\n";
    template_code << "        buffer[source.length()] = '\\0';\n";
    template_code << "        return true;\n";
    template_code << "    }\n";
    template_code << "\n";
    template_code << "    const char* getData() const { return buffer.get(); }\n";
    template_code << "    size_t getSize() const { return size; }\n";
    template_code << "};\n\n";
    
    template_code << "int main() {\n";
    template_code << "    try {\n";
    template_code << "        SecureBuffer buffer(256);\n";
    template_code << "        \n";
    template_code << "        std::string input;\n";
    template_code << "        std::cout << \"Enter string: \";\n";
    template_code << "        std::getline(std::cin, input);\n";
    template_code << "        \n";
    template_code << "        if (!buffer.copyString(input)) {\n";
    template_code << "            std::cerr << \"Input too long\" << std::endl;\n";
    template_code << "            return 1;\n";
    template_code << "        }\n";
    template_code << "        \n";
    template_code << "        std::cout << \"Safe string: \" << buffer.getData() << std::endl;\n";
    template_code << "        return 0;\n";
    template_code << "    } catch (const std::exception& e) {\n";
    template_code << "        std::cerr << \"Error: \" << e.what() << std::endl;\n";
    template_code << "        return 1;\n";
    template_code << "    }\n";
    template_code << "}\n";
    
    return template_code.str();
}

std::string CodePatcher::applySecurityHeaders(const std::string& code) {
    std::string patched_code = code;
    
    for (const auto& header : pImpl->security_headers) {
        if (patched_code.find(header) == std::string::npos) {
            size_t pos = patched_code.find("#include");
            if (pos != std::string::npos) {
                patched_code.insert(pos, header + "\n");
            } else {
                patched_code = header + "\n" + patched_code;
            }
        }
    }
    
    for (const auto& macro : pImpl->security_macros) {
        if (patched_code.find(macro) == std::string::npos) {
            size_t pos = patched_code.find_last_of("#include");
            if (pos != std::string::npos) {
                pos = patched_code.find('\n', pos) + 1;
                patched_code.insert(pos, "\n" + macro + "\n");
            } else {
                patched_code = macro + "\n" + patched_code;
            }
        }
    }
    
    return patched_code;
}

std::string CodePatcher::generateCompilationFlags() {
    std::string flags;
    
#ifdef _WIN32
    flags = "/std:c++17 /W4 /WX /GS /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA";
#else
    flags = "-std=c++17 -Wall -Wextra -Werror -fstack-protector-strong -fPIE -pie -D_FORTIFY_SOURCE=2";
    flags += " -fsanitize=address -fsanitize=undefined -fsanitize=thread";
#endif
    
    return flags;
}
