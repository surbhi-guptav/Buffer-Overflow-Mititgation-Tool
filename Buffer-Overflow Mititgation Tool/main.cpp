#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <chrono>
#include "httplib.h"
#include "analyzer/static_analyzer.h"
#include "scanner/buffer_scanner.h"
#include "mitigator/code_patcher.h"
#include "mitigator/shadow_stack.h"
#include "utils/logger.h"

namespace fs = std::filesystem;
using namespace httplib;

std::string htmlForm = R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Buffer Mitigation Tool</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { padding: 20px; background-color: #f8f9fa; }
        .container { max-width: 800px; }
        textarea { height: 300px; font-family: 'Courier New', monospace; }
        #results { margin-top: 20px; }
        .accordion-button { font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center mb-4">Buffer Mitigation Tool</h1>
        <form id="codeForm" method="POST" action="/analyze">
            <div class="mb-3">
                <label for="code" class="form-label">Enter Your C++ Code</label>
                <textarea class="form-control" id="code" name="code" placeholder="Paste your code here..."></textarea>
            </div>
            <button type="submit" class="btn btn-primary w-100">Analyze Code</button>
        </form>
        <div id="results" class="mt-4"></div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.getElementById('codeForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const code = document.getElementById('code').value;
            const formData = new URLSearchParams();
            formData.append('code', code);

            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: formData
                });
                const data = await response.json();
                renderResults(data);
            } catch (error) {
                document.getElementById('results').innerHTML = 
                    `<div class="alert alert-danger">Error: ${error.message}</div>`;
            }
        });

        function renderResults(data) {
            const resultsDiv = document.getElementById('results');
            resultsDiv.innerHTML = `
                <div class="accordion" id="analysisAccordion">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#staticVulns">
                                Static Vulnerabilities (${data.static_vulnerabilities.length})
                            </button>
                        </h2>
                        <div id="staticVulns" class="accordion-collapse collapse show" data-bs-parent="#analysisAccordion">
                            <div class="accordion-body">
                                ${data.static_vulnerabilities.length ? 
                                    data.static_vulnerabilities.map(v => 
                                        `<p class="mb-1"><strong>${v.type}</strong> (${v.severity}): ${v.details} at line ${v.line_number}</p>`
                                    ).join('') : 
                                    '<p>No static vulnerabilities found.</p>'}
                            </div>
                        </div>
                    </div>
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#runtimeVulns">
                                Runtime Vulnerabilities (${data.runtime_vulnerabilities.length})
                            </button>
                        </h2>
                        <div id="runtimeVulns" class="accordion-collapse collapse" data-bs-parent="#analysisAccordion">
                            <div class="accordion-body">
                                ${data.runtime_vulnerabilities.length ? 
                                    data.runtime_vulnerabilities.map(v => 
                                        `<p class="mb-1"><strong>${v.type}</strong> (${v.severity}): ${v.details}</p>`
                                    ).join('') : 
                                    '<p>No runtime vulnerabilities found.</p>'}
                            </div>
                        </div>
                    </div>
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#mitigations">
                                Mitigation Suggestions (${data.mitigations.length})
                            </button>
                        </h2>
                        <div id="mitigations" class="accordion-collapse collapse" data-bs-parent="#analysisAccordion">
                            <div class="accordion-body">
                                ${data.mitigations.length ? 
                                    data.mitigations.map(m => 
                                        `<p class="mb-1"><strong>${m.type}</strong>: ${m.suggested_fix}</p>`
                                    ).join('') : 
                                    '<p>No mitigations suggested.</p>'}
                            </div>
                        </div>
                    </div>
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#stackIssues">
                                Post-Mitigation Stack Issues (${data.stack_issues.length})
                            </button>
                        </h2>
                        <div id="stackIssues" class="accordion-collapse collapse" data-bs-parent="#analysisAccordion">
                            <div class="accordion-body">
                                ${data.stack_issues.length ? 
                                    data.stack_issues.map(s => 
                                        `<p class="mb-1"><strong>${s.type}</strong> (${s.severity}): ${s.details}</p>`
                                    ).join('') : 
                                    '<p>No stack issues found.</p>'}
                            </div>
                        </div>
                    </div>
                </div>
                <p class="mt-3 text-muted">Analysis completed for ${data.file_path}</p>
            `;
        }
    </script>
</body>
</html>
)";

bool compileCode(const std::string& source_path, const std::string& output_path) {
    fs::path outDir = fs::path(output_path).parent_path();
    if (!fs::exists(outDir)) {
        fs::create_directories(outDir);
    }
    std::string cmd = "C:/mingw64/bin/g++ -g -o " + output_path + " " + source_path + 
                      " -IC:/Users/Lenovo/Desktop/buffer-mitigation-tool/include " +
                      " -LC:/Users/Lenovo/Desktop/buffer-mitigation-tool/build/lib " +
                      " -lanalyzer -lscanner -lmitigator -lutils -lstdc++fs";
    int result = system(cmd.c_str());
    return result == 0;
}

void runShadowStackDemo(ShadowStack& shadow) {
    std::cout << "Running Shadow Stack Demo..." << std::endl;
    void* dummy_addr = reinterpret_cast<void*>(0x12345678);
    shadow.pushReturnAddress(dummy_addr);
    bool valid = shadow.validateReturnAddress(dummy_addr);
    std::cout << "Shadow stack validation: " << (valid ? "Success" : "Failure") << std::endl;
    ::Logger::log("Shadow stack demo: " + std::string(valid ? "Success" : "Failure"));
}

std::string escapeJsonString(const std::string& input) {
    std::string escaped;
    for (char c : input) {
        switch (c) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default: escaped += c; break;
        }
    }
    return escaped;
}

std::string analyzeFile(const std::string& code_path, StaticAnalyzer& analyzer, BufferScanner& scanner, 
                        CodePatcher& patcher, ShadowStack& stack) {
    std::string log_file = "C:/Users/Lenovo/Desktop/buffer-mitigation-tool/logs/analyze_" + 
                           fs::path(code_path).stem().string() + ".log";
    ::Logger::init(log_file);

    std::ifstream file(code_path);
    if (!file) {
        ::Logger::log("Error: Could not open source file " + code_path);
        return R"({"error": "Failed to open file", "file_path": ")" + escapeJsonString(code_path) + R"("})";
    }
    std::string code((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    ::Logger::log("Starting analysis for " + code_path);

    std::vector<Vulnerability> static_vulns = analyzer.analyze(code);
    ::Logger::log("Static analysis completed. Found " + std::to_string(static_vulns.size()) + " vulnerabilities");

    std::string exe_path = "C:/Users/Lenovo/Desktop/buffer-mitigation-tool/build/temp_" + 
                           fs::path(code_path).stem().string() + ".exe";
    std::vector<Vulnerability> runtime_vulns;
    bool compiled = compileCode(code_path, exe_path);
    if (compiled) {
        ::Logger::log("Scanning executable: " + exe_path);
        runtime_vulns = scanner.scanExecutable(exe_path);
        ::Logger::log("Runtime scanning completed. Found " + std::to_string(runtime_vulns.size()) + " vulnerabilities");
    } else {
        ::Logger::log("Error: Compilation failed for " + code_path);
    }

    std::vector<Vulnerability> all_vulns = static_vulns;
    all_vulns.insert(all_vulns.end(), runtime_vulns.begin(), runtime_vulns.end());
    std::vector<CodePatcher::Mitigation> mitigations = patcher.suggestPatches(all_vulns);
    ::Logger::log("Mitigation suggestions generated. Found " + std::to_string(mitigations.size()) + " mitigations");

    std::vector<Vulnerability> stack_vulns;
    if (fs::exists(exe_path)) {
        ::Logger::log("Verifying stack protection for: " + exe_path);
        stack_vulns = stack.verifyStackProtection(exe_path);
        ::Logger::log("Shadow stack verification completed. Found " + std::to_string(stack_vulns.size()) + " remaining issues");
        fs::remove(exe_path);
    }

    std::string json = "{";
    json += "\"file_path\": \"" + escapeJsonString(code_path) + "\",";
    json += "\"static_vulnerabilities\": [";
    for (size_t i = 0; i < static_vulns.size(); ++i) {
        json += "{";
        json += "\"type\": \"" + escapeJsonString(static_vulns[i].type) + "\",";
        json += "\"severity\": \"" + escapeJsonString(static_vulns[i].severity) + "\",";
        json += "\"details\": \"" + escapeJsonString(static_vulns[i].details) + "\",";
        json += "\"line_number\": " + std::to_string(static_vulns[i].line_number);
        json += "}";
        if (i < static_vulns.size() - 1) json += ",";
        ::Logger::logVulnerability(static_vulns[i]);
    }
    json += "],";
    json += "\"runtime_vulnerabilities\": [";
    for (size_t i = 0; i < runtime_vulns.size(); ++i) {
        json += "{";
        json += "\"type\": \"" + escapeJsonString(runtime_vulns[i].type) + "\",";
        json += "\"severity\": \"" + escapeJsonString(runtime_vulns[i].severity) + "\",";
        json += "\"details\": \"" + escapeJsonString(runtime_vulns[i].details) + "\"";
        json += "}";
        if (i < runtime_vulns.size() - 1) json += ",";
        ::Logger::logVulnerability(runtime_vulns[i]);
    }
    json += "],";
    json += "\"mitigations\": [";
    for (size_t i = 0; i < mitigations.size(); ++i) {
        json += "{";
        json += "\"type\": \"" + escapeJsonString(mitigations[i].vuln.type) + "\",";
        json += "\"suggested_fix\": \"" + escapeJsonString(mitigations[i].suggested_fix) + "\"";
        json += "}";
        if (i < mitigations.size() - 1) json += ",";
        ::Logger::logMitigation(mitigations[i]);
    }
    json += "],";
    json += "\"stack_issues\": [";
    for (size_t i = 0; i < stack_vulns.size(); ++i) {
        json += "{";
        json += "\"type\": \"" + escapeJsonString(stack_vulns[i].type) + "\",";
        json += "\"severity\": \"" + escapeJsonString(stack_vulns[i].severity) + "\",";
        json += "\"details\": \"" + escapeJsonString(stack_vulns[i].details) + "\"";
        json += "}";
        if (i < stack_vulns.size() - 1) json += ",";
        ::Logger::logVulnerability(stack_vulns[i]);
    }
    json += "]";
    json += "}";

    ::Logger::log("Analysis completed for " + code_path);
    return json;
}

int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    std::cout << "Buffer Mitigation Tool" << std::endl;

    ::Logger::init("C:/Users/Lenovo/Desktop/buffer-mitigation-tool/logs/buffer_mitigation.log");

    StaticAnalyzer analyzer;
    BufferScanner scanner;
    CodePatcher patcher;
    ShadowStack shadow;

    if (!analyzer.initialize()) {
        ::Logger::log("Failed to initialize StaticAnalyzer");
        std::cerr << "Initialization failed for StaticAnalyzer" << std::endl;
        return 1;
    }
    if (!scanner.initialize()) {
        ::Logger::log("Failed to initialize BufferScanner");
        std::cerr << "Initialization failed for BufferScanner" << std::endl;
        return 1;
    }
    if (!patcher.initialize()) {
        ::Logger::log("Failed to initialize CodePatcher");
        std::cerr << "Initialization failed for CodePatcher" << std::endl;
        return 1;
    }
    if (!shadow.initialize()) {
        ::Logger::log("Failed to initialize ShadowStack");
        std::cerr << "Initialization failed for ShadowStack" << std::endl;
        return 1;
    }
    ::Logger::log("Components instantiated and initialized");

    if (argc > 1 && std::string(argv[1]) == "--demo") {
        runShadowStackDemo(shadow);
        ::Logger::log("All components executed successfully");
        std::cout << "All components initialized successfully!" << std::endl;
        return 0;
    }

    Server svr;

    svr.Get("/", [](const Request&, Response& res) {
        res.set_content(htmlForm, "text/html");
    });

    svr.Post("/analyze", [&](const Request& req, Response& res) {
        std::cout << "Received /analyze request" << std::endl;
        std::cout << "Raw Body: " << req.body << std::endl;

        if (req.has_param("code")) {
            auto code = req.get_param_value("code");
            std::cout << "Extracted Code: " << code << std::endl;

            if (code.empty()) {
                res.set_content(R"({"error": "Code parameter is empty"})", "application/json");
                return;
            }

            std::string timestamp = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
            std::string filename = "C:/Users/Lenovo/Desktop/buffer-mitigation-tool/code_samples/user_code_" + timestamp + ".cpp";
            std::ofstream file(filename);
            if (!file) {
                res.set_content(R"({"error": "Failed to save code"})", "application/json");
                return;
            }
            file << code;
            file.close();

            std::string result = analyzeFile(filename, analyzer, scanner, patcher, shadow);
            std::cout << "Generated JSON: " << result << std::endl;
            res.set_content(result, "application/json");
        } else {
            std::cout << "Error: No 'code' parameter found in request" << std::endl;
            res.set_content(R"({"error": "No code provided"})", "application/json");
        }
    });

    std::cout << "Server running at http://localhost:8080" << std::endl;
    ::Logger::log("Server started at http://localhost:8080");
    svr.listen("localhost", 8080);

    return 0;
}