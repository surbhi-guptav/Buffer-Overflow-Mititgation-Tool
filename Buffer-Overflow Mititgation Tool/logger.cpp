#include "logger.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <mutex>
#include <filesystem>
#include <algorithm>

namespace {
    std::ofstream log_file;
    std::string current_log_file;
    std::mutex log_mutex;
    Logger::LogLevel current_level = Logger::LogLevel::INFO;
    bool initialized = false;
    const size_t MAX_LOG_SIZE = 10 * 1024 * 1024;
    const int MAX_LOG_FILES = 5;
}

void Logger::init(const std::string& logFile) {
    std::lock_guard<std::mutex> lock(log_mutex);
    
    if (initialized) {
        log("Logger already initialized");
        return;
    }
    
    current_log_file = logFile;
    
    std::filesystem::path log_path(logFile);
    std::filesystem::create_directories(log_path.parent_path());
    
    log_file.open(logFile, std::ios::app);
    if (!log_file.is_open()) {
        std::cerr << "Failed to open log file: " << logFile << std::endl;
        return;
    }
    
    initialized = true;
    log("Logger initialized successfully");
}

void Logger::setLogLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(log_mutex);
    current_level = level;
    log("Log level set to " + std::to_string(static_cast<int>(level)));
}

void Logger::log(const std::string& message, LogLevel level) {
    if (level < current_level) return;
    
    std::lock_guard<std::mutex> lock(log_mutex);
    
    if (!initialized) {
        std::cerr << "Logger not initialized" << std::endl;
        return;
    }
    
    if (log_file.is_open()) {
        log_file.seekp(0, std::ios::end);
        size_t file_size = log_file.tellp();
        if (file_size > MAX_LOG_SIZE) {
            rotateLogFile();
        }
    }
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    
    std::string timestamp = ss.str();
    std::string level_str = getLevelString(level);
    
    std::string log_entry = "[" + timestamp + "] [" + level_str + "] " + message + "\n";
    
    if (log_file.is_open()) {
        log_file << log_entry;
        log_file.flush();
    }
    
    if (level >= LogLevel::WARNING) {
        std::cout << log_entry;
    }
}

void Logger::logVulnerability(const Vulnerability& vuln) {
    std::stringstream ss;
    ss << "VULNERABILITY DETECTED - Type: " << vuln.type 
       << ", Severity: " << vuln.severity 
       << ", Line: " << vuln.line_number 
       << ", Details: " << vuln.details;
    
    if (!vuln.suggested_fix.empty()) {
        ss << ", Fix: " << vuln.suggested_fix;
    }
    
    LogLevel level = getSeverityLevel(vuln.severity);
    log(ss.str(), level);
}

void Logger::logMitigation(const CodePatcher::Mitigation& mitigation) {
    std::stringstream ss;
    ss << "MITIGATION SUGGESTED - Type: " << mitigation.vuln.type 
       << ", Confidence: " << std::fixed << std::setprecision(2) << (mitigation.confidence * 100) << "%"
       << ", Fix: " << mitigation.suggested_fix;
    
    log(ss.str(), LogLevel::INFO);
}

void Logger::logSecurityViolation(const std::string& type, const std::string& details, 
                                 void* address, size_t size, const std::string& severity) {
    std::stringstream ss;
    ss << "SECURITY VIOLATION - Type: " << type 
       << ", Severity: " << severity 
       << ", Address: 0x" << std::hex << reinterpret_cast<uintptr_t>(address) << std::dec
       << ", Size: " << size 
       << ", Details: " << details;
    
    LogLevel level = getSeverityLevel(severity);
    log(ss.str(), level);
}

void Logger::logMemoryOperation(const std::string& operation, void* address, size_t size) {
    std::stringstream ss;
    ss << "MEMORY OPERATION - " << operation 
       << " at 0x" << std::hex << reinterpret_cast<uintptr_t>(address) << std::dec
       << " size: " << size;
    
    log(ss.str(), LogLevel::DEBUG);
}

void Logger::logPerformance(const std::string& operation, double duration_ms) {
    std::stringstream ss;
    ss << "PERFORMANCE - " << operation << " took " << std::fixed << std::setprecision(2) 
       << duration_ms << "ms";
    
    log(ss.str(), LogLevel::DEBUG);
}

void Logger::logConfiguration(const std::string& config_name, const std::string& config_value) {
    std::stringstream ss;
    ss << "CONFIGURATION - " << config_name << ": " << config_value;
    
    log(ss.str(), LogLevel::INFO);
}

void Logger::logError(const std::string& error_message, const std::string& file, int line) {
    std::stringstream ss;
    ss << "ERROR - " << error_message << " in " << file << ":" << line;
    
    log(ss.str(), LogLevel::ERROR);
}

void Logger::logWarning(const std::string& warning_message, const std::string& file, int line) {
    std::stringstream ss;
    ss << "WARNING - " << warning_message << " in " << file << ":" << line;
    
    log(ss.str(), LogLevel::WARNING);
}

void Logger::logInfo(const std::string& info_message) {
    log(info_message, LogLevel::INFO);
}

void Logger::logDebug(const std::string& debug_message) {
    log(debug_message, LogLevel::DEBUG);
}

void Logger::logTrace(const std::string& trace_message) {
    log(trace_message, LogLevel::TRACE);
}

void Logger::logCritical(const std::string& critical_message) {
    log(critical_message, LogLevel::CRITICAL);
}

void Logger::rotateLogFile() {
    if (current_log_file.empty()) return;
    
    log_file.close();
    
    std::filesystem::path log_path(current_log_file);
    std::string base_name = log_path.stem().string();
    std::string extension = log_path.extension().string();
    std::string directory = log_path.parent_path().string();
    
    for (int i = MAX_LOG_FILES - 1; i >= 0; --i) {
        std::string old_file = directory + "/" + base_name + "_" + std::to_string(i) + extension;
        if (std::filesystem::exists(old_file)) {
            if (i == MAX_LOG_FILES - 1) {
                std::filesystem::remove(old_file);
            } else {
                std::string new_file = directory + "/" + base_name + "_" + std::to_string(i + 1) + extension;
                std::filesystem::rename(old_file, new_file);
            }
        }
    }
    
    std::string new_file = directory + "/" + base_name + "_0" + extension;
    std::filesystem::rename(current_log_file, new_file);
    
    log_file.open(current_log_file, std::ios::app);
    if (log_file.is_open()) {
        log("Log file rotated successfully");
    }
}

std::string Logger::getLevelString(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

Logger::LogLevel Logger::getSeverityLevel(const std::string& severity) {
    std::string lower_severity = severity;
    std::transform(lower_severity.begin(), lower_severity.end(), lower_severity.begin(), ::tolower);
    
    if (lower_severity == "critical") return LogLevel::CRITICAL;
    if (lower_severity == "high") return LogLevel::ERROR;
    if (lower_severity == "medium") return LogLevel::WARNING;
    if (lower_severity == "low") return LogLevel::INFO;
    
    return LogLevel::INFO;
}

void Logger::flush() {
    std::lock_guard<std::mutex> lock(log_mutex);
    if (log_file.is_open()) {
        log_file.flush();
    }
}

void Logger::close() {
    std::lock_guard<std::mutex> lock(log_mutex);
    if (log_file.is_open()) {
        log("Logger shutting down");
        log_file.close();
    }
    initialized = false;
}

std::string Logger::getCurrentLogFile() {
    return current_log_file;
}

bool Logger::isInitialized() {
    return initialized;
}
