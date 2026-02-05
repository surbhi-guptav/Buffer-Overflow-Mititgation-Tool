#ifndef LOGGER_H
#define LOGGER_H
#include <string>
#include "analyzer/static_analyzer.h"  // For Vulnerability
#include "mitigator/code_patcher.h"    // For CodePatcher::Mitigation

class Logger {
public:
    enum class LogLevel {
        TRACE = 0,
        DEBUG = 1,
        INFO = 2,
        WARNING = 3,
        ERROR = 4,
        CRITICAL = 5
    };

    static void init(const std::string& logFile);
    static void setLogLevel(LogLevel level);
    static void log(const std::string& message, LogLevel level = LogLevel::INFO);
    
    // Specialized logging methods
    static void logVulnerability(const Vulnerability& vuln);
    static void logMitigation(const CodePatcher::Mitigation& mitigation);
    static void logSecurityViolation(const std::string& type, const std::string& details, 
                                   void* address, size_t size, const std::string& severity);
    static void logMemoryOperation(const std::string& operation, void* address, size_t size);
    static void logPerformance(const std::string& operation, double duration_ms);
    static void logConfiguration(const std::string& config_name, const std::string& config_value);
    static void logError(const std::string& error_message, const std::string& file = "", int line = 0);
    static void logWarning(const std::string& warning_message, const std::string& file = "", int line = 0);
    static void logInfo(const std::string& info_message);
    static void logDebug(const std::string& debug_message);
    static void logTrace(const std::string& trace_message);
    static void logCritical(const std::string& critical_message);
    
    // Utility methods
    static void flush();
    static void close();
    static std::string getCurrentLogFile();
    static bool isInitialized();

private:
    Logger() = default;
    
    static void rotateLogFile();
    static std::string getLevelString(LogLevel level);
    static LogLevel getSeverityLevel(const std::string& severity);
};

#endif // LOGGER_H