#include "analyzer/dynamic_analyzer.h"
#include "utils/logger.h"
#include <iostream>

DynamicAnalyzer::DynamicAnalyzer() 
    : isMonitoring(false), monitoredRegionStart(nullptr), monitoredRegionSize(0) {}

DynamicAnalyzer::~DynamicAnalyzer() {
    if (monitoredRegionStart) {
        delete[] static_cast<char*>(monitoredRegionStart);
    }
}

void DynamicAnalyzer::startMonitoring() {
    isMonitoring = true;
    monitoredRegionStart = new char[1024]; // Simulated memory region
    monitoredRegionSize = 1024;
    Logger::log("Dynamic monitoring started with 1024-byte region");
}

bool DynamicAnalyzer::analyzeAccess(void* address, size_t size) {
    if (!isMonitoring) return true;

    uintptr_t addr = reinterpret_cast<uintptr_t>(address);
    uintptr_t start = reinterpret_cast<uintptr_t>(monitoredRegionStart);
    uintptr_t end = start + monitoredRegionSize;

    if (addr >= start && (addr + size) <= end) {
        Logger::log("Valid memory access at " + std::to_string(addr));
        return true;
    }
    Logger::log("Out-of-bounds access detected at " + std::to_string(addr));
    return false;
}