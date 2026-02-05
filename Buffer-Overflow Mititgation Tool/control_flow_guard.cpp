#include "analyzer/control_flow_guard.h"
#include "utils/logger.h"
#include <iostream>

ControlFlowGuard::ControlFlowGuard() : isEnabled(false), validTargets("main") {
}

ControlFlowGuard::~ControlFlowGuard() {}

bool ControlFlowGuard::validateCall(const std::string& source, const std::string& target) {
    if (!isEnabled) return true;
    if (validTargets.find(target) != std::string::npos) {
        Logger::log("Valid call from " + source + " to " + target);
        return true;
    }
    Logger::log("Invalid call detected from " + source + " to " + target);
    return false;
}

void ControlFlowGuard::enable() {
    isEnabled = true;
    Logger::log("Control Flow Guard enabled");
}