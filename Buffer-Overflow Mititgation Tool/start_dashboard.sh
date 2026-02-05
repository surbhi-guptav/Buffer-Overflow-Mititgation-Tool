#!/bin/bash

# Buffer Overflow Mitigation Tool Dashboard Startup Script
# This script starts the dashboard server and opens the web interface

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DASHBOARD_PORT=8080
DASHBOARD_HOST="localhost"
DASHBOARD_URL="http://$DASHBOARD_HOST:$DASHBOARD_PORT"
DASHBOARD_FILE="dashboard.html"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  Buffer Overflow Mitigation Tool${NC}"
    echo -e "${BLUE}         Dashboard Startup${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if port is available
check_port() {
    if command_exists lsof; then
        lsof -i :$DASHBOARD_PORT >/dev/null 2>&1
    elif command_exists netstat; then
        netstat -an | grep ":$DASHBOARD_PORT " >/dev/null 2>&1
    else
        # Fallback: try to bind to the port
        timeout 1 bash -c "echo >/dev/tcp/$DASHBOARD_HOST/$DASHBOARD_PORT" 2>/dev/null || return 1
    fi
}

# Function to find available Python version
find_python() {
    if command_exists python3; then
        echo "python3"
    elif command_exists python; then
        # Check if it's Python 3
        python --version 2>&1 | grep -q "Python 3" && echo "python" || return 1
    else
        return 1
    fi
}

# Function to find available browser
find_browser() {
    local browsers=("google-chrome" "chromium" "firefox" "safari" "opera" "brave")
    
    for browser in "${browsers[@]}"; do
        if command_exists "$browser"; then
            echo "$browser"
            return 0
        fi
    done
    
    return 1
}

# Function to open browser
open_browser() {
    local browser=$1
    
    case "$browser" in
        "google-chrome"|"chromium"|"brave")
            "$browser" --new-window "$DASHBOARD_URL" >/dev/null 2>&1 &
            ;;
        "firefox")
            "$browser" -new-window "$DASHBOARD_URL" >/dev/null 2>&1 &
            ;;
        "safari")
            open -a Safari "$DASHBOARD_URL" >/dev/null 2>&1 &
            ;;
        "opera")
            "$browser" --new-window "$DASHBOARD_URL" >/dev/null 2>&1 &
            ;;
        *)
            # Fallback: use system default
            if command_exists xdg-open; then
                xdg-open "$DASHBOARD_URL" >/dev/null 2>&1 &
            elif command_exists open; then
                open "$DASHBOARD_URL" >/dev/null 2>&1 &
            else
                print_warning "Could not open browser automatically. Please open: $DASHBOARD_URL"
                return 1
            fi
            ;;
    esac
}

# Function to start HTTP server
start_server() {
    local python_cmd=$1
    
    print_status "Starting HTTP server on port $DASHBOARD_PORT..."
    
    # Start server in background
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        # Windows (Git Bash, Cygwin)
        "$python_cmd" -m http.server "$DASHBOARD_PORT" &
    else
        # Unix-like systems
        "$python_cmd" -m http.server "$DASHBOARD_PORT" >/dev/null 2>&1 &
    fi
    
    SERVER_PID=$!
    
    # Wait a moment for server to start
    sleep 2
    
    # Check if server started successfully
    if kill -0 "$SERVER_PID" 2>/dev/null; then
        print_status "HTTP server started successfully (PID: $SERVER_PID)"
        return 0
    else
        print_error "Failed to start HTTP server"
        return 1
    fi
}

# Function to cleanup on exit
cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        print_status "Stopping HTTP server (PID: $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
    fi
    print_status "Dashboard stopped"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Main execution
main() {
    print_header
    
    # Check if dashboard file exists
    if [[ ! -f "$DASHBOARD_FILE" ]]; then
        print_error "Dashboard file '$DASHBOARD_FILE' not found!"
        print_error "Please ensure you're running this script from the project directory."
        exit 1
    fi
    
    # Check if port is already in use
    if check_port; then
        print_warning "Port $DASHBOARD_PORT is already in use"
        print_status "Attempting to use port $((DASHBOARD_PORT + 1))..."
        DASHBOARD_PORT=$((DASHBOARD_PORT + 1))
        DASHBOARD_URL="http://$DASHBOARD_HOST:$DASHBOARD_PORT"
    fi
    
    # Find Python
    PYTHON_CMD=$(find_python)
    if [[ -z "$PYTHON_CMD" ]]; then
        print_error "Python 3 is required but not found!"
        print_error "Please install Python 3 and try again."
        exit 1
    fi
    
    print_status "Using Python: $($PYTHON_CMD --version)"
    
    # Start HTTP server
    if ! start_server "$PYTHON_CMD"; then
        exit 1
    fi
    
    # Find and open browser
    BROWSER=$(find_browser)
    if [[ -n "$BROWSER" ]]; then
        print_status "Opening dashboard in $BROWSER..."
        if open_browser "$BROWSER"; then
            print_status "Dashboard opened successfully!"
        else
            print_warning "Could not open browser automatically"
        fi
    else
        print_warning "No supported browser found"
    fi
    
    print_status "Dashboard is running at: $DASHBOARD_URL"
    print_status "Press Ctrl+C to stop the server"
    echo
    
    # Keep script running
    while kill -0 "$SERVER_PID" 2>/dev/null; do
        sleep 1
    done
}

# Check if script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
