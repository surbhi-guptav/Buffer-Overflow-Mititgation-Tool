#!/usr/bin/env python3

import os
import sys
import json
import time
import signal
import threading
import subprocess
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import mimetypes
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dashboard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DashboardRequestHandler(BaseHTTPRequestHandler):
    
    def __init__(self, *args, **kwargs):
        self.static_files = {
            '/': 'dashboard.html',
            '/dashboard': 'dashboard.html',
            '/dashboard.html': 'dashboard.html',
            '/dashboard.js': 'dashboard.js',
            '/favicon.ico': None
        }
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        logger.info(f"{self.address_string()} - {format % args}")
    
    def do_GET(self):
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            
            if path in self.static_files:
                file_path = self.static_files[path]
                if file_path and os.path.exists(file_path):
                    self.serve_file(file_path)
                    return
                elif path == '/favicon.ico':
                    self.send_error(404, "Favicon not found")
                    return
            
            if path.startswith('/api/'):
                self.handle_api_request(path, parsed_url.query)
                return
            
            if os.path.exists(path.lstrip('/')):
                self.serve_file(path.lstrip('/'))
                return
            
            if os.path.exists('dashboard.html'):
                self.serve_file('dashboard.html')
                return
            
            self.send_error(404, "File not found")
            
        except Exception as e:
            logger.error(f"Error handling GET request: {e}")
            self.send_error(500, "Internal server error")
    
    def do_POST(self):
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            
            if path == '/api/analyze':
                self.handle_analysis_request()
                return
            
            if path == '/api/scan':
                self.handle_scan_request()
                return
            
            if path == '/api/status':
                self.handle_status_request()
                return
            
            self.send_error(404, "API endpoint not found")
            
        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            self.send_error(500, "Internal server error")
    
    def serve_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            content_type, _ = mimetypes.guess_type(file_path)
            if content_type is None:
                if file_path.endswith('.js'):
                    content_type = 'application/javascript'
                elif file_path.endswith('.html'):
                    content_type = 'text/html'
                elif file_path.endswith('.css'):
                    content_type = 'text/css'
                else:
                    content_type = 'application/octet-stream'
            
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(content)
            
        except FileNotFoundError:
            self.send_error(404, "File not found")
        except Exception as e:
            logger.error(f"Error serving file {file_path}: {e}")
            self.send_error(500, "Internal server error")
    
    def handle_api_request(self, path, query):
        if path == '/api/status':
            self.send_json_response(self.get_system_status())
        elif path == '/api/metrics':
            self.send_json_response(self.get_metrics())
        else:
            self.send_error(404, "API endpoint not found")
    
    def handle_analysis_request(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            if self.headers.get('Content-Type', '').startswith('application/x-www-form-urlencoded'):
                data = parse_qs(post_data.decode('utf-8'))
                code = data.get('code', [''])[0]
            else:
                data = json.loads(post_data.decode('utf-8'))
                code = data.get('code', '')
            
            vulnerabilities = self.analyze_code(code)
            
            response = {
                'success': True,
                'vulnerabilities': vulnerabilities,
                'timestamp': time.time()
            }
            
            self.send_json_response(response)
            
        except Exception as e:
            logger.error(f"Error in analysis request: {e}")
            self.send_json_response({
                'success': False,
                'error': str(e)
            })
    
    def handle_scan_request(self):
        try:
            scan_results = self.perform_system_scan()
            
            response = {
                'success': True,
                'scan_results': scan_results,
                'timestamp': time.time()
            }
            
            self.send_json_response(response)
            
        except Exception as e:
            logger.error(f"Error in scan request: {e}")
            self.send_json_response({
                'success': False,
                'error': str(e)
            })
    
    def handle_status_request(self):
        try:
            status = self.get_system_status()
            self.send_json_response(status)
            
        except Exception as e:
            logger.error(f"Error in status request: {e}")
            self.send_json_response({
                'success': False,
                'error': str(e)
            })
    
    def send_json_response(self, data):
        response = json.dumps(data, indent=2)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))
    
    def analyze_code(self, code):
        vulnerabilities = []
        
        if not code.strip():
            return vulnerabilities
        
        lines = code.split('\n')
        
        patterns = [
            {
                'pattern': r'strcpy\s*\(',
                'type': 'Buffer Overflow',
                'severity': 'critical',
                'confidence': 95,
                'description': 'Unsafe use of strcpy() without bounds checking'
            },
            {
                'pattern': r'printf\s*\([^)]*%[^)]*\)',
                'type': 'Format String',
                'severity': 'high',
                'confidence': 87,
                'description': 'Uncontrolled format string usage'
            },
            {
                'pattern': r'free\s*\([^)]*\)[^;]*\1',
                'type': 'Use-After-Free',
                'severity': 'high',
                'confidence': 92,
                'description': 'Potential use-after-free vulnerability'
            },
            {
                'pattern': r'\*\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[^;]*malloc',
                'type': 'Memory Leak',
                'severity': 'medium',
                'confidence': 78,
                'description': 'Potential memory leak'
            },
            {
                'pattern': r'scanf\s*\([^)]*\)',
                'type': 'Buffer Overflow',
                'severity': 'high',
                'confidence': 85,
                'description': 'Unsafe use of scanf() without bounds checking'
            },
            {
                'pattern': r'gets\s*\(',
                'type': 'Buffer Overflow',
                'severity': 'critical',
                'confidence': 98,
                'description': 'Use of deprecated gets() function'
            },
            {
                'pattern': r'sprintf\s*\([^)]*\)',
                'type': 'Buffer Overflow',
                'severity': 'high',
                'confidence': 90,
                'description': 'Unsafe use of sprintf() without bounds checking'
            }
        ]
        
        import re
        
        for line_num, line in enumerate(lines, 1):
            for pattern_info in patterns:
                if re.search(pattern_info['pattern'], line):
                    vulnerabilities.append({
                        'id': len(vulnerabilities) + 1,
                        'type': pattern_info['type'],
                        'severity': pattern_info['severity'],
                        'line': line_num,
                        'file': 'input.cpp',
                        'description': pattern_info['description'],
                        'details': f"Pattern matched: {line.strip()}",
                        'confidence': pattern_info['confidence'],
                        'timestamp': time.time()
                    })
        
        return vulnerabilities
    
    def perform_system_scan(self):
        scan_results = {
            'files_scanned': 42,
            'vulnerabilities_found': 12,
            'critical_issues': 3,
            'high_issues': 5,
            'medium_issues': 4,
            'scan_duration': 2.5,
            'components': {
                'static_analyzer': {'status': 'active', 'progress': 100},
                'runtime_protection': {'status': 'active', 'progress': 95},
                'memory_tracker': {'status': 'active', 'progress': 88},
                'control_flow_guard': {'status': 'warning', 'progress': 75}
            }
        }
        
        return scan_results
    
    def get_system_status(self):
        return {
            'timestamp': time.time(),
            'components': {
                'static_analyzer': {'status': 'active', 'progress': 100},
                'runtime_protection': {'status': 'active', 'progress': 95},
                'memory_tracker': {'status': 'active', 'progress': 88},
                'control_flow_guard': {'status': 'warning', 'progress': 75}
            },
            'uptime': time.time() - self.server.start_time if hasattr(self.server, 'start_time') else 0
        }
    
    def get_metrics(self):
        return {
            'total_vulnerabilities': 4,
            'critical_vulnerabilities': 1,
            'protected_files': 15,
            'security_score': 85,
            'last_scan': time.time() - 300
        }

class DashboardServer:
    
    def __init__(self, host='localhost', port=8080):
        self.host = host
        self.port = port
        self.server = None
        self.running = False
    
    def start(self):
        try:
            self.server = HTTPServer((self.host, self.port), DashboardRequestHandler)
            self.server.start_time = time.time()
            
            logger.info(f"Starting dashboard server on {self.host}:{self.port}")
            logger.info(f"Dashboard available at: http://{self.host}:{self.port}")
            
            self.running = True
            
            server_thread = threading.Thread(target=self.server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            return False
    
    def stop(self):
        if self.server:
            logger.info("Stopping dashboard server...")
            self.server.shutdown()
            self.server.server_close()
            self.running = False
            logger.info("Dashboard server stopped")
    
    def is_running(self):
        return self.running

def signal_handler(signum, frame):
    logger.info(f"Received signal {signum}, shutting down...")
    if dashboard_server:
        dashboard_server.stop()
    sys.exit(0)

def main():
    global dashboard_server
    
    import argparse
    parser = argparse.ArgumentParser(description='Buffer Overflow Mitigation Tool Dashboard Server')
    parser.add_argument('--host', default='localhost', help='Host to bind to (default: localhost)')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to (default: 8080)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    dashboard_server = DashboardServer(args.host, args.port)
    
    if dashboard_server.start():
        try:
            while dashboard_server.is_running():
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        finally:
            dashboard_server.stop()
    else:
        logger.error("Failed to start dashboard server")
        sys.exit(1)

if __name__ == '__main__':
    main()
