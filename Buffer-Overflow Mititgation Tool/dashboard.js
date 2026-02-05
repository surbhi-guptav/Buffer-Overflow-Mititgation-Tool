
class DashboardManager {
    constructor() {
        this.vulnerabilities = [];
        this.currentLanguage = 'auto';
        this.init();
    }

    init() {
        this.updateSummaryCounts();
        this.setupEventListeners();
    }

    setupEventListeners() {
        const codeInput = document.getElementById('codeInput');
        if (codeInput) {
            codeInput.addEventListener('input', () => {
                localStorage.setItem('dashboard_code_input', codeInput.value);
                this.detectLanguage(codeInput.value);
            });
            
            const savedCode = localStorage.getItem('dashboard_code_input');
            if (savedCode) {
                codeInput.value = savedCode;
                this.detectLanguage(savedCode);
            }
        }

        let analysisTimeout;
        if (codeInput) {
            codeInput.addEventListener('input', () => {
                clearTimeout(analysisTimeout);
                analysisTimeout = setTimeout(() => {
                    this.performRealTimeAnalysis();
                }, 2000);
            });
        }
    }

    detectLanguage(code) {
        const languagePatterns = {
            'cpp': /#include\s*<[^>]+>|std::|cout\s*<<|cin\s*>>/,
            'c': /#include\s*<[^>]+>|printf\s*\(|scanf\s*\(|malloc\s*\(/,
            'java': /import\s+java\.|public\s+class|System\.out\.|Scanner\s+/,
            'python': /import\s+|def\s+|print\s*\(|input\s*\(/,
            'javascript': /function\s+|var\s+|let\s+|const\s+|console\.log/,
            'php': /<\?php|echo\s+|print\s+|mysql_|mysqli_/,
            'ruby': /def\s+|puts\s+|gets\s+|require\s+/,
            'go': /package\s+main|import\s+|fmt\.|func\s+main/,
            'rust': /fn\s+|println!\s*\(|use\s+|extern\s+crate/,
            'csharp': /using\s+System|namespace\s+|Console\.|public\s+class/
        };

        for (const [lang, pattern] of Object.entries(languagePatterns)) {
            if (pattern.test(code)) {
                this.currentLanguage = lang;
                this.updateLanguageIndicator(lang);
                return lang;
            }
        }

        this.currentLanguage = 'cpp';
        this.updateLanguageIndicator('cpp');
        return 'cpp';
    }

    updateLanguageIndicator(language) {
        const languageNames = {
            'cpp': 'C++',
            'c': 'C',
            'java': 'Java',
            'python': 'Python',
            'javascript': 'JavaScript',
            'php': 'PHP',
            'ruby': 'Ruby',
            'go': 'Go',
            'rust': 'Rust',
            'csharp': 'C#'
        };

        const codeInput = document.getElementById('codeInput');
        if (codeInput) {
            codeInput.placeholder = `Paste your ${languageNames[language]} code here to detect vulnerabilities...`;
        }

        const langIndicator = document.getElementById('languageIndicator');
        if (langIndicator) {
            langIndicator.textContent = `Detected: ${languageNames[language]}`;
        }
    }

    updateSummaryCounts() {
        const counts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            total: this.vulnerabilities.length
        };

        this.vulnerabilities.forEach(vuln => {
            counts[vuln.severity]++;
        });

        document.getElementById('criticalCount').textContent = counts.critical;
        document.getElementById('highCount').textContent = counts.high;
        document.getElementById('mediumCount').textContent = counts.medium;
        document.getElementById('lowCount').textContent = counts.low;
        document.getElementById('totalCount').textContent = counts.total;
    }

    loadSampleVulnerabilities() {
        this.vulnerabilities = [
            {
                id: 1,
                type: 'Buffer Overflow',
                severity: 'critical',
                line: 15,
                file: 'main.cpp',
                description: 'Potential stack buffer overflow in strcpy() call',
                details: 'Unsafe use of strcpy() without bounds checking',
                confidence: 95,
                timestamp: new Date()
            },
            {
                id: 2,
                type: 'Format String',
                severity: 'high',
                line: 42,
                file: 'utils.cpp',
                description: 'Uncontrolled format string in printf()',
                details: 'User input directly passed to printf() without validation',
                confidence: 87,
                timestamp: new Date()
            },
            {
                id: 3,
                type: 'Use-After-Free',
                severity: 'high',
                line: 78,
                file: 'memory.cpp',
                description: 'Potential use-after-free vulnerability',
                details: 'Pointer used after memory deallocation',
                confidence: 92,
                timestamp: new Date()
            },
            {
                id: 4,
                type: 'Integer Overflow',
                severity: 'medium',
                line: 125,
                file: 'calculator.cpp',
                description: 'Potential integer overflow in arithmetic operation',
                details: 'Multiplication result may exceed integer limits',
                confidence: 73,
                timestamp: new Date()
            }
        ];
        
        this.updateVulnerabilitiesList();
        this.updateSummaryCounts();
    }

    updateVulnerabilitiesList() {
        console.log('updateVulnerabilitiesList called with', this.vulnerabilities.length, 'vulnerabilities');
        const container = document.getElementById('vulnerabilitiesList');
        if (!container) {
            console.error('vulnerabilitiesList container not found!');
            return;
        }

        if (this.vulnerabilities.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted py-5">
                    <i class="fas fa-check-circle fa-3x mb-3 text-success"></i>
                    <h4>No vulnerabilities found!</h4>
                    <p>Your code appears to be secure. Great job!</p>
                </div>
            `;
            return;
        }

        let html = '';
        this.vulnerabilities.forEach(vuln => {
            const severityClass = this.getSeverityClass(vuln.severity);
            const badgeClass = `badge-${vuln.severity}`;
            
            html += `
                <div class="vulnerability-item ${severityClass}">
                    <div class="vulnerability-header">
                        <div class="vulnerability-info">
                            <div class="vulnerability-title">${vuln.type}</div>
                            <div class="vulnerability-description">${vuln.description}</div>
                            <div class="vulnerability-meta">
                                <i class="fas fa-file-code me-1"></i>${vuln.file} | 
                                <i class="fas fa-code-branch me-1"></i>Line ${vuln.line} | 
                                <i class="fas fa-chart-line me-1"></i>Confidence: ${vuln.confidence}%
                            </div>
                        </div>
                        <span class="vulnerability-badge ${badgeClass}">${vuln.severity.toUpperCase()}</span>
                    </div>
                    <div class="vulnerability-actions">
                        <button class="btn btn-sm btn-outline-primary" onclick="showVulnerabilityDetails(${vuln.id})">
                            <i class="fas fa-info-circle me-1"></i>Details
                        </button>
                        <button class="btn btn-sm btn-outline-success" onclick="generateFix(${vuln.id})">
                            <i class="fas fa-wrench me-1"></i>Generate Fix
                        </button>
                        <button class="btn btn-sm btn-outline-warning" onclick="ignoreVulnerability(${vuln.id})">
                            <i class="fas fa-eye-slash me-1"></i>Ignore
                        </button>
                    </div>
                </div>
            `;
        });

        container.innerHTML = html;
        
        const vulnCount = document.getElementById('vulnCount');
        if (vulnCount) {
            vulnCount.textContent = this.vulnerabilities.length;
        }
        
        this.updateDetailsTab();
        this.updateFixesTab();
        this.updateReportTab();
    }

    updateDetailsTab() {
        const container = document.getElementById('vulnerabilityDetails');
        if (!container) return;

        if (this.vulnerabilities.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted py-5">
                    <i class="fas fa-info-circle fa-3x mb-3"></i>
                    <h4>No detailed analysis available</h4>
                    <p>Scan for vulnerabilities first to see detailed analysis</p>
                </div>
            `;
            return;
        }

        let html = '<div class="row">';
        
        const stats = this.getVulnerabilityStats();
        html += `
            <div class="col-md-6 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-chart-pie me-2"></i>Vulnerability Statistics</h5>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <strong>Total Vulnerabilities:</strong> ${stats.total}
                        </div>
                        <div class="mb-3">
                            <strong>Critical:</strong> ${stats.critical} (${stats.criticalPercent}%)
                        </div>
                        <div class="mb-3">
                            <strong>High:</strong> ${stats.high} (${stats.highPercent}%)
                        </div>
                        <div class="mb-3">
                            <strong>Medium:</strong> ${stats.medium} (${stats.mediumPercent}%)
                        </div>
                        <div class="mb-3">
                            <strong>Low:</strong> ${stats.low} (${stats.lowPercent}%)
                        </div>
                        <div class="mb-3">
                            <strong>Average Confidence:</strong> ${stats.avgConfidence}%
                        </div>
                    </div>
                </div>
            </div>
        `;

        html += `
            <div class="col-md-6 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-code me-2"></i>Language Analysis</h5>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <strong>Detected Language:</strong> ${this.getLanguageName(this.currentLanguage)}
                        </div>
                        <div class="mb-3">
                            <strong>File Extension:</strong> .${this.getFileExtension(this.currentLanguage)}
                        </div>
                        <div class="mb-3">
                            <strong>Scan Patterns:</strong> ${this.getVulnerabilityPatterns(this.currentLanguage).length} patterns checked
                        </div>
                        <div class="mb-3">
                            <strong>Scan Time:</strong> ${new Date().toLocaleTimeString()}
                        </div>
                    </div>
                </div>
            </div>
        `;

        html += `
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-list-alt me-2"></i>Detailed Vulnerability Breakdown</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Type</th>
                                        <th>Severity</th>
                                        <th>Count</th>
                                        <th>Confidence</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
        `;

        const typeStats = this.getVulnerabilityTypeStats();
        typeStats.forEach(stat => {
            const severityClass = this.getSeverityClass(stat.severity);
            html += `
                <tr>
                    <td><strong>${stat.type}</strong></td>
                    <td><span class="badge badge-${severityClass}">${stat.severity.toUpperCase()}</span></td>
                    <td>${stat.count}</td>
                    <td>${stat.avgConfidence}%</td>
                    <td>${stat.description}</td>
                </tr>
            `;
        });

        html += `
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        `;

        html += '</div>';
        container.innerHTML = html;
    }

    updateFixesTab() {
        const container = document.getElementById('securityFixes');
        if (!container) return;

        if (this.vulnerabilities.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted py-5">
                    <i class="fas fa-wrench fa-3x mb-3"></i>
                    <h4>No security fixes available</h4>
                    <p>Scan for vulnerabilities first to see recommended fixes</p>
                </div>
            `;
            return;
        }

        let html = '';
        
        const groupedVulns = this.groupVulnerabilitiesByType();
        
        Object.keys(groupedVulns).forEach(vulnType => {
            const vulns = groupedVulns[vulnType];
            const firstVuln = vulns[0];
            
            html += `
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            ${vulnType} (${vulns.length} instances)
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6><i class="fas fa-info-circle me-2"></i>Problem Description</h6>
                                <p>${firstVuln.description}</p>
                                
                                <h6><i class="fas fa-map-marker-alt me-2"></i>Affected Lines</h6>
                                <ul>
            `;
            
            vulns.forEach(vuln => {
                html += `<li>Line ${vuln.line}: ${vuln.details}</li>`;
            });
            
            html += `
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <h6><i class="fas fa-shield-alt me-2"></i>Recommended Fix</h6>
                                <div class="bg-light p-3 rounded">
                                    <pre><code>${this.getFixForVulnerabilityType(vulnType, this.currentLanguage)}</code></pre>
                                </div>
                                
                                <h6 class="mt-3"><i class="fas fa-lightbulb me-2"></i>Best Practices</h6>
                                <ul>
            `;
            
            const bestPractices = this.getBestPracticesForType(vulnType, this.currentLanguage);
            bestPractices.forEach(practice => {
                html += `<li>${practice}</li>`;
            });
            
            html += `
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });

        container.innerHTML = html;
    }

    updateReportTab() {
        const container = document.getElementById('securityReport');
        if (!container) return;

        if (this.vulnerabilities.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted py-5">
                    <i class="fas fa-file-alt fa-3x mb-3"></i>
                    <h4>No security report available</h4>
                    <p>Scan for vulnerabilities first to generate a security report</p>
                </div>
            `;
            return;
        }

        const stats = this.getVulnerabilityStats();
        const report = this.generateSecurityReport();
        
        let html = `
            <div class="row">
                <div class="col-12 mb-4">
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5 class="mb-0"><i class="fas fa-file-alt me-2"></i>Security Analysis Report</h5>
                            <button class="btn btn-sm btn-outline-primary" onclick="downloadReport()">
                                <i class="fas fa-download me-2"></i>Download Report
                            </button>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <h6>Executive Summary</h6>
                                    <p>${report.executiveSummary}</p>
                                    
                                    <h6>Risk Assessment</h6>
                                    <p>${report.riskAssessment}</p>
                                </div>
                                <div class="col-md-6">
                                    <h6>Key Findings</h6>
                                    <ul>
                                        <li>Total vulnerabilities: ${stats.total}</li>
                                        <li>Critical issues: ${stats.critical}</li>
                                        <li>High priority: ${stats.high}</li>
                                        <li>Medium priority: ${stats.medium}</li>
                                        <li>Low priority: ${stats.low}</li>
                                    </ul>
                                    
                                    <h6>Recommendations</h6>
                                    <p>${report.recommendations}</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0"><i class="fas fa-chart-bar me-2"></i>Detailed Findings</h5>
                        </div>
                        <div class="card-body">
                            ${report.detailedFindings}
                        </div>
                    </div>
                </div>
            </div>
        `;

        container.innerHTML = html;
    }

    getVulnerabilityStats() {
        const stats = {
            total: this.vulnerabilities.length,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            criticalPercent: 0,
            highPercent: 0,
            mediumPercent: 0,
            lowPercent: 0,
            avgConfidence: 0
        };

        let totalConfidence = 0;
        this.vulnerabilities.forEach(vuln => {
            stats[vuln.severity]++;
            totalConfidence += vuln.confidence;
        });

        if (stats.total > 0) {
            stats.criticalPercent = Math.round((stats.critical / stats.total) * 100);
            stats.highPercent = Math.round((stats.high / stats.total) * 100);
            stats.mediumPercent = Math.round((stats.medium / stats.total) * 100);
            stats.lowPercent = Math.round((stats.low / stats.total) * 100);
            stats.avgConfidence = Math.round(totalConfidence / stats.total);
        }

        return stats;
    }

    getVulnerabilityTypeStats() {
        const typeStats = {};
        
        this.vulnerabilities.forEach(vuln => {
            if (!typeStats[vuln.type]) {
                typeStats[vuln.type] = {
                    type: vuln.type,
                    severity: vuln.severity,
                    count: 0,
                    totalConfidence: 0,
                    description: vuln.description
                };
            }
            typeStats[vuln.type].count++;
            typeStats[vuln.type].totalConfidence += vuln.confidence;
        });

        return Object.values(typeStats).map(stat => ({
            ...stat,
            avgConfidence: Math.round(stat.totalConfidence / stat.count)
        }));
    }

    groupVulnerabilitiesByType() {
        const grouped = {};
        this.vulnerabilities.forEach(vuln => {
            if (!grouped[vuln.type]) {
                grouped[vuln.type] = [];
            }
            grouped[vuln.type].push(vuln);
        });
        return grouped;
    }

    getLanguageName(language) {
        const languageNames = {
            'cpp': 'C++',
            'c': 'C',
            'java': 'Java',
            'python': 'Python',
            'javascript': 'JavaScript',
            'php': 'PHP',
            'ruby': 'Ruby',
            'go': 'Go',
            'rust': 'Rust',
            'csharp': 'C#'
        };
        return languageNames[language] || 'Unknown';
    }

    getFixForVulnerabilityType(vulnType, language) {
        const fixes = {
            'Buffer Overflow': {
                'cpp': `// Replace unsafe functions with safe alternatives
// Instead of: strcpy(buffer, input);
strncpy(buffer, input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\\0';

// Instead of: scanf("%s", input);
scanf("%99s", input);  // Limit input size

// Instead of: gets(input);
fgets(input, sizeof(input), stdin);`,
                'c': `// Replace unsafe functions with safe alternatives
// Instead of: strcpy(buffer, input);
strncpy(buffer, input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\\0';

// Instead of: scanf("%s", input);
scanf("%99s", input);  // Limit input size`,
                'java': `// Use proper input validation
// Instead of: Runtime.getRuntime().exec(userInput);
String[] command = {"ls", "-la"};  // Use array instead of string
Process process = Runtime.getRuntime().exec(command);

// Validate user input before processing
if (userInput.matches("^[a-zA-Z0-9]+$")) {
    // Process valid input
}`,
                'python': `# Use safe alternatives
# Instead of: eval(user_input)
import ast
try:
    result = ast.literal_eval(user_input)  # Safe evaluation
except:
    print("Invalid input")

# Instead of: os.system(user_input)
import subprocess
subprocess.run(['ls', '-la'], check=True)  # Use list instead of string`,
                'javascript': `// Use safe alternatives
// Instead of: eval(userInput)
const result = JSON.parse(userInput);  // Safe parsing

// Instead of: element.innerHTML = userInput;
element.textContent = userInput;  // Safe content setting

// Instead of: document.write(userInput);
document.getElementById('output').textContent = userInput;`,
                'php': `<?php
// Use safe alternatives
// Instead of: eval($userInput);
$result = json_decode($userInput, true);  // Safe parsing

// Instead of: exec($userInput);
$command = escapeshellcmd($userInput);  // Escape shell commands
exec($command);

// Instead of: mysql_query("SELECT * FROM users WHERE name = '$userInput'");
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
$stmt->execute([$userInput]);  // Use prepared statements
?>`
            },
            'SQL Injection': {
                'java': `// Use prepared statements
// Instead of: "SELECT * FROM users WHERE name = '" + userInput + "'"
String sql = "SELECT * FROM users WHERE name = ?";
PreparedStatement stmt = connection.prepareStatement(sql);
stmt.setString(1, userInput);
ResultSet rs = stmt.executeQuery();`,
                'python': `# Use parameterized queries
# Instead of: "SELECT * FROM users WHERE name = '" + user_input + "'"
cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))`,
                'php': `<?php
// Use prepared statements
// Instead of: mysql_query("SELECT * FROM users WHERE name = '$userInput'");
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
$stmt->execute([$userInput]);
?>`
            },
            'XSS': {
                'javascript': `// Use safe content setting
// Instead of: element.innerHTML = userInput;
element.textContent = userInput;

// Or use DOMPurify for HTML content
const cleanHTML = DOMPurify.sanitize(userInput);
element.innerHTML = cleanHTML;`,
                'php': `<?php
// Use htmlspecialchars for output
// Instead of: echo $userInput;
echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
?>`
            }
        };

        return fixes[vulnType]?.[language] || `// Fix for ${vulnType} in ${language}
// Replace vulnerable code with secure alternative
// Example: Validate input, use safe functions, implement proper error handling`;
    }

    getBestPracticesForType(vulnType, language) {
        const practices = {
            'Buffer Overflow': [
                'Always validate input length before copying',
                'Use safe string functions (strncpy, strncat)',
                'Implement proper bounds checking',
                'Use modern C++ containers (std::string, std::vector)',
                'Enable compiler warnings and static analysis'
            ],
            'SQL Injection': [
                'Use parameterized queries/prepared statements',
                'Validate and sanitize all user inputs',
                'Use ORM frameworks when possible',
                'Implement proper error handling',
                'Use least privilege database accounts'
            ],
            'XSS': [
                'Encode all user input before output',
                'Use Content Security Policy (CSP)',
                'Validate input on both client and server side',
                'Use safe DOM manipulation methods',
                'Implement proper session management'
            ],
            'Code Injection': [
                'Never use eval() or similar functions with user input',
                'Validate all user inputs thoroughly',
                'Use safe parsing methods (JSON.parse, ast.literal_eval)',
                'Implement proper input sanitization',
                'Use whitelist validation approach'
            ]
        };

        return practices[vulnType] || [
            'Validate all user inputs',
            'Use secure coding practices',
            'Implement proper error handling',
            'Follow the principle of least privilege',
            'Keep dependencies updated'
        ];
    }

    generateSecurityReport() {
        const stats = this.getVulnerabilityStats();
        const language = this.getLanguageName(this.currentLanguage);
        
        let riskLevel = 'Low';
        if (stats.critical > 0) riskLevel = 'Critical';
        else if (stats.high > 0) riskLevel = 'High';
        else if (stats.medium > 0) riskLevel = 'Medium';

        return {
            executiveSummary: `This security analysis of ${language} code identified ${stats.total} vulnerabilities with ${stats.critical} critical issues requiring immediate attention.`,
            riskAssessment: `The overall risk level is ${riskLevel}. ${stats.critical} critical vulnerabilities pose immediate security threats that should be addressed before deployment.`,
            recommendations: `Prioritize fixing critical and high-severity vulnerabilities first. Implement secure coding practices and consider using automated security testing tools.`,
            detailedFindings: this.generateDetailedFindings()
        };
    }

    generateDetailedFindings() {
        const typeStats = this.getVulnerabilityTypeStats();
        let html = '<div class="table-responsive"><table class="table table-striped">';
        html += '<thead><tr><th>Vulnerability Type</th><th>Count</th><th>Severity</th><th>Risk Level</th></tr></thead><tbody>';
        
        typeStats.forEach(stat => {
            const riskLevel = stat.severity === 'critical' ? 'Critical' : 
                            stat.severity === 'high' ? 'High' : 
                            stat.severity === 'medium' ? 'Medium' : 'Low';
            
            html += `<tr>
                <td>${stat.type}</td>
                <td>${stat.count}</td>
                <td><span class="badge badge-${this.getSeverityClass(stat.severity)}">${stat.severity.toUpperCase()}</span></td>
                <td>${riskLevel}</td>
            </tr>`;
        });
        
        html += '</tbody></table></div>';
        return html;
    }

    getSeverityClass(severity) {
        const classes = {
            'low': 'low',
            'medium': 'medium',
            'high': 'high',
            'critical': 'critical'
        };
        return classes[severity] || 'medium';
    }

    performRealTimeAnalysis() {
        const codeInput = document.getElementById('codeInput');
        if (!codeInput || !codeInput.value.trim()) return;

        this.showLoadingState();
        
        setTimeout(() => {
            this.analyzeCode(codeInput.value);
            this.hideLoadingState();
        }, 1000);
    }

    analyzeCode(code) {
        console.log('Dashboard analyzeCode called with:', code.substring(0, 100) + '...');
        
        if (!code || !code.trim()) {
            this.showNotification('Please enter some code to analyze.', 'warning');
            return;
        }
        
        this.showLoadingState();
        
        setTimeout(() => {
            console.log('Starting vulnerability detection...');
            const vulnerabilities = this.detectVulnerabilities(code);
            console.log('Detected vulnerabilities:', vulnerabilities);
            
            this.vulnerabilities = vulnerabilities;
            this.updateVulnerabilitiesList();
            this.updateSummaryCounts();
            this.hideLoadingState();
            this.showAnalysisComplete();
        }, 500);
    }

    detectVulnerabilities(code) {
        console.log('detectVulnerabilities called with language:', this.currentLanguage);
        
        const vulnerabilities = [];
        const language = this.currentLanguage;
        
        const patterns = this.getVulnerabilityPatterns(language);
        console.log('Using patterns for language:', language, 'Pattern count:', patterns.length);
        
        const lines = code.split('\n');
        let vulnId = 1;
        
        patterns.forEach((pattern, patternIndex) => {
            lines.forEach((line, lineNum) => {
                if (pattern.pattern.test(line)) {
                    console.log(`Pattern ${patternIndex} matched on line ${lineNum + 1}:`, line.trim());
                    vulnerabilities.push({
                        id: vulnId++,
                        type: pattern.type,
                        severity: pattern.severity,
                        line: lineNum + 1,
                        file: `input.${this.getFileExtension(language)}`,
                        description: pattern.description,
                        details: `Pattern matched: ${line.trim()}`,
                        confidence: pattern.confidence,
                        timestamp: new Date()
                    });
                }
            });
        });

        console.log('Total vulnerabilities detected:', vulnerabilities.length);
        return vulnerabilities;
    }

    getFileExtension(language) {
        const extensions = {
            'cpp': 'cpp',
            'c': 'c',
            'java': 'java',
            'python': 'py',
            'javascript': 'js',
            'php': 'php',
            'ruby': 'rb',
            'go': 'go',
            'rust': 'rs',
            'csharp': 'cs'
        };
        return extensions[language] || 'txt';
    }

    getVulnerabilityPatterns(language) {
        const patterns = {
            'cpp': [
                { pattern: /strcpy\s*\(/, type: 'Buffer Overflow', severity: 'critical', confidence: 95, description: 'Unsafe use of strcpy() without bounds checking' },
                { pattern: /printf\s*\([^)]*%[^)]*\)/, type: 'Format String', severity: 'high', confidence: 87, description: 'Uncontrolled format string usage' },
                { pattern: /free\s*\([^)]*\)[^;]*\1/, type: 'Use-After-Free', severity: 'high', confidence: 92, description: 'Potential use-after-free vulnerability' },
                { pattern: /\*\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[^;]*malloc/, type: 'Memory Leak', severity: 'medium', confidence: 78, description: 'Potential memory leak' },
                { pattern: /scanf\s*\([^)]*\)/, type: 'Buffer Overflow', severity: 'high', confidence: 85, description: 'Unsafe use of scanf() without bounds checking' },
                { pattern: /gets\s*\(/, type: 'Buffer Overflow', severity: 'critical', confidence: 98, description: 'Use of deprecated gets() function' },
                { pattern: /sprintf\s*\([^)]*\)/, type: 'Buffer Overflow', severity: 'high', confidence: 90, description: 'Unsafe use of sprintf() without bounds checking' },
                { pattern: /strcat\s*\(/, type: 'Buffer Overflow', severity: 'high', confidence: 88, description: 'Unsafe use of strcat() without bounds checking' }
            ],
            'c': [
                { pattern: /strcpy\s*\(/, type: 'Buffer Overflow', severity: 'critical', confidence: 95, description: 'Unsafe use of strcpy() without bounds checking' },
                { pattern: /printf\s*\([^)]*%[^)]*\)/, type: 'Format String', severity: 'high', confidence: 87, description: 'Uncontrolled format string usage' },
                { pattern: /malloc\s*\([^)]*\)/, type: 'Memory Management', severity: 'medium', confidence: 75, description: 'Potential memory management issue' },
                { pattern: /scanf\s*\([^)]*\)/, type: 'Buffer Overflow', severity: 'high', confidence: 85, description: 'Unsafe use of scanf() without bounds checking' },
                { pattern: /gets\s*\(/, type: 'Buffer Overflow', severity: 'critical', confidence: 98, description: 'Use of deprecated gets() function' }
            ],
            'java': [
                { pattern: /System\.out\.println\s*\([^)]*\+[^)]*\)/, type: 'Information Disclosure', severity: 'medium', confidence: 70, description: 'Potential information disclosure in console output' },
                { pattern: /Runtime\.getRuntime\(\)\.exec\s*\(/, type: 'Command Injection', severity: 'critical', confidence: 90, description: 'Potential command injection vulnerability' },
                { pattern: /ProcessBuilder\s*\(/, type: 'Command Injection', severity: 'high', confidence: 85, description: 'Potential command injection with ProcessBuilder' },
                { pattern: /Class\.forName\s*\(/, type: 'Reflection Attack', severity: 'high', confidence: 80, description: 'Potential reflection-based attack' },
                { pattern: /ObjectInputStream\s*\(/, type: 'Deserialization', severity: 'critical', confidence: 95, description: 'Unsafe deserialization vulnerability' },
                { pattern: /SQL\s*\+/, type: 'SQL Injection', severity: 'critical', confidence: 92, description: 'Potential SQL injection vulnerability' }
            ],
            'python': [
                { pattern: /eval\s*\(/, type: 'Code Injection', severity: 'critical', confidence: 95, description: 'Unsafe use of eval() function' },
                { pattern: /exec\s*\(/, type: 'Code Injection', severity: 'critical', confidence: 95, description: 'Unsafe use of exec() function' },
                { pattern: /input\s*\(/, type: 'Input Validation', severity: 'medium', confidence: 65, description: 'Unvalidated user input' },
                { pattern: /os\.system\s*\(/, type: 'Command Injection', severity: 'critical', confidence: 90, description: 'Potential command injection with os.system()' },
                { pattern: /subprocess\.call\s*\(/, type: 'Command Injection', severity: 'high', confidence: 85, description: 'Potential command injection with subprocess' },
                { pattern: /pickle\.loads\s*\(/, type: 'Deserialization', severity: 'critical', confidence: 95, description: 'Unsafe deserialization with pickle' },
                { pattern: /sqlite3\.execute\s*\([^)]*\+/, type: 'SQL Injection', severity: 'critical', confidence: 92, description: 'Potential SQL injection vulnerability' }
            ],
            'javascript': [
                { pattern: /eval\s*\(/, type: 'Code Injection', severity: 'critical', confidence: 95, description: 'Unsafe use of eval() function' },
                { pattern: /innerHTML\s*=/, type: 'XSS', severity: 'critical', confidence: 90, description: 'Potential XSS vulnerability with innerHTML' },
                { pattern: /document\.write\s*\(/, type: 'XSS', severity: 'high', confidence: 85, description: 'Potential XSS vulnerability with document.write()' },
                { pattern: /setTimeout\s*\([^,]*\+/, type: 'Code Injection', severity: 'high', confidence: 80, description: 'Potential code injection with setTimeout' },
                { pattern: /Function\s*\(/, type: 'Code Injection', severity: 'critical', confidence: 90, description: 'Unsafe use of Function constructor' },
                { pattern: /localStorage\s*\[[^\]]*\]\s*=/, type: 'Data Storage', severity: 'medium', confidence: 70, description: 'Sensitive data stored in localStorage' }
            ],
            'php': [
                { pattern: /eval\s*\(/, type: 'Code Injection', severity: 'critical', confidence: 95, description: 'Unsafe use of eval() function' },
                { pattern: /exec\s*\(/, type: 'Command Injection', severity: 'critical', confidence: 90, description: 'Potential command injection with exec()' },
                { pattern: /system\s*\(/, type: 'Command Injection', severity: 'critical', confidence: 90, description: 'Potential command injection with system()' },
                { pattern: /mysql_query\s*\([^)]*\+/, type: 'SQL Injection', severity: 'critical', confidence: 92, description: 'Potential SQL injection vulnerability' },
                { pattern: /mysqli_query\s*\([^)]*\+/, type: 'SQL Injection', severity: 'critical', confidence: 92, description: 'Potential SQL injection vulnerability' },
                { pattern: /include\s*\$/, type: 'File Inclusion', severity: 'critical', confidence: 95, description: 'Potential file inclusion vulnerability' },
                { pattern: /require\s*\$/, type: 'File Inclusion', severity: 'critical', confidence: 95, description: 'Potential file inclusion vulnerability' }
            ],
            'ruby': [
                { pattern: /eval\s*\(/, type: 'Code Injection', severity: 'critical', confidence: 95, description: 'Unsafe use of eval() function' },
                { pattern: /system\s*\(/, type: 'Command Injection', severity: 'critical', confidence: 90, description: 'Potential command injection with system()' },
                { pattern: /`[^`]*\$/, type: 'Command Injection', severity: 'critical', confidence: 90, description: 'Potential command injection with backticks' },
                { pattern: /exec\s*\(/, type: 'Command Injection', severity: 'critical', confidence: 90, description: 'Potential command injection with exec()' },
                { pattern: /ActiveRecord::Base\.connection\.execute\s*\([^)]*\+/, type: 'SQL Injection', severity: 'critical', confidence: 92, description: 'Potential SQL injection vulnerability' }
            ],
            'go': [
                { pattern: /exec\.Command\s*\(/, type: 'Command Injection', severity: 'high', confidence: 85, description: 'Potential command injection with exec.Command' },
                { pattern: /fmt\.Sprintf\s*\([^)]*\+/, type: 'Format String', severity: 'medium', confidence: 70, description: 'Potential format string vulnerability' },
                { pattern: /database\/sql\.Query\s*\([^)]*\+/, type: 'SQL Injection', severity: 'critical', confidence: 92, description: 'Potential SQL injection vulnerability' }
            ],
            'rust': [
                { pattern: /unsafe\s*\{/, type: 'Unsafe Code', severity: 'medium', confidence: 75, description: 'Use of unsafe Rust code block' },
                { pattern: /std::process::Command::new\s*\(/, type: 'Command Execution', severity: 'high', confidence: 80, description: 'Command execution with user input' }
            ],
            'csharp': [
                { pattern: /Process\.Start\s*\(/, type: 'Command Injection', severity: 'high', confidence: 85, description: 'Potential command injection with Process.Start' },
                { pattern: /SqlCommand\s*\([^)]*\+/, type: 'SQL Injection', severity: 'critical', confidence: 92, description: 'Potential SQL injection vulnerability' },
                { pattern: /HttpUtility\.HtmlEncode\s*\([^)]*\)/, type: 'XSS Prevention', severity: 'low', confidence: 60, description: 'Good practice: HTML encoding used' }
            ]
        };

        return patterns[language] || patterns['cpp'];
    }

    showLoadingState() {
        const button = document.querySelector('button[onclick="analyzeCode()"]');
        if (button) {
            button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Scanning...';
            button.disabled = true;
        }
    }

    hideLoadingState() {
        const button = document.querySelector('button[onclick="analyzeCode()"]');
        if (button) {
            button.innerHTML = '<i class="fas fa-search me-2"></i>Scan for Vulnerabilities';
            button.disabled = false;
        }
    }

    showAnalysisComplete() {
        this.showNotification('Vulnerability scan completed!', 'success');
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
    }
}

function analyzeCode() {
    console.log('analyzeCode function called');
    const codeInput = document.getElementById('codeInput');
    console.log('Code input element:', codeInput);
    console.log('Dashboard object:', dashboard);
    
    if (codeInput && codeInput.value.trim()) {
        console.log('Code to analyze:', codeInput.value.substring(0, 100) + '...');
        dashboard.analyzeCode(codeInput.value);
    } else {
        console.log('No code provided');
        if (dashboard) {
            dashboard.showNotification('Please enter some code to analyze.', 'warning');
        } else {
            alert('Dashboard not initialized. Please refresh the page.');
        }
    }
}

function clearCode() {
    const codeInput = document.getElementById('codeInput');
    if (codeInput) {
        codeInput.value = '';
        localStorage.removeItem('dashboard_code_input');
        dashboard.vulnerabilities = [];
        dashboard.updateVulnerabilitiesList();
        dashboard.updateSummaryCounts();
    }
}

function loadSample() {
    const language = dashboard.currentLanguage;
    const samples = {
        'cpp': `#include <iostream>
#include <cstring>
#include <cstdio>

int main() {
    char buffer[10];
    char input[100];
    
    // Vulnerable code examples
    printf("Enter your name: ");
    scanf("%s", input);  // Buffer overflow vulnerability
    
    strcpy(buffer, input);  // Another buffer overflow
    
    printf(input);  // Format string vulnerability
    
    char* ptr = (char*)malloc(10);
    free(ptr);
    *ptr = 'A';  // Use-after-free vulnerability
    
    return 0;
}`,
        'java': `import java.util.Scanner;
import java.sql.*;

public class VulnerableApp {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String userInput = scanner.nextLine();
        
        // Vulnerable code examples
        System.out.println("User input: " + userInput);  // Information disclosure
        
        try {
            Runtime.getRuntime().exec(userInput);  // Command injection
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // SQL injection
        String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
    }
}`,
        'python': `import os
import subprocess
import sqlite3

# Vulnerable code examples
user_input = input("Enter command: ")

# Command injection vulnerabilities
os.system(user_input)  # Critical vulnerability
subprocess.call(user_input, shell=True)  # Another command injection

# Code injection
eval(user_input)  # Critical vulnerability
exec(user_input)  # Critical vulnerability

# SQL injection
conn = sqlite3.connect('database.db')
query = "SELECT * FROM users WHERE name = '" + user_input + "'"
conn.execute(query)`,
        'javascript': `// Vulnerable JavaScript code examples
const userInput = prompt("Enter some input:");

// Code injection vulnerabilities
eval(userInput);  // Critical vulnerability

// XSS vulnerabilities
document.getElementById("output").innerHTML = userInput;  // Critical XSS
document.write(userInput);  // Another XSS vulnerability

// Command injection
setTimeout(userInput, 1000);  // Potential code injection

// Unsafe function constructor
new Function(userInput);  // Critical vulnerability`,
        'php': `<?php
// Vulnerable PHP code examples
$userInput = $_GET['input'];

// Code injection
eval($userInput);  // Critical vulnerability

// Command injection
exec($userInput);  // Critical vulnerability
system($userInput);  // Critical vulnerability

// SQL injection
$query = "SELECT * FROM users WHERE name = '" . $userInput . "'";
mysql_query($query);

// File inclusion
include($userInput);  // Critical vulnerability
require($userInput);  // Critical vulnerability
?>`,
        'ruby': `# Vulnerable Ruby code examples
user_input = gets.chomp

# Code injection
eval(user_input)  # Critical vulnerability

# Command injection
system(user_input)  # Critical vulnerability
exec(user_input)  # Critical vulnerability

# SQL injection
query = "SELECT * FROM users WHERE name = '#{user_input}'"
ActiveRecord::Base.connection.execute(query)`,
        'go': `package main

import (
    "fmt"
    "os/exec"
    "database/sql"
)

func main() {
    userInput := "user provided input"
    
    // Command injection
    exec.Command(userInput)  // High risk
    
    // Format string vulnerability
    fmt.Sprintf("User input: %s", userInput)  // Medium risk
    
    // SQL injection
    query := "SELECT * FROM users WHERE name = '" + userInput + "'"
    db.Query(query)  // Critical vulnerability
}`,
        'rust': `fn main() {
    let user_input = "user provided input";
    
    // Unsafe code block
    unsafe {
        // This is unsafe Rust code
        let ptr = user_input.as_ptr();
    }
    
    // Command execution
    std::process::Command::new(user_input);  // High risk
}`,
        'csharp': `using System;
using System.Diagnostics;
using System.Data.SqlClient;

class VulnerableApp {
    static void Main(string[] args) {
        string userInput = Console.ReadLine();
        
        // Command injection
        Process.Start(userInput);  // High risk
        
        // SQL injection
        string query = "SELECT * FROM users WHERE name = '" + userInput + "'";
        SqlCommand cmd = new SqlCommand(query);
    }
}`
    };

    const sampleCode = samples[language] || samples['cpp'];
    const codeInput = document.getElementById('codeInput');
    if (codeInput) {
        codeInput.value = sampleCode;
        dashboard.analyzeCode(sampleCode);
    }
}

function showVulnerabilityDetails(id) {
    const vuln = dashboard.vulnerabilities.find(v => v.id === id);
    if (vuln) {
        const details = `
Vulnerability Details:
- Type: ${vuln.type}
- Severity: ${vuln.severity}
- File: ${vuln.file}
- Line: ${vuln.line}
- Description: ${vuln.description}
- Details: ${vuln.details}
- Confidence: ${vuln.confidence}%
- Detected: ${vuln.timestamp.toLocaleString()}
        `;
        alert(details);
    }
}

function generateFix(id) {
    const vuln = dashboard.vulnerabilities.find(v => v.id === id);
    if (vuln) {
        dashboard.showNotification(`Generating fix for ${vuln.type} vulnerability...`, 'info');
        setTimeout(() => {
            const fix = `// Fix for ${vuln.type} at line ${vuln.line}
// Replace vulnerable code with secure alternative
// Example: Use strncpy instead of strcpy, validate input, etc.`;
            alert(fix);
            dashboard.showNotification('Fix generated! Check the alert for details.', 'success');
        }, 1000);
    }
}

function ignoreVulnerability(id) {
    const index = dashboard.vulnerabilities.findIndex(v => v.id === id);
    if (index !== -1) {
        dashboard.vulnerabilities.splice(index, 1);
        dashboard.updateVulnerabilitiesList();
        dashboard.updateSummaryCounts();
        dashboard.showNotification('Vulnerability ignored.', 'warning');
    }
}

function testScan() {
    console.log('Test scan function called');
    const testCode = `#include <iostream>
#include <cstring>

int main() {
    char buffer[10];
    char input[100];
    
    strcpy(buffer, input);  // Buffer overflow
    printf(input);  // Format string
    
    return 0;
}`;
    
    const codeInput = document.getElementById('codeInput');
    if (codeInput) {
        codeInput.value = testCode;
        if (dashboard) {
            dashboard.analyzeCode(testCode);
        } else {
            alert('Dashboard not initialized!');
        }
    }
}

function downloadReport() {
    const stats = dashboard.getVulnerabilityStats();
    const report = dashboard.generateSecurityReport();
    const language = dashboard.getLanguageName(dashboard.currentLanguage);
    
    const reportData = {
        timestamp: new Date().toISOString(),
        language: language,
        summary: {
            totalVulnerabilities: stats.total,
            critical: stats.critical,
            high: stats.high,
            medium: stats.medium,
            low: stats.low,
            averageConfidence: stats.avgConfidence
        },
        vulnerabilities: dashboard.vulnerabilities,
        executiveSummary: report.executiveSummary,
        riskAssessment: report.riskAssessment,
        recommendations: report.recommendations
    };
    
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security_report_${language}_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    
    dashboard.showNotification('Security report downloaded successfully!', 'success');
}

let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    console.log('Initializing dashboard...');
    dashboard = new DashboardManager();
    console.log('Dashboard initialized:', dashboard);
});

setInterval(() => {
    if (dashboard) {
        dashboard.updateSummaryCounts();
    }
}, 30000);
