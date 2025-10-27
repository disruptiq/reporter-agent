#!/usr/bin/env python3
"""
Cybersecurity Reporter Agent

This agent processes outputs from various security scanners in a specified directory
and generates a comprehensive HTML cybersecurity report with findings organized by severity and type.

Features:
- Processes JSON and YAML files from security tools
- Extracts and categorizes cybersecurity findings
- Generates HTML reports with improved structure and styling
- Skips large files to avoid memory issues
- Creates organized repository structure
"""

import os
import json
import yaml
import pathlib
import argparse
import sys
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import shutil
import concurrent.futures
import threading

@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: str
    category: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    tool: Optional[str] = None
    confidence: Optional[float] = None
    evidence: Optional[str] = None

@dataclass
class ReportSection:
    title: str
    findings: List[Finding]
    summary: str

class CybersecurityReporterAgent:
    def __init__(self, outputs_dir: str = "inputs", max_file_size_mb: int = 100):
        self.outputs_dir = pathlib.Path(outputs_dir)
        self.max_file_size_mb = max_file_size_mb
        self.findings: List[Finding] = []
        self.file_count = 0
        self.skipped_files = 0
        self.findings_lock = threading.Lock()

    def should_process_file(self, file_path: pathlib.Path) -> bool:
        """Check if file should be processed based on size and name."""
        # Skip files with "raw_one_file_output" in name
        if "raw_one_file_output" in file_path.name.lower():
            return False

        # Check file size
        try:
            size_mb = file_path.stat().st_size / (1024 * 1024)
            if size_mb > self.max_file_size_mb:
                print(f"Skipping large file: {file_path} ({size_mb:.2f} MB)")
                return False
        except OSError:
            return False

        return True

    def parse_json_file(self, file_path: pathlib.Path) -> Dict[str, Any]:
        """Parse JSON file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def parse_yaml_file(self, file_path: pathlib.Path) -> Dict[str, Any]:
        """Parse YAML file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def extract_findings_from_json(self, data: Dict[str, Any], tool_name: str) -> List[Finding]:
        """Extract findings from JSON data."""
        findings = []

        # Handle obfuscation checker output
        if "findings" in data and isinstance(data["findings"], list):
            for finding in data["findings"]:
                findings.append(Finding(
                    id=str(finding.get("id", len(findings))),
                    title=finding.get("obfuscation_type", "Obfuscation Finding"),
                    description=finding.get("description", ""),
                    severity=finding.get("severity", "unknown"),
                    category=finding.get("category", "obfuscation"),
                    file_path=finding.get("file_path"),
                    line_number=finding.get("line_number"),
                    tool=tool_name,
                    confidence=finding.get("confidence"),
                    evidence=finding.get("evidence")
                ))

        # Handle static analysis output
        if "results" in data and isinstance(data["results"], list):
            for result in data["results"]:
                if "findings" in result and isinstance(result["findings"], list):
                    for finding in result["findings"]:
                        findings.append(Finding(
                            id=f"{result.get('tool_name', 'unknown')}_{finding.get('rule', finding.get('line', len(findings)))}",
                            title=finding.get("message", finding.get("rule", "Finding")),
                            description=finding.get("code", ""),
                            severity=finding.get("severity", "unknown"),
                            category=finding.get("category", "static_analysis"),
                            file_path=finding.get("file"),
                            line_number=finding.get("line"),
                            tool=result.get("tool_name", tool_name),
                            evidence=finding.get("cwe")
                        ))

        # Handle network output
        if "signals" in data and isinstance(data["signals"], list):
            for signal in data["signals"]:
                findings.append(Finding(
                    id=str(signal.get("id", len(findings))),
                    title=signal.get("type", "Network Signal"),
                    description=signal.get("description", ""),
                    severity=signal.get("severity", "unknown"),
                    category="network",
                    tool=tool_name
                ))

        # Handle supply chain
        if "dependencies" in data and isinstance(data["dependencies"], list):
            for dep in data["dependencies"]:
                if "signals" in dep and dep["signals"]:
                    for signal in dep["signals"]:
                        findings.append(Finding(
                            id=f"dep_{dep['dependency']['name']}",
                            title=signal.get("type", "Supply Chain Issue"),
                            description=signal.get("description", ""),
                            severity=signal.get("severity", "unknown"),
                            category="supply_chain",
                            tool=tool_name
                        ))

        return findings

    def process_file(self, file_path: pathlib.Path) -> List[Finding]:
        """Process a single file."""
        if not self.should_process_file(file_path):
            with self.findings_lock:
                self.skipped_files += 1
            return []

        try:
            findings = []
            if file_path.suffix.lower() == '.json':
                data = self.parse_json_file(file_path)
                tool_name = file_path.stem.replace('_output', '').replace('-output', '')
                findings = self.extract_findings_from_json(data, tool_name)
            elif file_path.suffix.lower() in ['.yaml', '.yml']:
                data = self.parse_yaml_file(file_path)
                # For YAML, we could analyze the API spec for security issues
                # For now, just note it
                print(f"Processed YAML file: {file_path}")
                findings = []
            else:
                print(f"Skipping unsupported file type: {file_path}")
                return []

            with self.findings_lock:
                self.file_count += 1
            print(f"Processed {file_path} - {len(findings)} findings")
            return findings

        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            return []

    def scan_outputs(self):
        """Scan all files in outputs directory."""
        if not self.outputs_dir.exists():
            raise FileNotFoundError(f"Outputs directory not found: {self.outputs_dir}")

        file_paths = [file_path for file_path in self.outputs_dir.rglob('*') if file_path.is_file()]

        # Use ThreadPoolExecutor for concurrent processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(file_paths))) as executor:
            future_to_file = {executor.submit(self.process_file, file_path): file_path for file_path in file_paths}
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    findings = future.result()
                    self.findings.extend(findings)
                except Exception as e:
                    print(f"Error processing {file_path}: {e}")

    def categorize_findings(self) -> Dict[str, List[Finding]]:
        """Categorize findings by severity."""
        categories = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
            "unknown": []
        }

        for finding in self.findings:
            severity = finding.severity.lower()
            if severity in categories:
                categories[severity].append(finding)
            else:
                categories["unknown"].append(finding)

        return categories

    def generate_report(self) -> str:
        """Generate comprehensive HTML report."""
        categories = self.categorize_findings()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Load graph data
        graph_data = {}
        graph_path = pathlib.Path("inputs/mapper-agent/topological-graph-output.json")
        if graph_path.exists():
            try:
                with open(graph_path, 'r', encoding='utf-8') as f:
                    graph_data = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load graph data: {e}")
                graph_data = {}

        # Serialize graph data
        graph_data_json = json.dumps(graph_data)
        print(f"Graph data length: {len(graph_data_json)}")

        severity_colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#17a2b8',
            'unknown': '#6c757d'
        }

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cybersecurity Analysis Report</title>
        <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .severity-critical {{ background-color: {severity_colors['critical']}; color: white; }}
        .severity-high {{ background-color: {severity_colors['high']}; color: white; }}
        .severity-medium {{ background-color: {severity_colors['medium']}; color: black; }}
        .severity-low {{ background-color: {severity_colors['low']}; color: white; }}
        .severity-info {{ background-color: {severity_colors['info']}; color: white; }}
        .severity-unknown {{ background-color: {severity_colors['unknown']}; color: white; }}
        .findings-section {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .finding {{
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
            background: #f8f9fa;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .severity-badge {{
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .recommendations {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .recommendations ul {{
            list-style-type: none;
            padding: 0;
        }}
        .recommendations li {{
            background: #f8f9fa;
            margin: 10px 0;
            padding: 15px;
            border-left: 4px solid #007bff;
            border-radius: 0 5px 5px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            border: 1px solid #dee2e6;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: bold;
        }}
        .code {{
            font-family: 'Courier New', monospace;
            background: #f1f3f4;
            padding: 2px 4px;
            border-radius: 3px;
        }}
        #graph-container {{
            width: 100%;
            height: 600px;
            border: 1px solid #333;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        #metadata-panel {{
            width: 100%;
            height: 300px;
            padding: 20px;
            box-sizing: border-box;
            overflow-y: auto;
            background-color: #1A1A1A;
            color: #EAEAEA;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        #metadata-panel h3 {{
            margin-top: 0;
            color: #FFFFFF;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Cybersecurity Analysis Report</h1>
        <p>Automated Security Assessment Results</p>
        <div style="margin-top: 20px;">
            <strong>Generated on:</strong> {now}<br>
            <strong>Files Processed:</strong> {self.file_count} | <strong>Files Skipped:</strong> {self.skipped_files}<br>
            <strong>Total Findings:</strong> {len(self.findings)}
        </div>
        </div>

        <div class="findings-section">
        <h2>📊 Code Dependency Graph</h2>
        <div id="graph-container"></div>
        <div id="metadata-panel">
            <h3>Node Metadata</h3>
            <p>Click on a node to see its details.</p>
        </div>
    </div>

    <div class="summary">
        <div class="summary-card">
            <h3>Executive Summary</h3>
            <p>This report presents findings from automated security analysis tools including static analysis, obfuscation detection, network monitoring, and supply chain analysis.</p>
        </div>
    </div>

    <div class="summary">
"""

        for severity in ["critical", "high", "medium", "low", "info", "unknown"]:
            count = len(categories[severity])
            color = severity_colors[severity]
            html += f"""
        <div class="summary-card severity-{severity}">
            <h3>{severity.capitalize()}</h3>
            <div style="font-size: 2em; font-weight: bold;">{count}</div>
        </div>"""

        html += """
    </div>

    <div class="findings-section">
        <h2>📋 Detailed Findings</h2>
"""

        severity_order = ["critical", "high", "medium", "low", "info", "unknown"]

        for severity in severity_order:
            findings = categories[severity]
            if not findings:
                continue

            color = severity_colors[severity]
            html += f"""
        <h3 style="color: {color};">{severity.capitalize()} Severity Findings ({len(findings)})</h3>"""

            for finding in findings:
                html += f"""
        <div class="finding">
            <div class="finding-header">
                <h4>{finding.title}</h4>
                <span class="severity-badge severity-{severity}">{severity.upper()}</span>
            </div>
            <table>
                <tr><th>Tool</th><td>{finding.tool or 'Unknown'}</td></tr>
                <tr><th>Category</th><td>{finding.category}</td></tr>"""
                if finding.file_path:
                    html += f"<tr><th>File</th><td class='code'>{finding.file_path}</td></tr>"
                if finding.line_number:
                    html += f"<tr><th>Line</th><td>{finding.line_number}</td></tr>"
                if finding.confidence:
                    html += f"<tr><th>Confidence</th><td>{finding.confidence:.2f}</td></tr>"
                if finding.evidence:
                    html += f"<tr><th>Evidence</th><td>{finding.evidence}</td></tr>"
                html += f"""
                <tr><th>Description</th><td>{finding.description}</td></tr>
            </table>
        </div>"""

        html += """
    </div>

    <div class="recommendations">
        <h2>💡 Recommendations</h2>
        <ul>
            <li><strong>Address Critical and High Severity Issues Immediately</strong><br>These pose the greatest risk to your application security.</li>
            <li><strong>Review Code Obfuscation Findings</strong><br>Investigate sources of obfuscated code and ensure code is from trusted sources.</li>
            <li><strong>Static Analysis Improvements</strong><br>Fix identified security vulnerabilities and implement secure coding practices.</li>
            <li><strong>Supply Chain Security</strong><br>Audit third-party dependencies and keep them updated.</li>
            <li><strong>Network Security</strong><br>Monitor for suspicious network activity and implement proper network segmentation.</li>
        </ul>
        </div>

        <script type="text/javascript">
        window.graphData = {{GRAPH_DATA_PLACEHOLDER}};
        </script>
    <script type="text/javascript">
        document.addEventListener('DOMContentLoaded', function() {
            const graphData = window.graphData;
            if (!graphData || !graphData.nodes) {
                document.getElementById('metadata-panel').innerHTML = '<h3>No Graph Data</h3><p>Graph data could not be loaded.</p>';
                return;
            }

            const container = document.getElementById('graph-container');
            const metadataPanel = document.getElementById('metadata-panel');

                    // --- "DeepFence" Aesthetic Style Mapping ---
                    const styleMap = {
                        file:      { color: { border: '#3498DB', background: '#283747' }, shape: 'box', borderWidth: 2.5 },
                        class:     { color: '#8E44AD', shape: 'diamond' },
                        function:  { color: '#ECF0F1', shape: 'ellipse' },
                        variable:  { color: '#3498DB', shape: 'dot' },
                        interface: { color: '#C0392B', shape: 'triangle' },
                        type:      { color: '#E74C3C', shape: 'triangleDown' },
                        enum:      { color: '#16A085', shape: 'hexagon' },
                        namespace: { color: { border: '#566573', background: '#283747' }, shape: 'database' },
                        default:   { color: '#7F8C8D', shape: 'ellipse' }
                    };

                    // --- Data Transformation for Vis.js ---
                    const nodes = new vis.DataSet(
                        graphData.nodes.map(node => {
                            const style = styleMap[node.type] || styleMap.default;
                            return {
                                id: node.id,
                                label: node.name,
                                color: style.color,
                                shape: style.shape,
                                font: { color: (node.type === 'function' ? '#2C3E50' : '#FFFFFF') },
                                shadow: { enabled: true, color: 'rgba(0,0,0,0.5)', size: 10, x: 5, y: 5 },
                                borderWidth: style.borderWidth || 1.5 // Apply specific border width or default
                            };
                        })
                    );

                    const edges = new vis.DataSet(
                        graphData.links.map(edge => ({
                            from: edge.source,
                            to: edge.target,
                            arrows: 'to',
                            color: { color: '#444444', highlight: '#888888' },
                            width: 0.5
                        }))
                    );

                    const data = { nodes, edges };

                    const options = {
                        layout: {
                            hierarchical: false,
                            improvedLayout: false
                        },
                        physics: {
                            solver: 'forceAtlas2Based',
                            forceAtlas2Based: {
                                gravitationalConstant: -150, // Increased repulsion
                                centralGravity: 0.01,       // Increased pull to center
                                springLength: 300,          // Increased ideal edge length
                                springConstant: 0.08,       // Slightly weaker springs
                                avoidOverlap: 0.8           // Stronger overlap avoidance
                            }
                        },
                        nodes: {
                            borderWidth: 1.5
                        },
                        edges: {
                            smooth: {
                                type: 'continuous'
                            }
                        }
                    };

                    // Initialize the Network
                    const network = new vis.Network(container, data, options);

                    // --- Click Event Handler ---
                    network.on('click', function(params) {
                        if (params.nodes.length > 0) {
                            const nodeId = params.nodes[0];
                            const nodeData = graphData.nodes.find(n => n.id === nodeId);

                            if (nodeData) {
                                let metadataHtml = `<h3>Node Metadata</h3>`;
                                metadataHtml += `<pre>${JSON.stringify(nodeData, null, 2)}</pre>`;
                                metadataPanel.innerHTML = metadataHtml;
                            }
                        }
                    });
        });
    </script>
</body>
</html>""".replace('{{GRAPH_DATA_PLACEHOLDER}}', json.dumps(graph_data))

        return html

    def create_repository_structure(self, report_content: str):
        """Create organized repository structure with reports and findings."""
        # Create directories
        repo_dirs = [
            "output/reports",
            "output/findings/by-severity",
            "output/findings/by-category",
            "output/findings/by-tool",
            "output/assets"
        ]

        for dir_name in repo_dirs:
            pathlib.Path(dir_name).mkdir(parents=True, exist_ok=True)

        # Write main report
        with open("output/reports/cybersecurity-report.html", 'w', encoding='utf-8') as f:
            f.write(report_content)

        # Write categorized findings
        categories = self.categorize_findings()
        category_findings = {}
        tool_findings = {}

        for finding in self.findings:
            # By category
            cat = finding.category or "unknown"
            if cat not in category_findings:
                category_findings[cat] = []
            category_findings[cat].append(finding)

            # By tool
            tool = finding.tool or "unknown"
            if tool not in tool_findings:
                tool_findings[tool] = []
            tool_findings[tool].append(finding)

        # Generate HTML for severity files
        def generate_findings_html(title: str, findings: List[Finding]) -> str:
            severity_colors = {
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#28a745',
                'info': '#17a2b8',
                'unknown': '#6c757d'
            }
            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .finding {{ border: 1px solid #ddd; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .severity-badge {{ padding: 3px 8px; border-radius: 10px; color: white; font-size: 0.8em; }}
        .severity-critical {{ background-color: {severity_colors['critical']}; }}
        .severity-high {{ background-color: {severity_colors['high']}; }}
        .severity-medium {{ background-color: {severity_colors['medium']}; color: black; }}
        .severity-low {{ background-color: {severity_colors['low']}; }}
        .severity-info {{ background-color: {severity_colors['info']}; }}
        .severity-unknown {{ background-color: {severity_colors['unknown']}; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
"""
            for finding in findings:
                severity = finding.severity.lower()
                html += f"""
    <div class="finding">
        <h3>{finding.title} <span class="severity-badge severity-{severity}">{severity.upper()}</span></h3>
        <p><strong>Tool:</strong> {finding.tool or 'Unknown'}</p>
        <p><strong>Category:</strong> {finding.category}</p>
        <p><strong>Description:</strong> {finding.description}</p>
    </div>
"""
            html += "</body></html>"
            return html

        # Write severity files
        for severity, findings in categories.items():
            content = generate_findings_html(f"{severity.capitalize()} Severity Findings", findings)
            with open(f"output/findings/by-severity/{severity}.html", 'w', encoding='utf-8') as f:
                f.write(content)

        # Write category files
        for category, findings in category_findings.items():
            content = generate_findings_html(f"{category.replace('_', ' ').title()} Findings", findings)
            with open(f"output/findings/by-category/{category}.html", 'w', encoding='utf-8') as f:
                f.write(content)

        # Write tool files
        for tool, findings in tool_findings.items():
            content = generate_findings_html(f"{tool.replace('-', ' ').title()} Findings", findings)
            with open(f"output/findings/by-tool/{tool}.html", 'w', encoding='utf-8') as f:
                f.write(content)

        # Create README
        readme = f"""# Cybersecurity Analysis Repository

This repository contains the results of comprehensive cybersecurity analysis performed on the codebase.

## Structure

- `output/reports/` - Main analysis reports (HTML format)
- `output/findings/` - Organized findings by severity, category, and tool (HTML format)
- `output/assets/` - Supporting assets and documentation
- `inputs/` - Raw scanner outputs (preserved)

## Summary

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Files Processed:** {self.file_count}
**Total Findings:** {len(self.findings)}

### Findings by Severity
"""
        for severity in ["critical", "high", "medium", "low", "info", "unknown"]:
            count = len(categories.get(severity, []))
            readme += f"- {severity.capitalize()}: {count}\n"

        readme += "\n## Tools Used\n\n"
        tools = set(f.tool for f in self.findings if f.tool)
        for tool in sorted(tools):
            readme += f"- {tool}\n"

        with open("output/README.md", 'w', encoding='utf-8') as f:
            f.write(readme)

    def run(self):
        """Main execution method."""
        print("Starting Cybersecurity Reporter Agent...")

        try:
            self.scan_outputs()
            report = self.generate_report()
            self.create_repository_structure(report)

            print(f"Analysis complete!")
            print(f"Processed {self.file_count} files, skipped {self.skipped_files}")
            print(f"Found {len(self.findings)} security findings")
            print("Repository structure created with organized reports and findings.")

        except Exception as e:
            print(f"Error during analysis: {e}")
            raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cybersecurity Reporter Agent - Process security scanner outputs and generate reports.")
    parser.add_argument("output_dir", nargs="?", default="inputs", help="Path to the directory containing security scanner output files (default: inputs)")
    args = parser.parse_args()

    agent = CybersecurityReporterAgent(outputs_dir=args.output_dir)
    agent.run()
