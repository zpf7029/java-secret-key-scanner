#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java Secret Key Scanner - Optimized Version
Java代码敏感词/密钥审计工具 - 优化版

Features:
- 减少误报：过滤 getPassword(), configService, this.password 等常见误报
- 支持多种敏感信息检测
- 生成HTML报告
"""

import os
import re
import sys
from pathlib import Path
from datetime import datetime

# ============== 检测规则配置 ==============
# 优化版规则，减少误报
PATTERNS = {
    # 硬编码密码 - 排除常见误报
    "hardcoded_password": {
        "pattern": re.compile(
            r'password\s*[=:]\s*["\'](?!.*(?:getPassword|config|system|init|user\.get|login|check|validate|\$\{|new\s+))[a-zA-Z0-9@#$%^&*!]{6,30}["\']',
            re.I
        ),
        "severity": "CRITICAL",
        "description": "Hardcoded Password - 硬编码密码",
        "category": "Sensitive Data"
    },
    
    # 不安全的反序列化
    "deserialize": {
        "pattern": re.compile(r'(?i)(ObjectInputStream|readObject|XMLDecoder)\s*\(', re.I),
        "severity": "HIGH",
        "description": "Insecure Deserialization - 不安全的反序列化",
        "category": "Insecure Deserialization"
    },
    
    # 弱加密算法
    "weak_crypto": {
        "pattern": re.compile(r'(?i)(DES|MD5|SHA1)\s*[\("]', re.I),
        "severity": "MEDIUM",
        "description": "Weak Cryptography - 弱加密算法",
        "category": "Weak Cryptography"
    },
    
    # 路径遍历
    "path_traversal": {
        "pattern": re.compile(r'(?i)(new\s+File|FileInputStream|Paths\.get)\s*\([^)]*\+[^)]*\)', re.I),
        "severity": "MEDIUM",
        "description": "Path Traversal - 路径遍历",
        "category": "Path Traversal"
    },
    
    # SQL注入
    "sql_injection": {
        "pattern": re.compile(r'(?i)(Statement|executeQuery|executeUpdate)\s*\([^)]*\+[^)]*\)', re.I),
        "severity": "CRITICAL",
        "description": "SQL Injection - SQL注入风险",
        "category": "Injection"
    },
    
    # 动态代码执行
    "eval_exec": {
        "pattern": re.compile(r'(?i)(eval|exec|Runtime\.getRuntime\(\)\.exec|new\s+Function)\s*\(', re.I),
        "severity": "HIGH",
        "description": "Code Injection - 动态代码执行",
        "category": "Code Injection"
    },
    
    # XXE漏洞
    "xxe": {
        "pattern": re.compile(r'(?i)(DocumentBuilderFactory|SaxParser|XMLInputFactory)\.newInstance\(\)', re.I),
        "severity": "HIGH",
        "description": "XXE - XML外部实体",
        "category": "XXE"
    },
    
    # API密钥
    "api_key": {
        "pattern": re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,64})["\']?', re.I),
        "severity": "CRITICAL",
        "description": "API Key - API密钥",
        "category": "Sensitive Data"
    }
}

# ============== 误报过滤配置 ==============
# 排除以下模式，不计入问题
FALSE_POSITIVE_PATTERNS = [
    'getpassword',        # getPassword() 方法调用
    'setpassword',        # setPassword() 方法调用
    'this.password',     # this.password = xxx
    'user.get',          # user.getXxx()
    'configservice',      # configService.selectConfigByKey()
    'selectconfig',       # configService.selectConfigByKey()
    '@jsonignore',        # JSON序列化忽略
    'private string password',
    'protected string password',
    'public string password',
    'loginname,',        # loginName, password 参数
    'username and password',
]

def scan_file(file_path):
    """扫描单个文件"""
    findings = []
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        lines = content.split('\n')
        
        for name, info in PATTERNS.items():
            for match in info["pattern"].finditer(content):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1].lower() if line_num <= len(lines) else ""
                
                # 误报过滤
                if any(skip in line_content for skip in FALSE_POSITIVE_PATTERNS):
                    continue
                
                start = max(0, match.start() - 40)
                end = min(len(content), match.end() + 40)
                ctx = content[start:end].replace('\n', '\\n').replace('\r', '')
                
                findings.append({
                    "type": name,
                    "severity": info["severity"],
                    "description": info["description"],
                    "category": info["category"],
                    "file": str(file_path),
                    "line": line_num,
                    "match": match.group()[:60],
                    "context": ctx
                })
    except Exception:
        pass
    return findings

def scan_directory(dir_path, exclude_dirs=None):
    """扫描目录"""
    if exclude_dirs is None:
        exclude_dirs = ['target', 'build', '.git', 'node_modules', '.idea', '.vscode']
    
    all_findings = []
    java_files = [
        f for f in Path(dir_path).rglob("*.java")
        if not any(ex in str(f) for ex in exclude_dirs)
    ]
    
    print(f"[INFO] Scanning {len(java_files)} Java files...")
    
    for i, f in enumerate(java_files):
        if i % 50 == 0 and i > 0:
            print(f"[INFO] Progress: {i}/{len(java_files)}")
        findings = scan_file(f)
        all_findings.extend(findings)
    
    return all_findings

def generate_html_report(findings, project_name, output_path):
    """生成HTML报告"""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    
    # 统计
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    type_counts = {}
    for f in findings:
        stats[f["severity"]] = stats.get(f["severity"], 0) + 1
        type_counts[f["type"]] = type_counts.get(f["type"], 0) + 1
    
    # 排序
    sorted_findings = sorted(findings, key=lambda x: (severity_order.get(x["severity"], 4), x["file"], x["line"]))
    
    # 按文件分组
    by_file = {}
    for f in sorted_findings:
        by_file.setdefault(f["file"], []).append(f)
    
    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>{project_name} - Security Audit Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f7fa; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ text-align: center; color: #2c3e50; margin: 30px 0; }}
        h2, h3 {{ color: #2c3e50; margin: 20px 0 10px; }}
        .card {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }}
        .stat {{ background: white; border-radius: 8px; padding: 25px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-number {{ font-size: 48px; font-weight: bold; }}
        .stat-label {{ color: #666; margin-top: 5px; font-size: 14px; }}
        .critical {{ color: #e74c3c; }} .high {{ color: #e67e22; }} .medium {{ color: #f1c40f; }} .low {{ color: #27ae60; }}
        .finding {{ border-left: 4px solid; padding: 15px; margin-bottom: 15px; border-radius: 4px; background: #fafafa; }}
        .finding.critical {{ border-color: #e74c3c; background: #fef5f5; }}
        .finding.high {{ border-color: #e67e22; background: #fef9f0; }}
        .finding.medium {{ border-color: #f1c40f; background: #fefdf5; }}
        .code {{ background: #2c3e50; color: #ecf0f1; padding: 12px; border-radius: 4px; font-family: 'Consolas', monospace; font-size: 12px; word-break: break-all; margin: 10px 0; overflow-x: auto; white-space: pre-wrap; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .file-section {{ margin-bottom: 25px; }}
        .file-title {{ font-size: 16px; font-weight: bold; color: #2c3e50; padding: 10px; background: #ecf0f1; border-radius: 4px; margin-bottom: 10px; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; margin-right: 8px; }}
        .badge.critical {{ background: #e74c3c; color: white; }}
        .badge.high {{ background: #e67e22; color: white; }}
        .badge.medium {{ background: #f1c40f; color: #333; }}
        .badge.low {{ background: #27ae60; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{project_name} - Security Audit Report</h1>

        <div class="stats">
            <div class="stat">
                <div class="stat-number critical">{stats['CRITICAL']}</div>
                <div class="stat-label">CRITICAL</div>
            </div>
            <div class="stat">
                <div class="stat-number high">{stats['HIGH']}</div>
                <div class="stat-label">HIGH</div>
            </div>
            <div class="stat">
                <div class="stat-number medium">{stats['MEDIUM']}</div>
                <div class="stat-label">MEDIUM</div>
            </div>
            <div class="stat">
                <div class="stat-number">{len(findings)}</div>
                <div class="stat-label">TOTAL</div>
            </div>
        </div>

        <div class="card">
            <h2>Basic Information</h2>
            <table>
                <tr><td><strong>Project</strong></td><td>{project_name}</td></tr>
                <tr><td><strong>Scan Time</strong></td><td>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</td></tr>
                <tr><td><strong>Total Issues</strong></td><td>{len(findings)}</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>Issues by Type</h2>
            <table>
                <tr><th>Type</th><th>Count</th><th>Severity</th></tr>
"""
    
    for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
        severity = "HIGH" if t in ["sql_injection", "api_key", "hardcoded_password"] else "MEDIUM" if t in ["deserialize", "xxe", "eval_exec"] else "LOW"
        html += f"""                <tr><td>{t}</td><td>{c}</td><td class="{severity.lower()}"><span class="badge {severity.lower()}">{severity}</span></td></tr>
"""
    
    html += """            </table>
        </div>

        <div class="card">
            <h2>Detailed Findings</h2>
"""
    
    for file_path, file_findings in sorted(by_file.items()):
        filename = os.path.basename(file_path)
        html += f'<div class="file-section"><div class="file-title">{filename}</div>'
        for finding in file_findings:
            severity_class = finding["severity"].lower()
            html += f"""
        <div class="finding {severity_class}">
            <span class="badge {severity_class}">{finding["severity"]}</span>
            <strong>{finding["description"]}</strong> (Line {finding["line"]})
            <div class="code">{finding["context"]}</div>
        </div>
"""
        html += '</div>'
    
    html += """        </div>

        <div class="card" style="text-align: center; color: #666;">
            <p>Generated by Java Secret Key Scanner</p>
        </div>
    </div>
</body>
</html>
"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"[SUCCESS] Report saved to: {output_path}")
    return html

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Java Secret Key Scanner')
    parser.add_argument('-p', '--path', required=True, help='Project path to scan')
    parser.add_argument('-o', '--output', default='security-report.html', help='Output report path')
    parser.add_argument('--project-name', default='Java Project', help='Project name')
    parser.add_argument('-e', '--exclude', default='target,build,.git,node_modules', help='Exclude directories')
    
    args = parser.parse_args()
    
    exclude_dirs = [d.strip() for d in args.exclude.split(',')]
    
    print("=" * 60)
    print("[Java Secret Key Scanner]")
    print("=" * 60)
    
    findings = scan_directory(args.path, exclude_dirs)
    
    # 统计
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for f in findings:
        stats[f["severity"]] = stats.get(f["severity"], 0) + 1
    
    print(f"\n[RESULT] Total: {len(findings)}")
    print(f"  CRITICAL: {stats['CRITICAL']}")
    print(f"  HIGH: {stats['HIGH']}")
    print(f"  MEDIUM: {stats['MEDIUM']}")
    
    # 生成报告
    generate_html_report(findings, args.project_name, args.output)

if __name__ == "__main__":
    main()
