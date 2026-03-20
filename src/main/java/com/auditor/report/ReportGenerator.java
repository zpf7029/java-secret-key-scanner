package com.auditor.report;

import com.auditor.secrets.SecretFinding;
import com.auditor.secrets.SecretType;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 审计报告生成器
 */
public class ReportGenerator {
    
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    private final List<SecretFinding> findings;
    private final String projectName;
    private final String scanPath;
    private final LocalDateTime scanTime;
    
    public ReportGenerator(List<SecretFinding> findings, String projectName, String scanPath) {
        this.findings = findings;
        this.projectName = projectName;
        this.scanPath = scanPath;
        this.scanTime = LocalDateTime.now();
    }
    
    /**
     * 按文件分组统计
     */
    public Map<String, List<SecretFinding>> groupByFile() {
        Map<String, List<SecretFinding>> grouped = new TreeMap<>();
        for (SecretFinding finding : findings) {
            grouped.computeIfAbsent(finding.getFileName(), k -> new ArrayList<>()).add(finding);
        }
        return grouped;
    }
    
    /**
     * 按类型分组统计
     */
    public Map<SecretType, Integer> countByType() {
        Map<SecretType, Integer> counts = new EnumMap<>(SecretType.class);
        for (SecretFinding finding : findings) {
            counts.merge(finding.getType(), 1, Integer::sum);
        }
        return counts;
    }
    
    /**
     * 按严重程度统计
     */
    public Map<String, Integer> countBySeverity() {
        Map<String, Integer> counts = new LinkedHashMap<>();
        counts.put("CRITICAL", 0);
        counts.put("HIGH", 0);
        counts.put("MEDIUM", 0);
        counts.put("LOW", 0);
        
        for (SecretFinding finding : findings) {
            String severity = finding.getType().getSeverity();
            counts.merge(severity, 1, Integer::sum);
        }
        return counts;
    }
    
    /**
     * 生成控制台报告
     */
    public void printConsoleReport() {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("                    Java敏感词代码审计报告");
        System.out.println("=".repeat(80));
        System.out.println();
        
        // 基本信息
        System.out.println("📋 基本信息:");
        System.out.println("   项目名称: " + projectName);
        System.out.println("   扫描路径: " + scanPath);
        System.out.println("   扫描时间: " + scanTime.format(FORMATTER));
        System.out.println("   扫描文件: " + groupByFile().size() + " 个");
        System.out.println("   发现问题: " + findings.size() + " 个");
        System.out.println();
        
        // 严重程度统计
        Map<String, Integer> severityCounts = countBySeverity();
        System.out.println("📊 严重程度统计:");
        System.out.println("   🔴 严重: " + severityCounts.get("CRITICAL") + " 个");
        System.out.println("   🟠 高危: " + severityCounts.get("HIGH") + " 个");
        System.out.println("   🟡 中危: " + severityCounts.get("MEDIUM") + " 个");
        System.out.println("   🟢 低危: " + severityCounts.get("LOW") + " 个");
        System.out.println();
        
        // 类型统计
        Map<SecretType, Integer> typeCounts = countByType();
        System.out.println("📈 问题类型分布:");
        typeCounts.entrySet().stream()
            .sorted((a, b) -> b.getValue().compareTo(a.getValue()))
            .forEach(e -> System.out.printf("   %s: %d 个%n", 
                e.getKey().getChineseName(), e.getValue()));
        System.out.println();
        
        // 详细发现
        if (!findings.isEmpty()) {
            System.out.println("🔍 详细发现:");
            System.out.println("-".repeat(80));
            
            Map<String, List<SecretFinding>> byFile = groupByFile();
            for (Map.Entry<String, List<SecretFinding>> entry : byFile.entrySet()) {
                System.out.println("\n📁 文件: " + entry.getKey());
                for (SecretFinding finding : entry.getValue()) {
                    System.out.println(finding.getSeverityDescription());
                    System.out.println("   位置: 第 " + finding.getLineNumber() + " 行");
                    System.out.println("   匹配: " + finding.getMaskedText());
                    System.out.println("   上下文: " + finding.getContext());
                    System.out.println("   建议: " + finding.getType().getDescription());
                    System.out.println();
                }
            }
        }
        
        // 总结
        System.out.println("=".repeat(80));
        System.out.println("                              审计总结");
        System.out.println("=".repeat(80));
        
        int criticalCount = severityCounts.get("CRITICAL");
        int highCount = severityCounts.get("HIGH");
        
        if (criticalCount > 0) {
            System.out.println("⚠️  发现 " + criticalCount + " 个严重问题！请立即修复！");
        }
        if (highCount > 0) {
            System.out.println("⚠️  发现 " + highCount + " 个高危问题！请尽快修复！");
        }
        
        if (findings.isEmpty()) {
            System.out.println("✅ 未发现敏感信息泄露问题，代码安全状态良好！");
        } else {
            System.out.println("📝 请根据上述建议修复发现的问题。");
        }
        
        System.out.println("=".repeat(80));
    }
    
    /**
     * 生成JSON报告
     */
    public void generateJsonReport(String outputPath) throws IOException {
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("projectName", projectName);
        report.put("scanPath", scanPath);
        report.put("scanTime", scanTime.format(FORMATTER));
        report.put("totalFindings", findings.size());
        report.put("filesScanned", groupByFile().size());
        
        // 统计
        Map<String, Object> statistics = new LinkedHashMap<>();
        statistics.put("bySeverity", countBySeverity());
        statistics.put("byType", typeCountToString(countByType()));
        report.put("statistics", statistics);
        
        // 详细发现
        List<Map<String, Object>> findingsList = new ArrayList<>();
        for (SecretFinding finding : findings) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("type", finding.getType().name());
            item.put("typeName", finding.getType().getChineseName());
            item.put("severity", finding.getType().getSeverity());
            item.put("file", finding.getFileName());
            item.put("line", finding.getLineNumber());
            item.put("matched", finding.getMaskedText());
            item.put("context", finding.getContext());
            item.put("description", finding.getType().getDescription());
            findingsList.add(item);
        }
        report.put("findings", findingsList);
        
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputPath))) {
            gson.toJson(report, writer);
        }
        System.out.println("\n📄 JSON报告已生成: " + outputPath);
    }
    
    /**
     * 生成HTML报告
     */
    public void generateHtmlReport(String outputPath) throws IOException {
        Map<String, Integer> severityCounts = countBySeverity();
        Map<SecretType, Integer> typeCounts = countByType();
        Map<String, List<SecretFinding>> byFile = groupByFile();
        
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n");
        html.append("<html lang=\"zh-CN\">\n");
        html.append("<head>\n");
        html.append("    <meta charset=\"UTF-8\">\n");
        html.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.append("    <title>Java敏感词代码审计报告 - ").append(projectName).append("</title>\n");
        html.append("    <style>\n");
        html.append("        * { margin: 0; padding: 0; box-sizing: border-box; }\n");
        html.append("        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; ");
        html.append("background: #f5f7fa; color: #333; padding: 20px; }\n");
        html.append("        .container { max-width: 1200px; margin: 0 auto; }\n");
        html.append("        h1 { text-align: center; color: #2c3e50; margin-bottom: 30px; }\n");
        html.append("        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; ");
        html.append("box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
        html.append("        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); ");
        html.append("gap: 15px; margin-bottom: 20px; }\n");
        html.append("        .stat-card { background: white; border-radius: 8px; padding: 20px; ");
        html.append("text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
        html.append("        .stat-number { font-size: 36px; font-weight: bold; margin-bottom: 5px; }\n");
        html.append("        .stat-label { color: #666; font-size: 14px; }\n");
        html.append("        .critical { color: #e74c3c; }\n");
        html.append("        .high { color: #e67e22; }\n");
        html.append("        .medium { color: #f1c40f; }\n");
        html.append("        .low { color: #27ae60; }\n");
        html.append("        .finding { border-left: 4px solid; padding: 15px; margin-bottom: 10px; ");
        html.append("border-radius: 4px; background: #fafafa; }\n");
        html.append("        .finding.critical { border-color: #e74c3c; }\n");
        html.append("        .finding.high { border-color: #e67e22; }\n");
        html.append("        .finding.medium { border-color: #f1c40f; }\n");
        html.append("        .finding.low { border-color: #27ae60; }\n");
        html.append("        .finding-header { display: flex; justify-content: space-between; ");
        html.append("align-items: center; margin-bottom: 10px; }\n");
        html.append("        .finding-type { font-weight: bold; font-size: 16px; }\n");
        html.append("        .finding-meta { color: #666; font-size: 12px; }\n");
        html.append("        .code { background: #2c3e50; color: #ecf0f1; padding: 10px; ");
        html.append("border-radius: 4px; font-family: 'Consolas', monospace; font-size: 13px; ");
        html.append("overflow-x: auto; margin: 10px 0; }\n");
        html.append("        .file-section { margin-bottom: 20px; }\n");
        html.append("        .file-title { font-size: 18px; font-weight: bold; color: #2c3e50; ");
        html.append("padding: 10px; background: #ecf0f1; border-radius: 4px; margin-bottom: 10px; }\n");
        html.append("        table { width: 100%; border-collapse: collapse; }\n");
        html.append("        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }\n");
        html.append("        th { background: #f8f9fa; font-weight: 600; }\n");
        html.append("    </style>\n");
        html.append("</head>\n");
        html.append("<body>\n");
        html.append("    <div class=\"container\">\n");
        html.append("        <h1>🛡️ Java敏感词代码审计报告</h1>\n");
        
        // 基本信息
        html.append("        <div class=\"card\">\n");
        html.append("            <h2>📋 基本信息</h2>\n");
        html.append("            <table>\n");
        html.append("                <tr><td><strong>项目名称</strong></td><td>").append(escapeHtml(projectName)).append("</td></tr>\n");
        html.append("                <tr><td><strong>扫描路径</strong></td><td>").append(escapeHtml(scanPath)).append("</td></tr>\n");
        html.append("                <tr><td><strong>扫描时间</strong></td><td>").append(scanTime.format(FORMATTER)).append("</td></tr>\n");
        html.append("                <tr><td><strong>扫描文件数</strong></td><td>").append(byFile.size()).append("</td></tr>\n");
        html.append("                <tr><td><strong>发现问题数</strong></td><td>").append(findings.size()).append("</td></tr>\n");
        html.append("            </table>\n");
        html.append("        </div>\n");
        
        // 统计卡片
        html.append("        <div class=\"stats\">\n");
        html.append("            <div class=\"stat-card\">\n");
        html.append("                <div class=\"stat-number critical\">").append(severityCounts.get("CRITICAL")).append("</div>\n");
        html.append("                <div class=\"stat-label\">🔴 严重</div>\n");
        html.append("            </div>\n");
        html.append("            <div class=\"stat-card\">\n");
        html.append("                <div class=\"stat-number high\">").append(severityCounts.get("HIGH")).append("</div>\n");
        html.append("                <div class=\"stat-label\">🟠 高危</div>\n");
        html.append("            </div>\n");
        html.append("            <div class=\"stat-card\">\n");
        html.append("                <div class=\"stat-number medium\">").append(severityCounts.get("MEDIUM")).append("</div>\n");
        html.append("                <div class=\"stat-label\">🟡 中危</div>\n");
        html.append("            </div>\n");
        html.append("            <div class=\"stat-card\">\n");
        html.append("                <div class=\"stat-number low\">").append(severityCounts.get("LOW")).append("</div>\n");
        html.append("                <div class=\"stat-label\">🟢 低危</div>\n");
        html.append("            </div>\n");
        html.append("        </div>\n");
        
        // 类型分布
        html.append("        <div class=\"card\">\n");
        html.append("            <h2>📈 问题类型分布</h2>\n");
        html.append("            <table>\n");
        html.append("                <tr><th>类型</th><th>数量</th><th>严重程度</th></tr>\n");
        typeCounts.entrySet().stream()
            .sorted((a, b) -> b.getValue().compareTo(a.getValue()))
            .forEach(e -> {
                String severityClass = e.getKey().getSeverity().toLowerCase();
                html.append("                <tr>");
                html.append("<td>").append(e.getKey().getChineseName()).append("</td>");
                html.append("<td>").append(e.getValue()).append("</td>");
                html.append("<td class=\"").append(severityClass).append("\">");
                html.append(e.getKey().getSeverityLevel()).append("</td>");
                html.append("</tr>\n");
            });
        html.append("            </table>\n");
        html.append("        </div>\n");
        
        // 详细发现
        if (!findings.isEmpty()) {
            html.append("        <div class=\"card\">\n");
            html.append("            <h2>🔍 详细发现</h2>\n");
            
            for (Map.Entry<String, List<SecretFinding>> entry : byFile.entrySet()) {
                html.append("            <div class=\"file-section\">\n");
                html.append("                <div class=\"file-title\">📁 ").append(escapeHtml(entry.getKey())).append("</div>\n");
                
                for (SecretFinding finding : entry.getValue()) {
                    String severityClass = finding.getType().getSeverity().toLowerCase();
                    html.append("                <div class=\"finding ").append(severityClass).append("\">\n");
                    html.append("                    <div class=\"finding-header\">\n");
                    html.append("                        <span class=\"finding-type\">").append(finding.getType().getChineseName()).append("</span>\n");
                    html.append("                        <span class=\"finding-meta\">").append(finding.getType().getSeverityLevel()).append(" | 第").append(finding.getLineNumber()).append("行</span>\n");
                    html.append("                    </div>\n");
                    html.append("                    <div class=\"code\">").append(escapeHtml(finding.getContext())).append("</div>\n");
                    html.append("                    <p><strong>建议:</strong> ").append(escapeHtml(finding.getType().getDescription())).append("</p>\n");
                    html.append("                </div>\n");
                }
                
                html.append("            </div>\n");
            }
            html.append("        </div>\n");
        }
        
        // 页脚
        html.append("        <div class=\"card\" style=\"text-align: center; color: #666;\">\n");
        html.append("            <p>由 Java Secret Key Scanner 自动生成</p>\n");
        html.append("            <p>扫描时间: ").append(scanTime.format(FORMATTER)).append("</p>\n");
        html.append("        </div>\n");
        html.append("    </div>\n");
        html.append("</body>\n");
        html.append("</html>\n");
        
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputPath))) {
            writer.print(html.toString());
        }
        System.out.println("\n📄 HTML报告已生成: " + outputPath);
    }
    
    private Map<String, Integer> typeCountToString(Map<SecretType, Integer> typeCounts) {
        Map<String, Integer> result = new LinkedHashMap<>();
        for (Map.Entry<SecretType, Integer> entry : typeCounts.entrySet()) {
            result.put(entry.getKey().name(), entry.getValue());
        }
        return result;
    }
    
    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;")
                   .replace("\n", "<br>");
    }
}
