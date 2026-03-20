package com.auditor;

import com.auditor.report.ReportGenerator;
import com.auditor.secrets.SecretDetector;
import com.auditor.secrets.SecretFinding;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveTask;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Java敏感词代码审计工具 - 主程序
 */
public class SecretScannerCLI {
    
    @Parameter(names = {"-p", "--path"}, description = "要扫描的目录路径", required = true)
    private String scanPath;
    
    @Parameter(names = {"-o", "--output"}, description = "输出报告路径")
    private String outputPath = "secret-audit-report";
    
    @Parameter(names = {"-f", "--format"}, description = "报告格式: console, json, html, all", arity = 1)
    private String format = "all";
    
    @Parameter(names = {"-e", "--exclude"}, description = "排除的目录/文件（逗号分隔）")
    private String excludeDirs = "target,build,.git,node_modules,.idea,.vscode";
    
    @Parameter(names = {"-t", "--threads"}, description = "并行扫描线程数")
    private int threads = 4;
    
    @Parameter(names = {"--include-test"}, description = "包含测试代码中的敏感信息")
    private boolean includeTest = false;
    
    @Parameter(names = {"--project-name"}, description = "项目名称")
    private String projectName = "Unknown Project";
    
    @Parameter(names = {"-h", "--help"}, help = true)
    private boolean help = false;
    
    public static void main(String[] args) {
        SecretScannerCLI cli = new SecretScannerCLI();
        JCommander jCommander = JCommander.newBuilder()
            .addObject(cli)
            .build();
        
        try {
            jCommander.parse(args);
            
            if (cli.help) {
                jCommander.usage();
                return;
            }
            
            cli.run();
            
        } catch (ParameterException e) {
            System.err.println("❌ 参数错误: " + e.getMessage());
            jCommander.usage();
            System.exit(1);
        } catch (Exception e) {
            System.err.println("❌ 扫描失败: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    public void run() throws IOException {
        System.out.println("🔍 Java敏感词代码审计工具");
        System.out.println("=".repeat(60));
        System.out.println("📁 扫描路径: " + scanPath);
        System.out.println("📋 项目名称: " + projectName);
        System.out.println("🔢 并行线程: " + threads);
        System.out.println("=".repeat(60));
        
        long startTime = System.currentTimeMillis();
        
        // 收集所有Java文件
        List<File> javaFiles = collectJavaFiles(scanPath);
        System.out.println("\n📊 发现 " + javaFiles.size() + " 个Java文件");
        
        if (javaFiles.isEmpty()) {
            System.out.println("⚠️  未找到Java文件，请检查路径是否正确");
            return;
        }
        
        // 并行扫描所有文件
        List<SecretFinding> allFindings = new ArrayList<>();
        
        try (ForkJoinPool pool = new ForkJoinPool(threads)) {
            ScanTask rootTask = new ScanTask(javaFiles, 0, javaFiles.size());
            allFindings = pool.invoke(rootTask);
        }
        
        long endTime = System.currentTimeMillis();
        System.out.println("\n⏱️  扫描完成，耗时: " + (endTime - startTime) + "ms");
        
        // 生成报告
        ReportGenerator generator = new ReportGenerator(allFindings, projectName, scanPath);
        
        switch (format.toLowerCase()) {
            case "console":
                generator.printConsoleReport();
                break;
            case "json":
                generator.generateJsonReport(outputPath + ".json");
                break;
            case "html":
                generator.generateHtmlReport(outputPath + ".html");
                break;
            case "all":
            default:
                generator.printConsoleReport();
                generator.generateJsonReport(outputPath + ".json");
                generator.generateHtmlReport(outputPath + ".html");
                break;
        }
    }
    
    /**
     * 收集所有Java文件
     */
    private List<File> collectJavaFiles(String rootPath) throws IOException {
        List<String> excludeList = Stream.of(excludeDirs.split(","))
            .map(String::trim)
            .collect(Collectors.toList());
        
        try (Stream<Path> walk = Files.walk(Paths.get(rootPath))) {
            return walk
                .filter(Files::isRegularFile)
                .filter(p -> p.toString().endsWith(".java"))
                .filter(p -> !isExcluded(p, excludeList))
                .map(Path::toFile)
                .collect(Collectors.toList());
        }
    }
    
    /**
     * 检查文件是否应该被排除
     */
    private boolean isExcluded(Path path, List<String> excludeList) {
        String pathStr = path.toString();
        for (String exclude : excludeList) {
            if (pathStr.contains(File.separator + exclude + File.separator) ||
                pathStr.endsWith(File.separator + exclude)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 并行扫描任务
     */
    private static class ScanTask extends RecursiveTask<List<SecretFinding>> {
        private final List<File> files;
        private final int start;
        private final int end;
        
        private static final int THRESHOLD = 10;
        
        ScanTask(List<File> files, int start, int end) {
            this.files = files;
            this.start = start;
            this.end = end;
        }
        
        @Override
        protected List<SecretFinding> compute() {
            List<SecretFinding> results = new ArrayList<>();
            
            if (end - start <= THRESHOLD) {
                // 直接扫描
                for (int i = start; i < end; i++) {
                    results.addAll(scanFile(files.get(i)));
                }
            } else {
                // 分而治之
                int mid = (start + end) / 2;
                ScanTask left = new ScanTask(files, start, mid);
                ScanTask right = new ScanTask(files, mid, end);
                
                left.fork();
                List<SecretFinding> rightResults = right.compute();
                List<SecretFinding> leftResults = left.join();
                
                results.addAll(leftResults);
                results.addAll(rightResults);
            }
            
            return results;
        }
    }
    
    /**
     * 扫描单个文件
     */
    private static List<SecretFinding> scanFile(File file) {
        List<SecretFinding> findings = new ArrayList<>();
        
        try {
            String content = Files.readString(file.toPath());
            findings.addAll(SecretDetector.detectSecrets(content, file.getPath()));
            
            if (!findings.isEmpty()) {
                System.out.println("  ⚠️  " + file.getName() + ": " + findings.size() + " 个问题");
            }
        } catch (IOException e) {
            System.err.println("  ❌ 读取文件失败: " + file.getPath());
        }
        
        return findings;
    }
}
