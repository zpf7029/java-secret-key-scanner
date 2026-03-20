package com.auditor.secrets;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 敏感信息检测器
 * 定义各种敏感信息的检测模式和规则
 */
public class SecretDetector {
    
    // 预编译的正则表达式模式
    private static final Map<SecretType, Pattern> PATTERNS = new HashMap<>();
    
    static {
        // 密码模式
        PATTERNS.put(SecretType.PASSWORD, Pattern.compile(
            "(?i)(password|passwd|pwd|pass|暗码|密码)\\s*[=:]\\s*[\"']?([^\"'\\s,;]{4,100})[\"']?",
            Pattern.CASE_INSENSITIVE
        ));
        
        PATTERNS.put(SecretType.DB_PASSWORD, Pattern.compile(
            "(?i)(db[_-]?password|database[_-]?password|mysql[_-]?password|postgres[_-]?password|oracle[_-]?password|mongodb[_-]?password)\\s*[=:]\\s*[\"']?([^\"'\\s]{4,100})[\"']?",
            Pattern.CASE_INSENSITIVE
        ));
        
        // API密钥模式
        PATTERNS.put(SecretType.API_KEY, Pattern.compile(
            "(?i)(api[_-]?key|apikey|api_secret|apiKey)\\s*[=:]\\s*[\"']?([a-zA-Z0-9_\\-]{16,64})[\"']?",
            Pattern.CASE_INSENSITIVE
        ));
        
        // 私钥模式
        PATTERNS.put(SecretType.PRIVATE_KEY, Pattern.compile(
            "(?i)(private[_-]?key|私钥|RSA[_-]?KEY|DSA[_-]?KEY|EC[_-]?KEY)\\s*[=:]\\s*[\"']?-----BEGIN[\\s\\S]*?-----END[\\s\\S]*?-----[\"']?",
            Pattern.CASE_INSENSITIVE
        ));
        
        // AWS密钥模式
        PATTERNS.put(SecretType.AWS_ACCESS_KEY, Pattern.compile(
            "(?i)(aws[_-]?access[_-]?key[_-]?id|aws_access_key|AKIA[0-9A-Z]{16})\\s*[=:]\\s*[\"']?([A-Z0-9]{20})[\"']?",
            Pattern.CASE_INSENSITIVE
        ));
        
        PATTERNS.put(SecretType.AWS_SECRET_KEY, Pattern.compile(
            "(?i)(aws[_-]?secret[_-]?access[_-]?key|aws_secret_key|aws[_-]?secret)\\s*[=:]\\s*[\"']?([a-zA-Z0-9/+=]{40})[\"']?",
            Pattern.CASE_INSENSITIVE
        ));
        
        // 阿里云密钥
        PATTERNS.put(SecretType.ALIYUN_KEY, Pattern.compile(
            "(?i)(aliyun[_-]?(access|secret|api)[_-]?key?|LTAI[0-9a-zA-Z]{20,})\\s*[=:]\\s*[\"']?([^\"'\\s]{20,40})[\"']?",
            Pattern.CASE_INSENSITIVE
        ));
        
        // 腾讯云密钥
        PATTERNS.put(SecretType.TENCENT_KEY, Pattern.compile(
            "(?i)(tencent[_-]?(secret|api)[_-]?key?|AKID[0-9a-zA-Z]{20,}|SecretId)\\s*[=:]\\s*[\"']?([^\"'\\s]{20,50})[\"']?",
            Pattern.CASE_INSENSITIVE
        ));
        
        // JWT密钥
        PATTERNS.put(SecretType.JWT_SECRET, Pattern.compile(
            "(?i)(jwt[_-]?secret|jwt[_-]?key|json[_-]?web[_-]?token[_-]?secret|jjwt[_-]?key)\\s*[=:]\\s*[\"']?([^\"'\\s]{16,128})[\"']?",
            Pattern.CASE_INSENSITIVE
        ));
        
        // Bearer令牌
        PATTERNS.put(SecretType.Bearer_TOKEN, Pattern.compile(
            "(?i)(bearer[_-]?token|access[_-]?token|refresh[_-]?token)\\s*[=:]\\s*[\"']?(eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]*)[\"']?",
            Pattern.CASE_INSENSITIVE
        ));
        
        // OAuth密钥
        PATTERNS.put(SecretType.OAUTH_SECRET, Pattern.compile(
            "(?i)(oauth[_-]?(client[_-]?secret|secret)|client[_-]?secret)\\s*[=:]\\s*[\"']?([^\"'\\s]{16,128})[\"']?",
            Pattern.CASE_INSENSITIVE
        ));
        
        // JDBC连接字符串
        PATTERNS.put(SecretType.JDBC_URL, Pattern.compile(
            "jdbc:(mysql|postgresql|oracle|sqlserver|mongodb)://[^\"'\\s]+:[^\"'\\s]+@[^\"'\\s]+",
            Pattern.CASE_INSENSITIVE
        ));
        
        // 通用密钥
        PATTERNS.put(SecretType.SECRET_KEY, Pattern.compile(
            "(?i)(secret[_-]?key|encryption[_-]?key|app[_-]?secret|salt)\\s*[=:]\\s*[\"']?([^\"'\\s]{8,128})[\"']?",
            Pattern.CASE_INSENSITIVE
        ));
        
        // Base64编码的密钥
        PATTERNS.put(SecretType.GENERIC_SECRET, Pattern.compile(
            "(?i)(base64|encoded)[_-]?(key|secret|token|password)\\s*[=:]\\s*[\"']?([A-Za-z0-9+/=]{20,})[\"']?",
            Pattern.CASE_INSENSITIVE
        ));
        
        // 信用卡号
        PATTERNS.put(SecretType.CREDIT_CARD, Pattern.compile(
            "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b"
        ));
        
        // 内网IP
        PATTERNS.put(SecretType.INTERNAL_IP, Pattern.compile(
            "\\b(?:10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}|172\\.(?:1[6-9]|2[0-9]|3[0-1])\\.[0-9]{1,3}\\.[0-9]{1,3}|192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3}|127\\.0\\.0\\.1)\\b"
        ));
        
        // 邮箱地址
        PATTERNS.put(SecretType.EMAIL, Pattern.compile(
            "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
        ));
        
        // 手机号
        PATTERNS.put(SecretType.PHONE, Pattern.compile(
            "(?:\\+?86)?1[3-9]\\d{9}"
        ));
        
        // 硬编码凭据通用模式
        PATTERNS.put(SecretType.HARDCODED_CREDENTIAL, Pattern.compile(
            "(?i)(username|user[_-]?name|login|credential)\\s*[=:]\\s*[\"']?([^\"'\\s]{2,50})[\"']?.*?(?=(?:password|passwd|secret|token|key)[=:]\\s*[\"']?[^\"'\\s])"
        ));
        
        // 文件路径中的敏感信息
        PATTERNS.put(SecretType.FILE_PATH_SENSITIVE, Pattern.compile(
            "(?i)(/etc/passwd|/etc/shadow|/home/.*\\.pem|/.ssh/|/root/.aws/|C:\\\\Users\\\\[^\"'\\\\]+\\\\.pem)"
        ));
    }
    
    /**
     * 检测代码中的所有敏感信息
     */
    public static List<SecretFinding> detectSecrets(String content, String fileName) {
        List<SecretFinding> findings = new ArrayList<>();
        
        for (Map.Entry<SecretType, Pattern> entry : PATTERNS.entrySet()) {
            SecretType type = entry.getKey();
            Pattern pattern = entry.getValue();
            
            java.util.regex.Matcher matcher = pattern.matcher(content);
            while (matcher.find()) {
                String matchedText = matcher.group();
                String context = extractContext(content, matcher.start(), matcher.end());
                int lineNumber = calculateLineNumber(content, matcher.start());
                
                // 排除注释中的敏感信息
                if (isInComment(content, matcher.start(), lineNumber)) {
                    continue;
                }
                
                // 排除测试代码中的敏感信息（可选）
                if (isTestCode(matchedText)) {
                    continue;
                }
                
                SecretFinding finding = new SecretFinding(
                    type,
                    matchedText,
                    fileName,
                    lineNumber,
                    context,
                    matcher.start(),
                    matcher.end()
                );
                findings.add(finding);
            }
        }
        
        return findings;
    }
    
    /**
     * 提取上下文
     */
    private static String extractContext(String content, int start, int end) {
        int contextStart = Math.max(0, start - 30);
        int contextEnd = Math.min(content.length(), end + 30);
        String context = content.substring(contextStart, contextEnd);
        
        // 清理换行符
        context = context.replace("\n", "\\n").replace("\r", "\\r");
        if (contextStart > 0) {
            context = "..." + context;
        }
        if (contextEnd < content.length()) {
            context = context + "...";
        }
        
        return context;
    }
    
    /**
     * 计算行号
     */
    private static int calculateLineNumber(String content, int position) {
        int lineNumber = 1;
        for (int i = 0; i < position && i < content.length(); i++) {
            if (content.charAt(i) == '\n') {
                lineNumber++;
            }
        }
        return lineNumber;
    }
    
    /**
     * 检查是否在注释中
     */
    private static boolean isInComment(String content, int position, int lineNumber) {
        // 检查单行注释 //
        int lineStart = content.lastIndexOf('\n', position) + 1;
        int lineEnd = content.indexOf('\n', position);
        if (lineEnd == -1) lineEnd = content.length();
        
        String line = content.substring(lineStart, lineEnd);
        if (line.trim().startsWith("//")) {
            return true;
        }
        
        // 检查多行注释 /* */
        if (position >= 2) {
            String before = content.substring(Math.max(0, position - 2), position);
            if (before.equals("/*")) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 检查是否是测试代码
     */
    private static boolean isTestCode(String matchedText) {
        // 排除常见的测试值
        String[] testValues = {"test", "Test", "TEST", "xxx", "123456", "password123", "admin", "demo", "sample"};
        for (String test : testValues) {
            if (matchedText.contains(test)) {
                return true;
            }
        }
        return false;
    }
}
