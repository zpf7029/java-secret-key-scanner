package com.auditor.secrets;

/**
 * 敏感信息发现结果
 */
public class SecretFinding {
    
    private final SecretType type;
    private final String matchedText;
    private final String fileName;
    private final int lineNumber;
    private final String context;
    private final int startPosition;
    private final int endPosition;
    
    public SecretFinding(SecretType type, String matchedText, String fileName, 
                        int lineNumber, String context, int startPosition, int endPosition) {
        this.type = type;
        this.matchedText = matchedText;
        this.fileName = fileName;
        this.lineNumber = lineNumber;
        this.context = context;
        this.startPosition = startPosition;
        this.endPosition = endPosition;
    }
    
    public SecretType getType() {
        return type;
    }
    
    public String getMatchedText() {
        return matchedText;
    }
    
    public String getFileName() {
        return fileName;
    }
    
    public int getLineNumber() {
        return lineNumber;
    }
    
    public String getContext() {
        return context;
    }
    
    public int getStartPosition() {
        return startPosition;
    }
    
    public int getEndPosition() {
        return endPosition;
    }
    
    /**
     * 获取脱敏后的显示文本
     */
    public String getMaskedText() {
        if (matchedText == null || matchedText.length() <= 8) {
            return "****";
        }
        
        // 根据类型决定脱敏策略
        if (type == SecretType.CREDIT_CARD) {
            // 信用卡只显示后4位
            return "****-****-****-" + matchedText.substring(matchedText.length() - 4);
        }
        
        if (type == SecretType.PRIVATE_KEY) {
            // 私钥显示前50字符和后20字符
            if (matchedText.length() > 80) {
                return matchedText.substring(0, 50) + "...(中间隐藏)...\n" + matchedText.substring(matchedText.length() - 20);
            }
        }
        
        // 其他情况只显示前后4个字符
        int visibleChars = Math.min(4, matchedText.length() / 4);
        String prefix = matchedText.substring(0, visibleChars);
        String suffix = matchedText.substring(matchedText.length() - visibleChars);
        return prefix + "****" + suffix;
    }
    
    /**
     * 获取严重程度描述
     */
    public String getSeverityDescription() {
        return type.getSeverityLevel() + " " + type.getChineseName();
    }
    
    @Override
    public String toString() {
        return String.format("[%s] %s:%d - %s", 
            type.getSeverity(), fileName, lineNumber, getMaskedText());
    }
}
