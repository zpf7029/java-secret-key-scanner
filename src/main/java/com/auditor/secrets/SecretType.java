package com.auditor.secrets;

/**
 * 敏感信息类型枚举
 */
public enum SecretType {
    // 认证凭据类
    PASSWORD("密码", "CRITICAL", "硬编码密码是最常见的安全漏洞之一"),
    API_KEY("API密钥", "CRITICAL", "API密钥泄露可能导致未授权访问"),
    PRIVATE_KEY("私钥", "CRITICAL", "私钥泄露可能导致身份伪造和加密通信被解密"),
    SECRET_KEY("密钥", "CRITICAL", "密钥用于数据加密，泄露后加密保护失效"),
    
    // 数据库类
    DB_PASSWORD("数据库密码", "HIGH", "数据库凭据泄露可能导致数据泄露"),
    DB_CONNECTION("数据库连接", "HIGH", "数据库连接信息包含敏感配置"),
    JDBC_URL("JDBC连接字符串", "HIGH", "JDBC URL可能包含用户名密码"),
    
    // 云服务类
    AWS_ACCESS_KEY("AWS访问密钥", "CRITICAL", "AWS密钥可用于访问云资源"),
    AWS_SECRET_KEY("AWS秘钥", "CRITICAL", "AWS秘钥用于签名请求"),
    AZURE_KEY("Azure密钥", "CRITICAL", "Azure访问密钥"),
    GCP_KEY("GCP密钥", "CRITICAL", "Google Cloud Platform服务账号密钥"),
    
    // 令牌类
    JWT_SECRET("JWT密钥", "HIGH", "JWT签名密钥泄露后可以伪造任意令牌"),
    Bearer_TOKEN("Bearer令牌", "HIGH", "认证令牌可用于冒充用户"),
    OAUTH_SECRET("OAuth密钥", "CRITICAL", "OAuth应用密钥"),
    
    // 认证协议类
    BASIC_AUTH("Basic认证", "MEDIUM", "Base64编码的认证信息"),
    API_TOKEN("API令牌", "HIGH", "API访问令牌"),
    
    // 加密相关
    ENCRYPTION_KEY("加密密钥", "CRITICAL", "数据加密密钥"),
    ENCRYPTION_SALT("加密盐", "MEDIUM", "密码哈希盐值"),
    
    // 云服务商特定
    ALIYUN_KEY("阿里云密钥", "CRITICAL", "阿里云访问密钥"),
    TENCENT_KEY("腾讯云密钥", "CRITICAL", "腾讯云SecretId/SecretKey"),
    HUAWEI_KEY("华为云密钥", "CRITICAL", "华为云访问密钥"),
    
    // 第三方服务
    STRIPE_KEY("Stripe密钥", "CRITICAL", "支付平台API密钥"),
    TWILIO_KEY("Twilio密钥", "HIGH", "短信/电话服务API密钥"),
    SENDGRID_KEY("SendGrid密钥", "HIGH", "邮件服务API密钥"),
    
    // 通用模式
    GENERIC_SECRET("通用密钥", "MEDIUM", "可能包含敏感配置"),
    HARDCODED_CREDENTIAL("硬编码凭据", "CRITICAL", "任何形式的硬编码认证信息"),
    
    // 文件路径模式
    FILE_PATH_SENSITIVE("敏感文件路径", "LOW", "包含敏感系统路径"),
    
    // IP地址模式
    INTERNAL_IP("内网IP", "MEDIUM", "内网IP地址泄露"),
    
    // 其他
    EMAIL("邮箱地址", "LOW", "个人邮箱地址"),
    PHONE("手机号码", "LOW", "手机号码"),
    CREDIT_CARD("信用卡号", "CRITICAL", "信用卡号必须遵循PCI-DSS规范"),
    
    // 自定义
    CUSTOM_PATTERN("自定义模式", "MEDIUM", "用户自定义的敏感词匹配");

    private final String chineseName;
    private final String severity;
    private final String description;

    SecretType(String chineseName, String severity, String description) {
        this.chineseName = chineseName;
        this.severity = severity;
        this.description = description;
    }

    public String getChineseName() {
        return chineseName;
    }

    public String getSeverity() {
        return severity;
    }

    public String getDescription() {
        return description;
    }

    public String getSeverityLevel() {
        switch (this.severity) {
            case "CRITICAL": return "🔴 严重";
            case "HIGH": return "🟠 高危";
            case "MEDIUM": return "🟡 中危";
            case "LOW": return "🟢 低危";
            default: return severity;
        }
    }
}
