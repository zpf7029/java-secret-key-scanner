# 🛡️ Java Secret Key Scanner

🛡️ Java敏感词代码审计工具 - 自动检测代码中的硬编码密钥、密码、API密钥等敏感信息

**GitHub**: https://github.com/zpf7029/java-secret-key-scanner

## 功能特点

- 🔍 **全面检测**: 支持30+种敏感信息类型检测
- ⚡ **高性能**: 支持多线程并行扫描
- 📊 **多格式报告**: 支持控制台、JSON、HTML三种报告格式
- 🎯 **精确匹配**: 基于正则表达式的精确模式匹配
- 🛡️ **安全优先**: 自动排除注释和测试代码中的敏感信息
- 📈 **分类统计**: 按严重程度和类型分类统计

## 支持检测的敏感信息类型

| 类别 | 检测类型 |
|------|----------|
| 🔴 严重 | API密钥、私钥、AWS密钥、阿里云/腾讯云密钥、信用卡号、JWT密钥 |
| 🟠 高危 | 数据库密码、JDBC连接字符串、Bearer令牌、OAuth密钥、数据库连接 |
| 🟡 中危 | 通用密钥、Base64编码密钥、加密盐值、内网IP |
| 🟢 低危 | 邮箱地址、手机号码、敏感文件路径 |

## 快速开始

### 方式1: 使用Maven构建

```bash
# 克隆项目
git clone https://github.com/zpf7029/oblong.git
cd oblong/java-secret-key-scanner

# 构建
mvn clean package

# 运行
java -jar target/java-secret-key-scanner-1.0.0.jar -p /path/to/your/java/project
```

### 方式2: 直接下载JAR

```bash
# 下载最新的JAR文件
curl -O https://github.com/zpf7029/oblong/releases/latest/download/java-secret-key-scanner.jar

# 运行
java -jar java-secret-key-scanner.jar -p /path/to/your/java/project
```

## 使用方法

### 基本用法

```bash
# 扫描单个项目
java -jar java-secret-key-scanner.jar -p /path/to/project

# 指定项目名称
java -jar java-secret-key-scanner.jar -p /path/to/project --project-name "MyApp"

# 生成所有格式报告
java -jar java-secret-key-scanner.jar -p /path/to/project -f all

# 指定输出路径
java -jar java-secret-key-scanner.jar -p /path/to/project -o /path/to/report
```

### 高级选项

```bash
# 指定报告格式
java -jar java-secret-key-scanner.jar -p /path/to/project -f console   # 仅控制台
java -jar java-secret-key-scanner.jar -p /path/to/project -f json      # JSON格式
java -jar java-secret-key-scanner.jar -p /path/to/project -f html      # HTML格式

# 排除特定目录
java -jar java-secret-key-scanner.jar -p /path/to/project -e "target,build,.git"

# 包含测试代码中的敏感信息
java -jar java-secret-key-scanner.jar -p /path/to/project --include-test

# 指定并行线程数
java -jar java-secret-key-scanner.jar -p /path/to/project -t 8

# 查看帮助
java -jar java-secret-key-scanner.jar --help
```

## 输出示例

### 控制台输出

```
🔍 Java敏感词代码审计工具
============================================================
📁 扫描路径: /path/to/project
📋 项目名称: MyApp
🔢 并行线程: 4
============================================================

📊 发现 25 个Java文件

⚠️  UserService.java: 3 个问题
⚠️  Config.java: 5 个问题
⚠️  DatabaseUtil.java: 2 个问题

⏱️  扫描完成，耗时: 1234ms

============================================================
                    Java敏感词代码审计报告
============================================================

📋 基本信息:
   项目名称: MyApp
   扫描路径: /path/to/project
   扫描时间: 2024-01-15 10:30:00
   扫描文件: 25 个
   发现问题: 10 个

📊 严重程度统计:
   🔴 严重: 2 个
   🟠 高危: 3 个
   🟡 中危: 4 个
   🟢 低危: 1 个
```

## 检测规则

### 密码类

```java
// 危险 - 会被检测
String password = "admin123";
String dbPassword = "mysecretpassword";

// 安全 - 不会被检测
String password = System.getenv("DB_PASSWORD");
```

### API密钥类

```java
// 危险 - 会被检测
String apiKey = "sk-1234567890abcdef";
String awsKey = "AKIAIOSFODNN7EXAMPLE";

// 安全 - 不会被检测
String apiKey = System.getenv("API_KEY");
```

### 数据库连接类

```java
// 危险 - 会被检测
String jdbcUrl = "jdbc:mysql://user:password@localhost:3306/db";

// 安全 - 不会被检测
String jdbcUrl = System.getenv("JDBC_URL");
```

## 项目结构

```
java-secret-key-scanner/
├── src/main/java/com/auditor/
│   ├── SecretScannerCLI.java          # CLI入口
│   ├── secrets/
│   │   ├── SecretType.java           # 敏感信息类型枚举
│   │   ├── SecretDetector.java        # 敏感信息检测器
│   │   └── SecretFinding.java         # 检测结果
│   └── report/
│       └── ReportGenerator.java       # 报告生成器
├── src/main/resources/
│   └── patterns/                     # 自定义检测规则
├── pom.xml                           # Maven配置
└── README.md
```

## 与CI/CD集成

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up JDK
        uses: actions/setup-java@v3
        with:
          java-version: '11'
          
      - name: Build Scanner
        run: mvn clean package -DskipTests
        
      - name: Run Secret Scan
        run: |
          java -jar target/java-secret-key-scanner-1.0.0.jar \
            -p . \
            --project-name "${{ github.repository }}" \
            -f html \
            -o security-report
            
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.html
```

### GitLab CI

```yaml
secret_scan:
  image: maven:3.8-openjdk-11
  script:
    - mvn clean package -DskipTests
    - java -jar target/java-secret-key-scanner-1.0.0.jar -p . -f html -o security-report
  artifacts:
    paths:
      - security-report.html
```

## 最佳实践

1. **定期扫描**: 将扫描集成到CI/CD流程中
2. **修复优先级**: 按严重程度优先修复高危问题
3. **使用环境变量**: 敏感信息应通过环境变量或密钥管理服务获取
4. **审计报告**: 保留扫描报告用于合规审计

## 常见问题

### Q: 如何处理误报？
A: 使用排除规则 `-e` 排除特定的测试文件或配置。

### Q: 支持扫描加密的配置文件吗？
A: 当前版本不支持加密文件的扫描。

### Q: 如何添加自定义检测规则？
A: 可以在 `SecretDetector.java` 中添加新的正则表达式模式。

## 贡献

欢迎提交Issue和Pull Request！

## 许可证

MIT License

## 作者

- GitHub: [zpf7029](https://github.com/zpf7029)
- Project: [oblong](https://github.com/zpf7029/oblong)
