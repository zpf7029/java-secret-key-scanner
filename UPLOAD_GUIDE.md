# 上传到 GitHub 指南

## 方式一：使用 GitHub 网页（推荐）

### 步骤1：下载项目文件
1. 打开文件管理器
2. 导航到：`C:\Users\0.0\.qclaw\workspace\`
3. 找到 `java-secret-key-scanner.tar.gz` 文件
4. 解压到同目录

### 步骤2：创建 GitHub 仓库
1. 打开浏览器访问：https://github.com/zpf7029/oblong
2. 点击 "Add file" → "Create new file"
3. 文件名输入：`java-secret-key-scanner/README.md`
4. 粘贴 README.md 内容（见下方）
5. 点击 "Commit changes"

### 步骤3：上传其他文件
1. 点击 "Add file" → "Upload files"
2. 拖拽解压后的 `java-secret-key-scanner` 文件夹中的所有文件
3. 点击 "Commit changes"

---

## 方式二：使用 Git 命令行（需要本地安装 Git）

```powershell
# 1. 克隆空仓库（如果已有）
git clone https://github.com/zpf7029/oblong.git
cd oblong

# 2. 创建子目录
mkdir java-secret-key-scanner

# 3. 复制项目文件到目录
# （将 C:\Users\0.0\.qclaw\workspace\java-secret-key-scanner\ 下的所有文件复制到此处）

# 4. 提交并推送
git add .
git commit -m "feat: Add Java Secret Key Scanner"
git push
```

---

## 方式三：使用 GitHub CLI（本工具已安装）

以管理员身份打开 PowerShell，运行：

```powershell
# 1. 登录 GitHub
"C:\Program Files\GitHub CLI\gh.exe" auth login --hostname github.com --web

# 2. 克隆仓库
git clone https://github.com/zpf7029/oblong.git
cd oblong

# 3. 创建目录并复制文件
mkdir java-secret-key-scanner
# 复制项目文件...

# 4. 推送
git add .
git commit -m "feat: Add Java Secret Key Scanner"
git push
```

---

## 项目文件清单

请按以下结构上传所有文件：

```
java-secret-key-scanner/
├── .github/
│   └── workflows/
│       └── ci.yml
├── .gitignore
├── LICENSE
├── README.md
├── pom.xml
└── src/
    └── main/
        └── java/
            └── com/
                └── auditor/
                    ├── SecretScannerCLI.java
                    ├── report/
                    │   └── ReportGenerator.java
                    └── secrets/
                        ├── SecretDetector.java
                        ├── SecretFinding.java
                        └── SecretType.java
```

---

## 仓库地址

- **GitHub**: https://github.com/zpf7029/oblong
- **项目目录**: https://github.com/zpf7029/oblong/tree/main/java-secret-key-scanner
