# AI 漏洞扫描器 IntelliJ 插件（桩代码）

将编辑器中选中的代码发送到后端 `http://localhost:8765/api/analyze` 进行漏洞扫描，
结果以通知形式展示。

> 本目录为**桩代码**，需在 IntelliJ Platform SDK 环境下配置后才能编译运行。

## 目录结构

```
intellij-extension/
├── build.gradle.kts                              # Gradle 构建文件
├── README.md                                      # 本文件
└── src/main/
    ├── java/com/graduation/vulnscanner/
    │   └── VulnScannerAction.java                 # AnAction 动作实现
    └── resources/META-INF/
        └── plugin.xml                             # 插件描述符
```

## 前置条件

1. **JDK 17+**（IntelliJ Platform 最低要求）
2. **网络可访问**（Gradle 需下载 IntelliJ Platform SDK）
3. **后端服务已启动**：在项目根目录执行
   ```bash
   uvicorn app.backend.main:app --host 127.0.0.1 --port 8765
   ```
   确认 `http://localhost:8765/api/health` 可访问。

## 构建与调试

### 方式一：在 IntelliJ IDEA 中打开

1. 用 IntelliJ IDEA（Community 或 Ultimate）打开本目录（`intellij-extension/`）
2. 等待 Gradle 同步完成（自动下载 IntelliJ Platform Gradle Plugin 与 SDK）
3. 执行 Gradle 任务 `runIde` 启动沙盒 IDE
4. 在沙盒 IDE 中打开任意代码文件 → 右键 → **AI 漏洞扫描**

### 方式二：命令行构建

```bash
# 构建（生成插件 zip 到 build/distributions/）
./gradlew buildPlugin

# 在沙盒 IDE 中运行调试
./gradlew runIde
```

## 使用方式

1. 启动后端服务（见上文前置条件）
2. 在编辑器中选中要扫描的代码（未选中时扫描整个文件）
3. 右键 → **AI 漏洞扫描**（或快捷键 `Ctrl+Shift+V`）
4. 等待扫描完成，结果将以气球通知形式弹出

## 配置

当前后端地址硬编码在 `VulnScannerAction.java` 的 `BACKEND_URL` 常量中：
```java
private static final String BACKEND_URL = "http://localhost:8765/api/analyze";
```
如需修改后端地址，直接编辑该常量后重新构建。

## 与 VSCode 插件的差异

| 特性           | VSCode 插件          | IntelliJ 插件（本目录） |
|---------------|----------------------|------------------------|
| 结果展示       | Webview 面板          | 通知（Notification）   |
| 诊断标记       | 波浪线诊断            | 暂未实现              |
| 批量扫描       | 支持                  | 暂未实现              |
| 后端 API       | `/api/analyze`        | `/api/analyze`         |

本插件为毕业设计演示用桩代码，功能较 VSCode 插件精简，仅展示选中代码的扫描流程。
