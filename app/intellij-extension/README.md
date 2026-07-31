# AI 漏洞扫描器 IntelliJ 插件

将编辑器中选中的代码发送到后端 `http://localhost:8765/api/analyze` 进行漏洞扫描，
结果以气球通知形式展示。

## 安装

1. 获取插件包 `vuln-scanner-0.1.0.zip`（位于 `app/intellij-extension/build/distributions/`，或从开发者处获取）
2. 打开 IntelliJ IDEA → `File` → `Settings` → `Plugins`
3. 点击右上角齿轮图标 ⚙️ → **Install Plugin from Disk...**
4. 选择 `vuln-scanner-0.1.0.zip` → 安装 → 重启 IDEA

## 前置条件

1. **IntelliJ IDEA**（Community 或 Ultimate 均可）
2. **后端服务已启动并保持运行**：在项目根目录双击 `start_windows.bat`（或 `bash app/launcher/start_linux_macos.sh`）启动后端，确认 `http://localhost:8765/api/health/live` 可访问。**后端必须常驻后台，关闭后插件无法工作。**

## 使用方式

1. 启动后端服务（双击 `start_windows.bat`，选 Web 模式 / 插件模式 / 全部均可，后端会常驻后台）
2. 在 IntelliJ IDEA 中打开任意项目或代码文件
3. 在编辑器中**选中要扫描的代码**（未选中时扫描整个文件）
4. 右键 → **AI 漏洞扫描**（或快捷键 `Ctrl+Shift+V`）
5. 等待扫描完成，结果以气球通知形式弹出，显示漏洞类型、风险等级、触发点

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

## 与 VSCode 插件的差异

| 特性           | VSCode 插件          | IntelliJ 插件（本目录） |
|---------------|----------------------|------------------------|
| 结果展示       | Webview 面板（详细）  | 气球通知（摘要）        |
| 诊断标记       | 红色波浪线            | 暂未实现              |
| 批量扫描       | 支持                  | 暂未实现              |
| 后端 API       | `/api/analyze`        | `/api/analyze`         |

本插件为毕业设计演示用插件，功能较 VSCode 插件精简，仅展示选中代码的扫描流程。两个插件共享同一个后端服务，可同时使用。
