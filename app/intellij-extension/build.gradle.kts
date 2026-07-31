// AI 漏洞扫描器 IntelliJ 插件 Gradle 构建文件。
// 使用 IntelliJ Platform Gradle Plugin（org.jetbrains.intellij）。
// 参考: https://plugins.jetbrains.com/docs/intellij/tools-intellij-platform-gradle-plugin.html
//
// 本项目为桩代码：需先执行 ./gradlew setupDependencies 下载 IntelliJ Platform SDK
// 后才能在 IDE 中编译运行。

plugins {
    id("java")
    // IntelliJ Platform Gradle Plugin 1.x（国内环境更稳定，毕业答辩够用）
    id("org.jetbrains.intellij") version "1.17.4"
}

group = "com.graduation"
version = "0.1.0"

// 兼容的 JDK 版本（IntelliJ Platform 最低要求）
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
    gradlePluginPortal()          // Gradle 官方插件仓库（org.jetbrains.intellij 在此）
    // 阿里云镜像：加速普通依赖下载（国内环境）
    maven { url = uri("https://maven.aliyun.com/repository/public") }
    maven { url = uri("https://maven.aliyun.com/repository/gradle-plugin") }
    // JetBrains 官方仓库（部分 SDK 包仍需从官方下载）
    maven { url = uri("https://plugins.jetbrains.com/maven") }
}

intellij {
    // 目标 IDE 版本（与 plugin.xml 的 idea-version 保持一致）
    version = "2023.2"
    type = "IC" // IC = IntelliJ IDEA Community Edition

    // 插件描述文件路径
    pluginName = "vuln-scanner"

    // 无需额外插件依赖（仅用平台核心 API）
    plugins = emptyList()
}

tasks {
    patchPluginXml {
        sinceBuild.set("221")
        untilBuild.set("262.*")
    }

    // 构建可分发插件 zip
    buildPlugin {
        archiveBaseName.set("vuln-scanner")
    }

    // 在沙盒 IDE 中运行插件（调试用）
    runIde {
        // 可指定自定义 IDE 路径，默认下载临时 IDE
        // ideDir.set(file("/path/to/idea"))
    }

    // 编译参数
    withType<JavaCompile> {
        options.encoding = "UTF-8"
    }
}
