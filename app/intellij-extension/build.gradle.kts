// AI 漏洞扫描器 IntelliJ 插件 Gradle 构建文件。
// 使用 IntelliJ Platform Gradle Plugin（org.jetbrains.intellij）。
// 参考: https://plugins.jetbrains.com/docs/intellij/tools-intellij-platform-gradle-plugin.html
//
// 本项目为桩代码：需先执行 ./gradlew setupDependencies 下载 IntelliJ Platform SDK
// 后才能在 IDE 中编译运行。

plugins {
    id("java")
    // IntelliJ Platform Gradle Plugin 2.x（指定版本号需联网下载）
    id("org.jetbrains.intellij") version "2.0.1"
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
}

intellij {
    // 目标 IDE 版本（与 plugin.xml 的 idea-version 保持一致）
    version.set("2023.2")
    type.set("IC") // IC = IntelliJ IDEA Community Edition

    // 插件描述文件路径
    pluginName.set("vuln-scanner")

    // 无需额外插件依赖（仅用平台核心 API）
    plugins.set(emptyList())
}

tasks {
    // 禁止 patchPluginXml 自动改写 plugin.xml
    patchPluginXml {
        sinceBuild.set("221")
        untilBuild.set("241.*")
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
