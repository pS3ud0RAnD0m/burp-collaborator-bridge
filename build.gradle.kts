plugins {
    java
}

group = (findProperty("group") as String?) ?: "com.ps3ud0rand0m"
version = (findProperty("version") as String?) ?: "0.0.1"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(22))
    }
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.6")

    // needed for com.ps3ud0rand0m.burp.utils.Logger (uses ch.qos.logback.*)
    compileOnly("ch.qos.logback:logback-classic:1.5.18")
    runtimeOnly("ch.qos.logback:logback-classic:1.5.18")
}

sourceSets {
    main {
        java.setSrcDirs(listOf("src/java"))
    }
}

tasks.register<org.gradle.jvm.tasks.Jar>("fatJar") {
    group = "build"
    description = "Assembles a fat JAR containing compiled classes and runtime dependencies for Burp."
    val base = (findProperty("archivesBaseName") as String?) ?: project.name
    archiveBaseName.set(base)
    archiveVersion.set(project.version.toString())
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes(
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version
        )
    }
    from(sourceSets.main.get().output)
    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get()
            .filter { it.name.endsWith("jar") }
            .map { zipTree(it) }
    })
}

tasks.named<org.gradle.jvm.tasks.Jar>("jar") {
    enabled = false
}

tasks.assemble {
    dependsOn("fatJar")
}

tasks.build {
    dependsOn("fatJar")
}
