import org.gradle.language.jvm.tasks.ProcessResources
import org.gradle.jvm.tasks.Jar

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
    // compileOnly
    compileOnly(libs.montoya)
    compileOnly(libs.logbackClassic)

    // implementation
    implementation(libs.miglayoutSwing)
    implementation(libs.flexmarkAll)

    // runtimeOnly
    runtimeOnly(libs.logbackClassic)
}

sourceSets {
    main {
        java.setSrcDirs(listOf("src/java"))
    }
}

tasks.named<ProcessResources>("processResources") {
    from(rootProject.layout.projectDirectory.files("README.md", "LICENSE")) {
        into("")
    }
}

tasks.register<Jar>("fatJar") {
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

tasks.named<Jar>("jar") {
    enabled = false
}

tasks.assemble {
    dependsOn("fatJar")
}

tasks.build {
    dependsOn("fatJar")
}
