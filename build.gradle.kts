plugins {
    application
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ktor)
    alias(libs.plugins.git.versioning)
}

group = "de.stefan-oltmann"

gitVersioning.apply {

    refs {
        /* The main branch contains the current dev version */
        branch("main") {
            version = "\${commit.short}"
        }
    }

    /* Fallback if the branch was not found (for feature branches) */
    rev {
        version = "\${commit.short}"
    }
}

kotlin {
    jvmToolchain(jdkVersion = 25)
}

application {

    mainClass.set("ApplicationKt")

    val isDevelopment: Boolean = project.ext.has("development")
    applicationDefaultJvmArgs = listOf("-Dio.ktor.development=$isDevelopment")
}

sourceSets {
    main {
        kotlin {
            srcDir(layout.buildDirectory.dir("generated/source"))
        }
    }
}

repositories {
    mavenCentral()
    maven(url = "https://central.sonatype.com/repository/maven-snapshots/")
}

dependencies {

    /*
     * Ktor server
     */
    implementation(libs.bundles.ktor.server)
    implementation(libs.logback.classic)

    /*
     * Ktor client
     */
    implementation(libs.ktor.client.okhttp)

    /*
     * Cryptography (JWT)
     */
    implementation(libs.jwtkt)
    implementation(libs.jwtkt.ecdsa)

    /*
     * Unit tests
     */
    testImplementation(libs.kotlin.test.junit)
}

// region Version
project.afterEvaluate {

    logger.lifecycle("Generate Version.kt")

    val outputDir = layout.buildDirectory.file("generated/source/").get().asFile

    outputDir.mkdirs()

    val file = File(outputDir.absolutePath, "Version.kt")

    file.printWriter().use { writer ->

        writer.println("const val VERSION: String = \"$version\"")

        writer.flush()
    }
}
// endregion
