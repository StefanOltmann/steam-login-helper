plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.trueangle.lambda)
    alias(libs.plugins.git.versioning)
}

group = "de.stefan_oltmann.steam"
version = "0.1"

gitVersioning.apply {

    refs {
        tag("(?<version>.*)") {
            version = "\${ref.version}"
        }
    }

    rev {
        version = "\${commit.short}"
    }
}

repositories {
    mavenCentral()
}

kotlin {

    listOf(
        linuxArm64()
    ).forEach {
        it.binaries {
            executable {
                entryPoint = "de.stefan_oltmann.steam.main"
                // freeCompilerArgs += listOf("-Xallocator=mimalloc")
            }
        }
    }

    sourceSets {
        nativeMain.dependencies {

            implementation(libs.ktor.client.core)
            implementation(libs.ktor.client.curl)

            implementation(libs.trueangle.lambda.runtime)
            implementation(libs.trueangle.lambda.events)

            /* Cryptography (JWT) */
            implementation(libs.jwtkt)
            implementation(libs.jwtkt.ecdsa)
        }

        nativeTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}

buildLambdaRelease {
    architecture.set(Architecture.LINUX_ARM64)
}
