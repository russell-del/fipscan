plugins {
    java
    application
}

repositories {
    mavenCentral()
}

dependencies {
    // Kotlin DSL — parens always
    implementation("org.bouncycastle:bcprov-jdk18on:1.77")
    implementation("org.mindrot:jbcrypt:0.4")

    runtimeOnly("commons-codec:commons-codec:1.16.0")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")

    // Platform / BOM — captures the BOM coordinate; harmless
    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.2.1"))
}
