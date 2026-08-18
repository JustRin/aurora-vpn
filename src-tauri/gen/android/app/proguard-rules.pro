# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# gomobile bindings resolve Go <-> Java calls by exact name at runtime.
-keep class io.nekohasekai.libbox.** { *; }
-keep class go.** { *; }

# The Tauri runtime instantiates the plugin and finds @Command methods
# through reflection, addressed by name from the Rust side.
-keep class com.aurora.vpn.VpnPlugin { *; }
-keep class com.aurora.vpn.StartArgs { *; }
-keep class com.aurora.vpn.AuroraVpnService { *; }