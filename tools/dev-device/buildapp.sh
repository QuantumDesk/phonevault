export JAVA_HOME=/root/lineage-src/prebuilts/jdk/jdk21/linux-x86
export ANDROID_HOME=/root/android-sdk
cd /root/pv-root
/root/gradle-8.10.2/bin/gradle --no-daemon :app:assembleAppliance 2>&1
echo "GRADLE_RC=$?"
