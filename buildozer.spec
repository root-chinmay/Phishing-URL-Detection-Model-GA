[app]

# (str) Title of your application
title = MobiURL-Guard

# (str) Package name
package.name = mobiurlguard

# (str) Package domain (needed for android/ios packaging)
package.domain = org.cybersecurity.mobiurlguard

# (str) Source code where the main.py lives
source.dir = .

# (list) Source files to include (let empty to include all the files)
source.include_exts = py,png,jpg,kv,atlas,json,yaml,csv

# (list) List of inclusions using pattern matching
source.include_patterns = assets/*,models/exported/*,config/*

# (str) Application versioning (method 1)
version = 1.0.0

# (list) Application requirements
# Offline inference requires ONLY pure python, kivymd/kivy, and requests if online enrichment is opted in
requirements = python3,kivy,kivymd,pillow,plyer

# (str) Supported orientation (one of landscape, sensorLandscape, portrait or all)
orientation = portrait

# (bool) Indicate if the application should be fullscreen
fullscreen = 0

# (list) Permissions
android.permissions = INTERNET,CAMERA,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE

# (int) Target Android API, should be as high as possible.
android.api = 33

# (int) Minimum API your APK / AAB will support.
android.minapi = 21

# (int) Android SDK version to use
android.sdk = 33

# (str) Android NDK version to use
android.ndk = 25b

# (bool) If True, then skip trying to update the Android sdk
# This can be useful to avoid excess Internet downloads or save time
android.skip_update = False

# (bool) If True, then accept all SDK licenses
android.accept_sdk_license = True

# (str) Android architecture to build for (e.g. armeabi-v7a, arm64-v8a)
android.archs = arm64-v8a, armeabi-v7a

# (bool) Copy library instead of making a libpymodules.so
android.copy_libs = 1

[buildozer]

# (int) Log level (0 = error only, 1 = info, 2 = debug with command output)
log_level = 2

# (int) Display warning if buildozer is run as root (0 = False, 1 = True)
warn_on_root = 0
