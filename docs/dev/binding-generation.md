# GasApp UniFFI Binding Generation Guide

## Overview
This document explains how to generate UniFFI bindings for the GasApp project. The bindings allow the Android (Kotlin) and iOS (Swift) applications to call Rust functions in the gasapp-ffi crate.

## Prerequisites

### For Android Bindings
1. **Android NDK** - Install and set ANDROID_NDK_HOME environment variable
2. **cargo-ndk** - Install via: `cargo install cargo-ndk`
3. **Rust Android targets** - Install via:
   ```bash
   rustup target add aarch64-linux-android \
                     armv7-linux-androideabi \
                     x86_64-linux-android \
                     i686-linux-android
   ```

### For iOS Bindings
1. **macOS** with Xcode installed (required for lipo and xcodebuild)
2. **Rust iOS targets** - Install via:
   ```bash
   rustup target add aarch64-apple-ios \
                     aarch64-apple-ios-sim \
                     x86_64-apple-ios
   ```

## Binding Generation Process

### Android Bindings
Run the following script from the project root:
```bash
./tools/build-rust-android.sh [--debug] [--abi arm64-v8a]
```

Options:
- `--debug`: Build debug variant instead of release
- `--abi`: Specify a single ABI to build (default: all ABIs)

The script will:
1. Build the gasapp-ffi crate for all Android ABIs using cargo-ndk
2. Generate Kotlin bindings using uniffi-bindgen in library mode
3. Place bindings in `android/app/src/main/kotlin/uniffi/gasapp/`
4. Copy compiled .so libraries to `android/app/src/main/jniLibs/<abi>/`

### iOS Bindings
Run the following script from the project root (requires macOS):
```bash
./tools/build-rust-ios.sh [--debug]
```

Options:
- `--debug`: Build debug variant instead of release

The script will:
1. Build the gasapp-ffi crate for iOS device and simulator targets
2. Generate Swift bindings using uniffi-bindgen in library mode
3. Create an XCFramework combining device and simulator slices
4. Place bindings in `ios/GasApp/Generated/`
5. Place XCFramework in `ios/GasAppCore.xcframework`

## Generated Binding Files

### Android
After successful generation, you should see:
```
android/app/src/main/kotlin/uniffi/gasapp/
├── GasApp.kt                    # Main interface to GasApp functions
├── GasAppErrors.kt              # Error handling
�└── uniffi/                     # UniFFI helper classes (auto-generated)
```

The main interface (GasApp.kt) will expose functions like:
- `fun coreVersion(): String`
- `fun protocolVersion(): Int`
- `fun checkProtocolVersion(raw: Int): Result<Int, FfiException>`
- `fun formatSafetyNumber(local: ByteArray, remote: ByteArray): Result<String, FfiException>`

### iOS
After successful generation, you should see:
```
ios/GasApp/Generated/
├── GasApp.swift                 # Main interface to GasApp functions
├── GasAppError.swift            # Error handling
�└── uniffi/                     # UniFFI helper classes (auto-generated)
```

And the XCFramework:
```
ios/GasAppCore.xcframework/
```

The main interface (GasApp.swift) will expose functions like:
- `func coreVersion() -> String`
- `func protocolVersion() -> UInt8`
- `func checkProtocolVersion(raw: UInt8) -> Result<UInt8, FfiError>`
- `func formatSafetyNumber(local: [UInt8], remote: [UInt8]) -> Result<String, FfiError>`

## Verification of Generated Bindings

### Android
Check that the following files exist after generation:
- `android/app/src/main/kotlin/uniffi/gasapp/GasApp.kt`
- `android/app/src/main/jniLibs/armeabi-v7a/libgasapp.so`
- `android/app/src/main/jniLibs/arm64-v8a/libgasapp.so`
- `android/app/src/main/jniLibs/x86/libgasapp.so`
- `android/app/src/main/jniLibs/x86_64/libgasapp.so`

### iOS
Check that the following exist after generation:
- `ios/GasApp/Generated/GasApp.swift`
- `ios/GasAppCore.xcframework/` (containing the framework binary and headers)

## Integration with Applications

### Android
Once bindings are generated:
1. The `uniffi.gasapp.GasApp` class can be imported and used in MainActivity.kt
2. Functions return Kotlin Result types that need to be handled
3. Example usage:
   ```kotlin
   val coreVersion = GasApp.coreVersion()
   val safetyNumberResult = GasApp.formatSafetyNumber(localData, remoteData)
   safetyNumberResult.fold(
       { error -> /* handle error */ },
       { number -> /* use safety number */ }
   )
   ```

### iOS
Once bindings are generated:
1. The `GasAppCore` module can be imported and used in ContentView.swift
2. Functions throw Swift errors that need to be caught
3. Example usage:
   ```swift
   let coreVersion = GasAppCore.coreVersion()
   do {
       let safetyNumber = try GasAppCore.formatSafetyNumber(local: localData, remote: remoteData)
       // use safetyNumber
   } catch {
       // handle error
   }
   ```

## Troubleshooting

### Common Android Issues
1. **"error: ANDROID_NDK_HOME не задан"** - Set the ANDROID_NDK_HOME environment variable
2. **"error: cargo-ndk не установлен"** - Run `cargo install cargo-ndk`
3. **"error: не найдена собранная библиотека"** - Ensure Rust Android targets are installed
4. **"error: uniffi-bindgen не создал ни одного файла Kotlin"** - Check that UNIFFI_META_* symbols weren't stripped (verify strip = "debuginfo" in Cargo.toml)

### Common iOS Issues
1. **"error: сборка под iOS возможна только на macOS"** - This script requires macOS
2. **"error: не найден $tool — установите Xcode"** - Install Xcode from App Store
3. **Linking errors** - Ensure the XCFramework is properly linked in the Xcode project

## Notes on Binding Regeneration

Bindings must be regenerated whenever:
1. The FFI interface in `crates/gasapp-ffi/src/lib.rs` changes (functions added/removed/modified)
2. The UniFFI version is changed in Cargo.toml
3. Major Rust compiler updates that affect ABI compatibility

After regenerating bindings,重新build the Android/iOS applications to pick up the changes.

## Security Considerations

The UniFFI bindings are generated in "library mode", which means:
- Bindings are generated from the compiled library, not from an IDL file
- This prevents drift between what the Rust code exports and what the bindings expect
- The bindings are guaranteed to match the actual compiled library interface

## References
- UniFFI Documentation: https://github.com/mozilla/uniffi-rs
- GasApp FFI Design: See `crates/gasapp-ffi/src/lib.rs` comments
- Android Build Script: `tools/build-rust-android.sh`
- iOS Build Script: `tools/build-rust-ios.sh`