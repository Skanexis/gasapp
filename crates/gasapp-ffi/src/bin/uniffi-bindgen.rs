// SPDX-License-Identifier: Apache-2.0

//! Генератор биндингов UniFFI для Swift и Kotlin.
//!
//! Запускается скриптами `tools/build-rust-android.sh` и
//! `tools/build-rust-ios.sh` после сборки библиотеки.

fn main() {
    uniffi::uniffi_bindgen_main();
}
