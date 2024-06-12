cargo build --release
cargo run --bin uniffi-bindgen generate --library target/release/libdidtoolbox.so --language kotlin --out-dir bindings/kotlin
cp target/release/libdidtoolbox.so bindings/kotlin