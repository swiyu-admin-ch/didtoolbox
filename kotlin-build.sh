cargo build --release
cargo run --bin uniffi-bindgen generate --library target/release/libtrustdidweb.so --language kotlin --out-dir bindings/kotlin
cp target/release/libtrustdidweb.so bindings/kotlin