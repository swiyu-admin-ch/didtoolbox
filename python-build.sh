cargo build --release
cargo run --bin uniffi-bindgen generate --library target/release/libtrustdidweb.so --language python --out-dir bindings/python
cp target/release/libtrustdidweb.so bindings/python
cp -r bindings/ did_server