cargo build --release
cargo run --bin uniffi-bindgen generate --library target/release/libdidtoolbox.so --language python --out-dir bindings/python
cp target/release/libdidtoolbox.so bindings/python
cp -r bindings/ did_server