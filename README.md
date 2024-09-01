# didtoolbox

This project implements the following things:
- General util structs reused by other libraries of e-id-admin
- Trust did web according to the specification [trust-did-web](https://bcgov.github.io/trustdidweb/)

## Using the library
The library can be used either directly in rust as is or through the different built bindings which are published in different submodules
### Rust
The library can be used directly in rust by adding the following dependency to your `Cargo.toml`:
````toml
[dependencies]
didtoolbox = {git="https://github.com/e-id-admin/didtoolbox", branch = "main"}

# Optional: For manipulating the json content in the example
serde_json = "1.0.115"
````
### Additional language bindings
> General information how the bindings are generated can be found in the [UniFFI user guide](https://mozilla.github.io/uniffi-rs/latest/)

The library is also available in other languages. Please consult the documentation of the subsequent repositories for more information:
- [Kotlin / Java](https://github.com/e-id-admin/didtoolbox-kotlin)

## Example
In the example the following steps are shown:
1. Create a new did:tdw by initializing a did doc. In this did doc an ed25519 key is used as controller and to create the integrity proofs
2. Add another verification method to the existing did doc
3. Update the did log
```rust
use didtoolbox::ed25519::Ed25519KeyPair;
use didtoolbox::did_tdw::TrustDidWeb;

fn main() {
    // Base url on which base the did will be created. This is legacy logic from the first version of the tdw specification
    let base_url = String::from("https://someservice.bit.admin.ch");
    // Keypair which is used to sign the did document and isn't used for actual credential issuing
    let key_pair = Ed25519KeyPair::generate();

    // Create genesis did document which contains the public key of "key_pair" as controller and an according verification method entry
    let tdw_v1 = TrustDidWeb::create(
        base_url,
        &key_pair,
        Some(false)
    );

    // Updating the did document by adding a new verification method
    let did_doc_v1_str = tdw_v1.get_did_doc();
    println!("DID Doc v1: {}", did_doc_v1_str);
    let mut did_doc_v1: serde_json::Value = serde_json::from_str(&did_doc_v1_str).unwrap();;
    match &did_doc_v1["verificationMethod"] {
        serde_json::Value::Array(v) => v.iter().for_each(|x| println!("{}", x)),
        _ => panic!("Should fail")
    };
    did_doc_v1["verificationMethod"].as_array_mut().unwrap().push(serde_json::json!({
        "id": "<some unique identifer e.g. {did}#{usage}>",
        "type": "<public key identifier according to specification registry>",
        "controller": "<e.g. some controller did>",
        "publicKeyMultibase": "<some fancy multibase encoded public key>"
    }));
    let did_doc_v2_str = did_doc_v1.to_string();
    let tdw_v2 = TrustDidWeb::update(tdw_v1.get_did(),tdw_v1.get_did_log(), did_doc_v2_str, &key_pair);
    println!("DID Doc v2: {}", tdw_v2.get_did_doc());
}

```

## License
This project is licensed under the terms of the MIT license. See the [LICENSE](LICENSE.md) file for details.
