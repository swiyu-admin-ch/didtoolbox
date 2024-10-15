// SPDX-License-Identifier: MIT
pub mod didtoolbox;
pub mod utils;
pub mod vc_data_integrity;
pub mod ed25519;
pub mod did_tdw;

use crate::didtoolbox::*;
use crate::ed25519::*;
use crate::did_tdw::*;
use rand::{Rng}; // 0.8

uniffi::include_scaffolding!("didtoolbox");

#[cfg(test)]
mod test {
    use std::borrow::BorrowMut;
    use std::borrow::Borrow;
    use base64::{Engine as _};
    use core::panic;
    use hex::ToHex;
    use std::ops::Index;
    use std::vec;
    use mockito::{Server, ServerOpts, Matcher};
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    use super::didtoolbox::*;
    use super::ed25519::*;
    use super::did_tdw::*;
    use rstest::{fixture, rstest};
    use serde_json::{json, Value};
    use sha2::{Sha256, Digest};
    use ssi::json_ld::syntax::BorrowUnordered;

    //
    // INFO: To run tests in this module, it is NO NEED to start the 'did_server'
    //       located in the folder with the same name anymore!!!
    //
    // However, if still interested in using it (as kind of playground), here is a short how-to manual.
    //
    // For instance on macOS, a Linux container may be started by running following commands:
    // - install podman:              brew update && brew install podman
    // - to start a container:        podman run -it --rm -v $(pwd):$(pwd):Z -w $(pwd) -p 8000:8000 rust
    // - to setup system packages:    apt-get update && apt-get install python3-fastapi jq lsof -y
    // - to generate bindings:        source python-build.sh
    // - to boot up the test-server:  python3 did_server/main.py &
    //                                ("lsof -i:8000" should produce some output)
    // - to (smoke) test bindings:    python3 did_server/playground.py | tail -2 | jq
    //                                Output:
    //                                INFO:     127.0.0.1:55058 - "POST /123456789/did.jsonl HTTP/1.1" 201 Created
    //                                INFO:     127.0.0.1:55068 - "GET /123456789/did.jsonl HTTP/1.1" 200 OK
    // - and the last, but not least: cargo test --color=always --profile test --package didtoolbox --lib test --no-fail-fast --config env.RUSTC_BOOTSTRAP=\"1\" -- --format=json -Z unstable-options --show-output
    // - press CTRL+D to exit container
    //

    // For testing purposes only.
    struct HttpClient {
        pub api_key: Option<String>,
    }
    impl HttpClient {
        fn read(&self, url: String) -> String {
            let mut request = ureq::get(&url);
            match &self.api_key {
                Some(api_key) => {
                    request = request.set("X-API-KEY", api_key);
                }
                None => (),
            };
            match request.call() {
                Ok(response) => match response.into_string() {
                    Ok(body) => body,
                    Err(_) => panic!("Couldn't read from url"),
                },
                Err(_) => panic!("Couldn't read from url"),
            }
        }
        /*
        fn write(&self, url: String, content: String) {
            let mut request = ureq::post(&url);
            match &self.api_key {
                Some(api_key) => {
                    request = request.set("X-API-KEY", api_key);
                },
                None => (),
            };
            match request.send_form(&[
                ("file", &content)
            ]) {
                Ok(_) => (),
                Err(e) => panic!("{}", e),
            }
        }
        */
    }

    #[fixture]
    fn unique_base_url() -> String {
        let random_thing: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        format!("https://localhost:8000/{random_thing}")
    }

    #[fixture]
    #[once]
    fn ed25519_key_pair() -> Ed25519KeyPair {
        Ed25519KeyPair::generate()
    }

    #[fixture]
    #[once]
    fn http_client() -> HttpClient {
        HttpClient {
            //api_key: None,
            api_key: Some("secret".to_string()),
        }
    }

    // For testing purposes only. Offers everything a test may need.
    struct TdwMock {
        url: String,
        did: String,
        server: Server,
    }
    impl TdwMock {
        pub fn new(key_pair: &Ed25519KeyPair, // CAUTION cannot use 'ed25519_key_pair' fixture here ;)
        ) -> Self {
            let mut server = Server::new_with_opts(ServerOpts {
                // CAUTION Setting a port explicitly would lead to "Address already in use (os error 48)" error
                ..Default::default()
            });

            let url = format!("{}/123456789", server.url());

            // CAUTION Using an existing SUT method to setup a mock is not really deterministic
            let tdw = TrustDidWeb::create(url, key_pair, Some(false));

            // assertion-relevant parsing
            let did_log = tdw.get_did_log();

            /*
            server.mock("POST", Matcher::Regex(format!(r"^/123456789/did.jsonl$")),
            ).match_body(
                //Matcher::Any
                Matcher::Regex("^file=*".to_string())
            ).with_status(201)
                .with_header("content-type", "application/x-www-form-urlencoded")
                .with_header("X-API-Key", "secret")
                .create();
            */

            // use newly created did_log (as json body) to setup the GET mock
            server.mock("GET", Matcher::Regex(r"/[a-z0-9=]+/did.jsonl$".to_string()))
                .with_body(did_log)
                .with_header("X-API-Key", "secret")
                .create();

            TdwMock {
                url: format!("{}/123456789", server.url()),
                did: tdw.get_did(),
                server, // in case additional mocks are required in a test function
            }
        }

        pub fn get_did(&self) -> String {
            self.did.clone()
        }

        pub fn get_url(&self) -> String {
            self.url.clone()
        }

        pub fn get_server(self) -> Server {
            self.server // NOT cloneable
        }
    }

    #[fixture]
    fn tdw_mock(ed25519_key_pair: &Ed25519KeyPair, // fixture
    ) -> TdwMock {
        TdwMock::new(ed25519_key_pair)
    }

    #[rstest]
    #[case("did:tdw:myScid:localhost%3A8000:123:456", "http://localhost:8000/123/456/did.jsonl")]
    #[case("did:tdw:myScid:localhost%3A8000", "http://localhost:8000/did.jsonl")]
    #[case("did:tdw:myScid:localhost", "http://localhost/.well-known/did.jsonl")]
    #[case("did:tdw:myScid:admin.ch%3A8000:123:456", "http://admin.ch:8000/123/456/did.jsonl")]
    #[case("did:tdw:myScid:admin.ch%3A8000", "http://admin.ch:8000/did.jsonl")]
    #[case("did:tdw:myScid:admin.ch", "http://admin.ch/.well-known/did.jsonl")]
    #[case("did:tdw:myScid:sub.admin.ch", "http://sub.admin.ch/.well-known/did.jsonl")]
    #[case("did:tdw:myScid:sub.admin.ch:mypath:mytrala", "http://sub.admin.ch/mypath/mytrala/did.jsonl"
    )]
    fn test_tdw_to_url_conversion(#[case] tdw: String, #[case] url: String) {
        let tdw = TrustDidWebId::try_from((tdw, Some(true))).unwrap();
        let resolved_url = tdw.get_url();
        assert_eq!(resolved_url, url)
    }

    #[rstest]
    #[case("did:xyz:myScid:localhost%3A8000:123:456")]
    fn test_tdw_to_url_conversion_error_kind_method_not_supported(#[case] tdw: String) {
        match TrustDidWebId::try_from((tdw, Some(true))) {
            Err(e) => assert_eq!(e.kind(), TrustDidWebIdResolutionErrorKind::MethodNotSupported),
            _ => (),
        }
    }

    #[rstest]
    #[case("did:tdw:")]
    fn test_tdw_to_url_conversion_error_kind_invalid_method_specific_id(#[case] tdw: String) {
        match TrustDidWebId::try_from((tdw, Some(true))) {
            Err(e) => assert_eq!(e.kind(), TrustDidWebIdResolutionErrorKind::InvalidMethodSpecificId),
            _ => (),
        }
    }

    #[rstest]
    #[case("http://localhost:8000/123/456", "localhost%3A8000:123:456")]
    #[case("http://localhost:8000", "localhost%3A8000")]
    #[case("http://localhost/123/456", "localhost:123:456")]
    #[case("http://sub.localhost/123/456", "sub.localhost:123:456")]
    #[case("http://sub.localhost", "sub.localhost")]
    fn test_url_to_tdw_domain(#[case] url: String, #[case] domain: String) {
        let resolved_domain = get_tdw_domain_from_url(&url, Some(true));
        assert_eq!(domain, resolved_domain)
    }

    #[rstest]
    fn test_did_wrapping(tdw_mock: TdwMock, // fixture
                         http_client: &HttpClient, // fixture
    ) {
        let tdw_id = TrustDidWebId::try_from((tdw_mock.get_did(), Some(false))).unwrap();

        // As any client (since EIDSYS-262) would/should do (after parsing DID to extract url)...
        let did_log_raw = http_client.read(tdw_id.get_url());

        // The (new) interface (since EIDSYS-262).
        let tdw = TrustDidWeb::read(tdw_id.get_scid(), did_log_raw);
        let did_doc = DidDoc::from_json(&tdw.get_did_doc());

        assert_eq!(did_doc.id, tdw.get_did());
        assert!(!did_doc.verification_method.is_empty());
        assert!(!did_doc.authentication.is_empty());
        assert!(!did_doc.controller.is_empty());
    }

    #[rstest]
    fn test_key_creation(ed25519_key_pair: &Ed25519KeyPair // fixture
    ) {
        let original_private = ed25519_key_pair.get_signing_key();
        let original_public = ed25519_key_pair.get_verifying_key();

        let new_private = Ed25519SigningKey::from_multibase(&original_private.to_multibase());
        let new_public = Ed25519VerifyingKey::from_multibase(&original_public.to_multibase());

        assert_eq!(original_private.to_multibase(), new_private.to_multibase());
        assert_eq!(original_public.to_multibase(), new_public.to_multibase());
    }

    #[rstest]
    fn test_create_did(tdw_mock: TdwMock, // fixture
                       ed25519_key_pair: &Ed25519KeyPair, // fixture
    ) {
        let url = tdw_mock.get_url();

        let tdw = TrustDidWeb::create(url, &ed25519_key_pair, Some(false));
        assert!(tdw.get_did().len() > 0);
        assert!(tdw.get_did().starts_with("did:tdw:"))
    }

    #[rstest]
    fn test_read_did_tdw(tdw_mock: TdwMock, // fixture
                         http_client: &HttpClient, // fixture
    ) {
        let tdw_id = TrustDidWebId::try_from((tdw_mock.get_did(), Some(false))).unwrap();

        // As any client (since EIDSYS-262) would/should do (after parsing DID to extract url)...
        let did_log_raw = http_client.read(tdw_id.get_url());

        // Read the newly did doc
        let did_doc_str_v1 = TrustDidWeb::read(tdw_id.get_scid(), did_log_raw);
        let did_doc_v1: serde_json::Value = serde_json::from_str(&did_doc_str_v1.get_did_doc()).unwrap();

        assert!(!did_doc_v1["@context"].to_string().is_empty());
        match did_doc_v1["id"] {
            serde_json::Value::String(ref doc_v1) => {
                assert!(doc_v1.eq(tdw_mock.get_did().as_str()))
            }
            _ => panic!("Invalid did doc"),
        }
        assert!(!did_doc_v1["verificationMethod"].to_string().is_empty());
        assert!(!did_doc_v1["authentication"].to_string().is_empty());
        assert!(!did_doc_v1["controller"].to_string().is_empty());
    }

    #[rstest]
    fn test_update_did_tdw(tdw_mock: TdwMock, // fixture
                           ed25519_key_pair: &Ed25519KeyPair, // fixture
                           http_client: &HttpClient, // fixture
    ) {
        let did = tdw_mock.get_did();
        let mut server = tdw_mock.get_server();

        let tdw_id = TrustDidWebId::try_from((did.to_owned(), Some(false))).unwrap();

        // As any client (since EIDSYS-262) would/should do (after parsing DID to extract url)...
        let mut did_log = http_client.read(tdw_id.get_url());

        // Read original did doc
        let tdw_v1 = TrustDidWeb::read(tdw_id.get_scid(), did_log.clone());
        let did_doc_v1: Value = serde_json::from_str(&tdw_v1.get_did_doc()).unwrap();

        // Update did document by adding a new verification method
        let mut did_doc_v2: Value = did_doc_v1.clone();
        let verification_method: VerificationMethod = VerificationMethod {
            id: String::from("did:jwk:123#type1"),
            controller: String::from("did:jwk:123"),
            verification_type: String::from("TestKey"),
            public_key_multibase: Some(String::from("SomeKey")),
            public_key_jwk: None,
        };
        did_doc_v2["assertionMethod"] = json!(vec![serde_json::to_value(&verification_method).unwrap()]);
        let did_doc_v2 = did_doc_v2.to_string();

        // use updated DID log (as json body) to setup the GET mock
        let scid = tdw_id.get_scid();

        //let did_log_str_v1 = TrustDidWeb::read(scid, tdw.get_did_log()).get_did_log();
        let did_log_str_v1 = did_log.clone();
        let updated = TrustDidWeb::update(did, did_log_str_v1, did_doc_v2.clone(), &ed25519_key_pair, Some(false));
        let updated_did_log_json = json!(updated.get_did_log());
        server.mock("GET", Matcher::Regex(r"/[a-z0-9=]+/did.jsonl$".to_string())).with_body(updated_did_log_json.to_string()).create();

        // As any client (since EIDSYS-262) would/should do (after parsing DID to extract url)...
        did_log = http_client.read(tdw_id.get_url());

        // Read updated did doc with new property
        let tdw_v3 = TrustDidWeb::read(scid, did_log);
        let did_doc_v3: serde_json::Value = serde_json::from_str(&tdw_v3.get_did_doc()).unwrap();
        match did_doc_v3["assertionMethod"][0]["id"] {
            serde_json::Value::String(ref s) => assert!(s.eq("did:jwk:123#type1")),
            _ => panic!("Invalid did doc"),
        };
    }

    #[rstest]
    #[should_panic(
        expected = "Invalid key pair. The provided key pair is not the one referenced in the did doc"
    )]
    fn test_update_did_tdw_with_non_controller_did(tdw_mock: TdwMock, // fixture
                                                   http_client: &HttpClient, // fixture
    ) {
        let did = tdw_mock.get_did();

        let tdw_id = TrustDidWebId::try_from((did.to_owned(), Some(false))).unwrap();

        // As any client (since EIDSYS-262) would/should do (after parsing DID to extract url)...
        let did_log_raw = http_client.read(tdw_id.get_url());

        // Read the newly did doc
        let tdw_v1 = TrustDidWeb::read(tdw_id.get_scid(), did_log_raw);
        let did_doc_v1: serde_json::Value = serde_json::from_str(&tdw_v1.get_did_doc()).unwrap();

        // Update did document by adding a new verification method
        let mut did_doc_v2: serde_json::Value = did_doc_v1.clone();
        let verification_method: VerificationMethod = VerificationMethod {
            id: String::from("did:jwk:123#type1"),
            controller: String::from("did:jwk:123"),
            verification_type: String::from("TestKey"),
            public_key_multibase: Some(String::from("SomeKey")),
            public_key_jwk: None,
        };
        did_doc_v2["assertionMethod"] = json!(vec![serde_json::to_value(&verification_method).unwrap()]);
        let did_doc_v2 = did_doc_v2.to_string();

        // Now, try using a whole another (and therefore invalid) key to update the DID
        let unauthorized_key_pair = Ed25519KeyPair::generate();
        TrustDidWeb::update(did, tdw_v1.get_did_log(), did_doc_v2, &unauthorized_key_pair, Some(false));
    }

    #[rstest]
    #[should_panic(
        expected = "Invalid did doc. The did doc is already deactivated. For simplicity reasons we don't allow updates of dids"
    )]
    fn test_deactivate_did_tdw(tdw_mock: TdwMock, // fixture
                               ed25519_key_pair: &Ed25519KeyPair, // fixture
                               http_client: &HttpClient, // fixture
    ) {
        let did = tdw_mock.get_did();
        let mut server = tdw_mock.get_server();

        let tdw_id = TrustDidWebId::try_from((did.to_owned(), Some(false))).unwrap();

        // As any client (since EIDSYS-262) would/should do (after parsing DID to extract url)...
        let did_log = http_client.read(tdw_id.get_url());

        // Deactivate DID and use its log (as json body) to setup the GET mock
        let deactivated = TrustDidWeb::deactivate(did.to_owned(), did_log.clone(), ed25519_key_pair, Some(false));
        let deactivated_did_log_json = json!(deactivated.get_did_log());
        server.mock("GET", Matcher::Regex(r"/[a-z0-9=]+/did.jsonl$".to_string())).with_body(deactivated_did_log_json.to_string()).create();

        // As any client (since EIDSYS-262) would/should do (after parsing DID to extract url)...
        let did_log = http_client.read(tdw_id.get_url());

        // Read original did doc, and then try to update it...
        let tdw_v1 = TrustDidWeb::read(tdw_id.get_scid(), did_log);
        let did_doc_v1: serde_json::Value = serde_json::from_str(&tdw_v1.get_did_doc()).unwrap();

        // Update did document after it has been deactivated
        let mut did_doc_v2: serde_json::Value = did_doc_v1.clone();
        let verification_method: VerificationMethod = VerificationMethod {
            id: String::from("did:jwk:123#type1"),
            controller: String::from("did:jwk:123"),
            verification_type: String::from("TestKey"),
            public_key_multibase: Some(String::from("SomeKey")),
            public_key_jwk: None,
        };
        did_doc_v2["assertionMethod"] = json!(vec![serde_json::to_value(&verification_method).unwrap()]);

        let did_doc_v2 = did_doc_v2.to_string();
        TrustDidWeb::update(did, tdw_v1.get_did_log(), did_doc_v2, ed25519_key_pair, Some(false));
    }
}