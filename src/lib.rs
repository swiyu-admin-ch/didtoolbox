// SPDX-License-Identifier: MIT
pub mod did_tdw;
pub mod didtoolbox;
pub mod ed25519;
pub mod utils;
pub mod vc_data_integrity;

use crate::did_tdw::*;
use crate::didtoolbox::*;
use crate::ed25519::*;
use crate::utils::*;
use rand::Rng; // 0.8

uniffi::include_scaffolding!("didtoolbox");

#[cfg(test)]
mod test {
    use super::did_tdw::*;
    use super::didtoolbox::*;
    use super::ed25519::*;
    use super::utils::*;
    use base64::Engine as _;
    use core::panic;
    use hex::ToHex;
    use mockito::{Matcher, Server, ServerOpts};
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    use rstest::{fixture, rstest};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use ssi::json_ld::syntax::BorrowUnordered;
    use std::borrow::Borrow;
    use std::borrow::BorrowMut;
    use std::ops::Index;
    use std::vec;

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
        server: Server, // CAUTION Must be in the struct, otherwise 501 (server) error status is returned
    }
    impl TdwMock {
        pub fn new(
            key_pair: &Ed25519KeyPair, // CAUTION Unfortunately, the 'ed25519_key_pair' fixture cannot be used here ;)
        ) -> Self {
            let mut server = Server::new_with_opts(ServerOpts {
                // CAUTION Setting a port explicitly would lead to "Address already in use (os error 48)" error!
                ..Default::default()
            });

            let url = format!("{}/123456789", server.url());

            // CAUTION Using one of the existing SUT methods (TrustDidWeb::create(...)) to setup a mock is NOT really deterministic!
            //         Alternatively, a raw test data should/could be loaded directly from the FS, e.g.:
            //         let did_log = minify::json::minify(std::fs::read_to_string(std::Path::new(&did_log_raw_filepath)).unwrap().as_str());
            //         However, in this particular setup, as port is always different (not explicitly set),
            //         it is impossible to create such a JSON content.
            //         So, the SUT method (TrustDidWeb::create(...)) should already be implemented "properly" 🤠
            let tdw = TrustDidWeb::create(url.to_owned(), key_pair, Some(false)).unwrap();
            let did_log = tdw.get_did_log();

            // use newly created did_log (as json body) to setup the GET mock
            server
                .mock("GET", Matcher::Regex(r"/[a-z0-9=]+/did.jsonl$".to_string()))
                .with_body(did_log)
                .with_header("X-API-Key", "secret")
                .create();

            // Smoke test
            //let http_client = HttpClient { api_key: Some("secret".to_string()) };
            let http_client = HttpClient { api_key: None }; // works as well, for some reason
            let did_log = http_client.read(format!("{}/did.jsonl", url.to_owned())); // may panic
            //println!("{did_log}");

            TdwMock {
                url,
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
    #[case(
        "did:tdw:myScid:localhost%3A8000:123:456",
        "http://localhost:8000/123/456/did.jsonl"
    )]
    #[case("did:tdw:myScid:localhost%3A8000", "http://localhost:8000/did.jsonl")]
    #[case("did:tdw:myScid:localhost", "http://localhost/.well-known/did.jsonl")]
    #[case(
        "did:tdw:myScid:admin.ch%3A8000:123:456",
        "http://admin.ch:8000/123/456/did.jsonl"
    )]
    #[case("did:tdw:myScid:admin.ch%3A8000", "http://admin.ch:8000/did.jsonl")]
    #[case("did:tdw:myScid:admin.ch", "http://admin.ch/.well-known/did.jsonl")]
    #[case(
        "did:tdw:myScid:sub.admin.ch",
        "http://sub.admin.ch/.well-known/did.jsonl"
    )]
    #[case(
        "did:tdw:myScid:sub.admin.ch:mypath:mytrala",
        "http://sub.admin.ch/mypath/mytrala/did.jsonl"
    )]
    fn test_tdw_to_url_conversion(#[case] tdw: String, #[case] url: String) {
        let tdw = TrustDidWebId::parse_did_tdw(tdw, Some(true)).unwrap();
        let resolved_url = tdw.get_url();
        assert_eq!(resolved_url, url)
    }

    #[rstest]
    #[case("did:xyz:myScid:localhost%3A8000:123:456")]
    fn test_tdw_to_url_conversion_error_kind_method_not_supported(#[case] tdw: String) {
        match TrustDidWebId::parse_did_tdw(tdw, Some(true)) {
            Err(e) => assert_eq!(
                e.kind(),
                TrustDidWebIdResolutionErrorKind::MethodNotSupported
            ),
            _ => (),
        }
    }

    #[rstest]
    #[case("did:tdw:")]
    fn test_tdw_to_url_conversion_error_kind_invalid_method_specific_id(#[case] tdw: String) {
        match TrustDidWebId::parse_did_tdw(tdw, Some(true)) {
            Err(e) => assert_eq!(
                e.kind(),
                TrustDidWebIdResolutionErrorKind::InvalidMethodSpecificId
            ),
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
        let resolved_domain = get_tdw_domain_from_url(&url, Some(true)).unwrap();
        assert_eq!(domain, resolved_domain)
    }

    #[rstest]
    #[case("not_really_an_http_url")]
    #[case("http://sub.localhost/did.jsonl")]
    fn test_url_to_tdw_domain_error(#[case] url: String) {
        match get_tdw_domain_from_url(&url, Some(true)) {
            Err(e) => assert_eq!(e.kind(), TrustDidWebErrorKind::InvalidMethodSpecificId),
            _ => (),
        }
    }

    #[rstest]
    fn test_generate_scid() {
        let did_doc = DidDoc {
            //context: vec![DID_CONTEXT.to_string(), MKEY_CONTEXT.to_string()],
            context: vec![],
            id: String::from(SCID_PLACEHOLDER),
            verification_method: vec![],
            authentication: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            assertion_method: vec![],
            //controller: vec![format!("did:tdw:{}:{}", SCID_PLACEHOLDER, "domain")],
            controller: vec![],
            deactivated: None,
        };

        let scid = generate_scid(&did_doc);
        //let scid_str = scid.as_str();
        assert_eq!(scid.len(), 94);
        assert_eq!(scid, "z7xbXB9W593YjYbJ7Fwo6mkwVhZrWa4bz1sSvq56zVL9oXoCsCJpmQg6PqHUiB4JU6CW1kQA7QehEE52CFFzpkYSBGVDPH")
    }

    #[rstest]
    #[should_panic(expected = "Invalid did:tdw document. SCID placeholder not found")]
    fn test_generate_scid_panic() {
        let did_doc = DidDoc {
            context: vec![DID_CONTEXT.to_string(), MKEY_CONTEXT.to_string()],
            id: String::from(""),
            verification_method: vec![],
            authentication: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            assertion_method: vec![],
            controller: vec![format!("did:tdw:{}:{}", SCID_PLACEHOLDER, "domain")],
            deactivated: None,
        };

        generate_scid(&did_doc);
    }

    #[rstest]
    fn test_did_wrapping(
        tdw_mock: TdwMock,        // fixture
        http_client: &HttpClient, // fixture
    ) {
        let tdw_id = TrustDidWebId::parse_did_tdw(tdw_mock.get_did(), Some(false)).unwrap();

        // As any client (since EIDSYS-262) would/should do (after parsing DID to extract url)...
        let did_log_raw = http_client.read(tdw_id.get_url());

        // The (new) interface (since EIDSYS-262).
        let tdw = TrustDidWeb::read(tdw_mock.get_did(), did_log_raw, Some(false)).unwrap();
        let did_doc = DidDoc::from_json(&tdw.get_did_doc()); // may panic

        assert_eq!(did_doc.id, tdw.get_did());
        assert!(!did_doc.verification_method.is_empty());
        assert!(!did_doc.authentication.is_empty());
        assert!(!did_doc.controller.is_empty());
    }

    #[rstest]
    fn test_key_creation(ed25519_key_pair: &Ed25519KeyPair, // fixture
    ) {
        let original_private = ed25519_key_pair.get_signing_key();
        let original_public = ed25519_key_pair.get_verifying_key();

        let new_private = Ed25519SigningKey::from_multibase(&original_private.to_multibase());
        let new_public = Ed25519VerifyingKey::from_multibase(&original_public.to_multibase());

        assert_eq!(original_private.to_multibase(), new_private.to_multibase());
        assert_eq!(original_public.to_multibase(), new_public.to_multibase());
    }

    #[rstest]
    fn test_create_did(
        tdw_mock: TdwMock,                 // fixture
        ed25519_key_pair: &Ed25519KeyPair, // fixture
    ) {
        let url = tdw_mock.get_url();

        let tdw = TrustDidWeb::create(url, &ed25519_key_pair, Some(false)).unwrap();
        println!("{}", tdw.get_did_log());
        assert!(tdw.get_did().len() > 0);
        assert!(tdw.get_did().starts_with("did:tdw:"))
    }

    #[rstest]
    fn test_read_did_tdw(
        tdw_mock: TdwMock,        // fixture
        http_client: &HttpClient, // fixture
    ) {
        let did = tdw_mock.get_did();

        let tdw_id = TrustDidWebId::parse_did_tdw(tdw_mock.get_did(), Some(false)).unwrap();

        // As any client (since EIDSYS-262) would/should do (after parsing DID to extract url)...
        let did_log_raw = http_client.read(tdw_id.get_url());

        // Read the newly did doc
        let did_doc_str_v1 = TrustDidWeb::read(did, did_log_raw, Some(false)).unwrap();
        let did_doc_v1: serde_json::Value =
            serde_json::from_str(&did_doc_str_v1.get_did_doc()).unwrap();

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
    fn test_update_did_tdw(
        tdw_mock: TdwMock,                 // fixture
        ed25519_key_pair: &Ed25519KeyPair, // fixture
        http_client: &HttpClient,          // fixture
    ) {
        let did = tdw_mock.get_did();
        let mut server = tdw_mock.get_server();

        let tdw_id = TrustDidWebId::parse_did_tdw(did.to_owned(), Some(false)).unwrap();

        // As any client (since EIDSYS-262) would/should do (after parsing DID to extract url)...
        let mut did_log = http_client.read(tdw_id.get_url());

        // Read original did doc
        let tdw_v1 = TrustDidWeb::read(did.to_owned(), did_log.clone(), Some(false)).unwrap();
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
        did_doc_v2["assertionMethod"] =
            json!(vec![serde_json::to_value(&verification_method).unwrap()]);
        let did_doc_v2 = did_doc_v2.to_string();

        // use updated DID log (as json body) to setup the GET mock
        let scid = tdw_id.get_scid();

        //let did_log_str_v1 = TrustDidWeb::read(scid, tdw.get_did_log()).get_did_log();
        let did_log_str_v1 = did_log.clone();
        let updated = TrustDidWeb::update(
            did.to_owned(),
            did_log_str_v1,
            did_doc_v2.clone(),
            &ed25519_key_pair,
            Some(false),
        )
            .unwrap();
        let updated_did_log_json = json!(updated.get_did_log());
        server
            .mock("GET", Matcher::Regex(r"/[a-z0-9=]+/did.jsonl$".to_string()))
            .with_body(updated_did_log_json.to_string())
            .create();

        // As any client (since EIDSYS-262) would/should do (after parsing DID to extract url)...
        did_log = http_client.read(tdw_id.get_url());

        // Read updated did doc with new property
        let tdw_v3 = TrustDidWeb::read(did, did_log, Some(false)).unwrap();
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
    fn test_update_did_tdw_with_non_controller_did(
        tdw_mock: TdwMock,        // fixture
        http_client: &HttpClient, // fixture
    ) {
        let did = tdw_mock.get_did();

        let tdw_id = TrustDidWebId::parse_did_tdw(did.to_owned(), Some(false)).unwrap();

        // As any client (since EIDSYS-262) would/should do (after parsing DID to extract url)...
        let did_log_raw = http_client.read(tdw_id.get_url());

        // Read the newly did doc
        let tdw_v1 = TrustDidWeb::read(did.to_owned(), did_log_raw, Some(false)).unwrap();
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
        did_doc_v2["assertionMethod"] =
            json!(vec![serde_json::to_value(&verification_method).unwrap()]);
        let did_doc_v2 = did_doc_v2.to_string();

        // Now, try using a whole another (and therefore invalid) key to update the DID
        let unauthorized_key_pair = Ed25519KeyPair::generate();
        TrustDidWeb::update(
            did,
            tdw_v1.get_did_log(),
            did_doc_v2,
            &unauthorized_key_pair,
            Some(false),
        )
            .unwrap();
    }

    #[rstest]
    #[should_panic(
        expected = "Invalid did doc. The did doc is already deactivated. For simplicity reasons we don't allow updates of dids"
    )]
    fn test_deactivate_did_tdw(
        tdw_mock: TdwMock,                 // fixture
        ed25519_key_pair: &Ed25519KeyPair, // fixture
        http_client: &HttpClient,          // fixture
    ) {
        let did = tdw_mock.get_did();
        let mut server = tdw_mock.get_server();

        let tdw_id = TrustDidWebId::parse_did_tdw(did.to_owned(), Some(false)).unwrap();

        // As any client (since EIDSYS-262) would/should do (after parsing DID to extract url)...
        let did_log = http_client.read(tdw_id.get_url());

        // Deactivate DID and use its log (as json body) to setup the GET mock
        let deactivated = TrustDidWeb::deactivate(
            did.to_owned(),
            did_log.clone(),
            ed25519_key_pair,
            Some(false),
        )
            .unwrap();
        let deactivated_did_log_json = json!(deactivated.get_did_log());
        server
            .mock("GET", Matcher::Regex(r"/[a-z0-9=]+/did.jsonl$".to_string()))
            .with_body(deactivated_did_log_json.to_string())
            .create();

        // As any client (since EIDSYS-262) would/should do (after parsing DID to extract url)...
        let did_log = http_client.read(tdw_id.get_url());

        // Read original did doc, and then try to update it...
        let tdw_v1 = TrustDidWeb::read(did.to_owned(), did_log, Some(false)).unwrap();
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
        did_doc_v2["assertionMethod"] =
            json!(vec![serde_json::to_value(&verification_method).unwrap()]);

        let did_doc_v2 = did_doc_v2.to_string();
        TrustDidWeb::update(
            did,
            tdw_v1.get_did_log(),
            did_doc_v2,
            ed25519_key_pair,
            Some(false),
        )
            .unwrap();
    }
}
