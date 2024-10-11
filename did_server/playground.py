from bindings.python import didtoolbox as toolbox

if __name__ == "__main__":
    # # Create did tdw on localhost:8000 domain
    processor = toolbox.TrustDidWebProcessor.new_with_api_key("secret")
    key_pair = toolbox.Ed25519KeyPair.generate()
    did = processor.create("https://localhost:8000/123456789", key_pair, False)

    # # Resolve did doc from did tdw
    did_log_raw = processor.read(did_tdw=did, allow_http=False)