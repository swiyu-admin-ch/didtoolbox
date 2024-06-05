from bindings.python import trustdidweb as tdw

if __name__ == "__main__":
    # Create did tdw on localhost:8000 domain
    processor = tdw.TrustDidWebProcessor.new_with_api_key("secret")
    key_pair = tdw.Ed25519KeyPair.generate()
    did = processor.create("https://localhost:8000", key_pair)
    
    # Resolve did doc from did tdw
    did_doc = processor.read(did_tdw=did)
    print(did_doc)