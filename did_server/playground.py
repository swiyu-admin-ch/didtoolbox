from bindings.python import didtoolbox as toolbox
#import requests as req
import json

if __name__ == "__main__":
    # # Create did tdw on localhost:8000 domain
    try:
        key_pair = toolbox.Ed25519KeyPair.generate()
        created = toolbox.TrustDidWeb.create("https://127.0.0.1/8000", key_pair, False)
        did_log = json.dumps(json.loads(created.get_did_log())) # Is it a proper JSON?
        #print(did_log)
        #did_doc_json = json.loads(created.get_did_doc())
        #print(str(did_doc_json["verificationMethod"][0]))

        did = created.get_did()
        #tdw = toolbox.TrustDidWeb.new_from_did("did:xyz::127.0.0.1%3A8000:12345678", False) # "DID method `xyz` not supported"
        #tdw = toolbox.TrustDidWeb.new_from_did("did:tdw:============:127.0.0.1%3A8000:12345678", False) # "invalid method specific identifier: did:tdw:============:127.0.0.1%3A8000:12345678"
        tdw = toolbox.TrustDidWeb.new_from_did(did, False)
        scid = tdw.get_scid()

        #did_log_raw = toolbox.TrustDidWeb.read(scid, "") # "Invalid did log. No entries found"
        read = toolbox.TrustDidWeb.read(scid, did_log)
        did_log_v1 = read.get_did_log()
        #print(did_log)
        did_doc_v1 = read.get_did_doc()
        deactivate = toolbox.TrustDidWeb.deactivate(did, did_log, key_pair, False)
        did_log = deactivate.get_did_log()
        #print(did_log)
        #deactivate = toolbox.TrustDidWeb.deactivate(did, did_log, key_pair, False) # Invalid did doc. The did doc is already deactivated. For simplicity reasons we don't allow updates of dids
        #update = toolbox.TrustDidWeb.update(scid, did, did_log_v1, did_doc_v1, key_pair, False)
        #did_log = update.get_did_log()
        print(did_log)

    except Exception as e:
        # e.g. "Unexpected e = InternalError('DID method `xyz` not supported'), type(e) = <class 'bindings.python.didtoolbox.InternalError'>"
        print(f"Unexpected {e = }, {type(e) = }")
