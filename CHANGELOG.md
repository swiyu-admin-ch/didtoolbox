# DID toolbox changelog

| Version | Description                                                                                                                                                                                               |
|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1.0.0   | **IMPROVEMENT/FIX** Cleanup. Fixed interop issue. Final attempt to ensure conformity with [Trust DID Web - did:tdw - v0.3](https://identity.foundation/trustdidweb/v0.3/)                                 |
| 0.0.5   | **IMPROVEMENT/FIX** Ensured conformity with [Trust DID Web - did:tdw - v0.3](https://identity.foundation/trustdidweb/v0.3/)                                                                               |
| 0.0.4   | **FEATURE** Non-empty constructor added for `TrustDidWeb`. Code formatted using `rustfmt`                                                                                                                 |
| 0.0.3   | **BREAKING CHANGE** `TrustDidWebProcessor` discontinued. <br/>Signature of the `read` method now also requires a DID log (as string).<br/> All `TrustDidWeb` methods may now throw new `TrustDidWebError` |

