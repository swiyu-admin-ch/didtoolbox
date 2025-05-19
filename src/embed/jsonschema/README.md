# [JSON schemata (Draft 2020-12)](https://json-schema.org/draft/2020-12) for [didwebvh](https://identity.foundation/didwebvh)

[JSON schema (Draft 2020-12)](https://json-schema.org/draft/2020-12) is a declarative language for annotating and validating JSON documents' structure, constraints, and data types.
It helps you standardize and define expectations for JSON data.

This directory features various [JSON schema (Draft 2020-12)](https://json-schema.org/draft/2020-12) designed for the sake of validating [didwebvh](https://identity.foundation/didwebvh) DID logs:

- [v03BitConform](did_log_jsonschema_v_0_3_BIT_conform.json), as defined by both [did:tdw:0.3](https://identity.foundation/didwebvh/v0.3) and (addendum):
  - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Log+Conformity+Check
  - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
- [V03](did_log_jsonschema_v_0_3.json), as (strictly) specified by [did:tdw:0.3](https://identity.foundation/didwebvh/v0.3)


Both these schemata are indeed different, not substantially, though. To explore their differences, feel free to run either:
- [`delta -s *.json`](https://github.com/dandavison/delta) or
- [`difft    *.json`](https://github.com/Wilfred/difftastic)

Furthermore, both these schemata feature several custom, hence non-standard, keywords such as `did-log-entry` and `did-version-time`.