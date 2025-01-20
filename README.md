![Public Beta banner](https://github.com/e-id-admin/eidch-public-beta/blob/main/assets/github-banner-publicbeta.jpg)

# DID toolbox

An official Swiss Government project made by
the [Federal Office of Information Technology, Systems and Telecommunication FOITT](https://www.bit.admin.ch/)
as part of the electronic identity (e-ID) project.

**⚠️ PARTLY OUTDATED ⚠️**

*Users must not use this library to create new DIDs, as they won't be compatible.*

This project has been superseded by [DID Toolbox](https://github.com/e-id-admin/didtoolbox-java). Parts of this library are still required by [DID Resolver](https://github.com/e-id-admin/didresolver). This library will vanish in the near future, and the required parts will be relocated to Resolver.

## Using the library

The library can be used either directly in rust as is.

### Rust

The library can be used directly in rust by adding the following dependency to your `Cargo.toml`:

````toml
[dependencies]
didtoolbox = { git = "https://github.com/e-id-admin/didtoolbox", branch = "main" }

# Optional: For manipulating the json content in the example
serde_json = "1.0.133"
````

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](LICENSE.md) file for details.
