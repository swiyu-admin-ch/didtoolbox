# trustdidweb

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Before you can use this library, you need to have the following software installed on your machine:

- 🦀 Rust: The library is implemented in Rust, so you need to have the Rust compiler installed. You can download it from the [official Rust website](https://www.rust-lang.org/tools/install).
- 🐍 Python: The Python bindings require Python 3.6 or later. You can download it from the [official Python website](https://www.python.org/downloads/).

### Installation

1. Clone the repository to your local machine:

    ```bash
    git clone git@github.com:admin-ch-ssi/trustdidweb.git
    ```

2. Navigate to the project directory:

    ```bash
    cd trustdidweb
    ```

3. Build the Rust library:

    ```bash
    cargo build --release
    ```

4. Copy the shared object file to the Python bindings directory:

    ```bash
    cp target/release/trustdidweb.so bindings/python/
    ```

5. Now you can import the `cryptosuite` and `bbs` modules in your Python scripts:

    ```python
    from bindings.python import trustdidweb as tdw
    ```