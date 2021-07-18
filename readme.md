# QA-RustClient
This is the Rust implementation of the client for the [QuartzAuth](https://auth.quartzinc.space) API.

Note, this likely has a lot of non-idiomatic code, as this was originally written when I had begun learning rust.  This will change in the future when I have time.

Pull requests are welcome for any bugs you may find!

If you have any questions, please join our [discord server](https://discord.gg/hgGUdk8efF)

## Example
```rust
use qauth::client::Client;

fn main() {
    let client = Client::new(
        String::from("ProgramKey"),
        String::from("VariableKey"),
        String::from("0.0.1"),
    );
    let client = client.unwrap();

    let resp = client.login(String::from("username"), String::from("password"));
}
```