#![crate_type = "lib"]
#![crate_name = "qauth"]

extern crate serde_json;

extern crate itertools;

extern crate openssl;

pub mod client;
mod packet;
mod utils;

#[cfg(test)]
mod tests {
    use crate::client::Client;

    #[test]
    fn connect_to_uplink() {
        let client = Client::new(
            String::from("1WFtHGbhfuBfoobarJLeNJgKtxOULdhtliz7BLG4dGVhZf9dINZQmk1JoXjUxCj1"),
            String::from("n0qy2cZyLtF3bHNOqiNaslm4mvGpWQcC"),
            String::from("0.0.1"),
        );
        assert!(client.is_ok(), "{}", true);
    }

    #[test]
    fn authenticate() {
        let client = Client::new(
            String::from("1WFtHGbhfuBUI3barfooNJgKtxOULdhtliz7BLG4dGVhZf9dINZQmk1JoXjUxCj1"),
            String::from("jl9BxW6jJ5jIUBjXbZAFQZGW8xhIqvx4"),
            String::from("0.0.1"),
        );
        assert!(client.is_ok(), "{}", true);
        let client = client.unwrap();

        let resp = client.login(String::from("user"), String::from("password"));
        assert!(resp.status.eq("success"), "{:?}", resp);
    }

    #[test]
    fn variable() {
        let client = Client::new(
            String::from("1WFtHGbhfuBUI3barJLeNJgKfooULdhtliz7BLG4dGVhZf9dINZQmk1JoXjUxCj1"),
            String::from("jl9BxW6jJ5jIUBjXbZAFQZGW8xhIqvx4"),
            String::from("0.0.1"),
        );
        assert!(client.is_ok(), "{}", true);
        let client = client.unwrap();

        let _resp = client.login(String::from("user"), String::from("password"));
        assert!(_resp.status.eq("success"), "{}", true);

        let var = client.variable("test");
        assert!(var.eq("test"), "{}", true)
    }

    #[test]
    fn all_variables() {
        let client = Client::new(
            String::from("1WFtHGbhfuBUI3barJLeNJgKtxfoodhtliz7BLG4dGVhZf9dINZQmk1JoXjUxCj1"),
            String::from("jl9BxW6jJ5jIUBjXbZAFQZGW8xhIqvx4"),
            String::from("0.0.1"),
        );
        assert!(client.is_ok(), "{}", true);
        let mut client = client.unwrap();

        let _resp = client.login(String::from("user"), String::from("password"));

        let var = client.all_variables();
        assert!(var.get("test").unwrap().eq("test"), "{}", true);
        assert!(var.get("test1").unwrap().eq("testing"), "{}", true);
    }

    #[test]
    fn vpn_test(){
        use std::time::Duration;
        let client = Client::new(
            "Ol8Y17q7MNe5HPWUhKy0wIhLsuNGtabtazVXpfq37vrmYoY3dDjUTvOyAEHKG47K".into(),
            "OLhoem4vyvTKFzk4EIiXcMRWZ8Fr5RkK".into(),
            "1.0".into()
        ).unwrap();
        let _resp = client.login("test".into(), "test".into());
        //Sleep 2 minutes to connect a VPN and check for crashes
        std::thread::sleep(Duration::from_secs(120));
    }
}

static SERVER_LIST: [&str; 9] = [
    "135.181.165.139",
    "95.216.255.232",
    "95.216.255.233",
    "95.216.255.234",
    "95.216.255.235",
    "95.216.255.236",
    "95.216.255.237",
    "95.216.255.238",
    "95.216.255.239",
];
