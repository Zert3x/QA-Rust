use crate::packet::{
    AuthData, AuthResponse, HeartBeat, Login, PacketType, Redeem, Register, SessionData, Var,
};
use crate::SERVER_LIST;
use chrono::Utc;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use std::fmt;
use std::fmt::Formatter;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use crate::utils::get_id;
use std::collections::HashMap;
use std::process::exit;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openssl::symm::{Cipher, Crypter, Mode};

#[derive(Clone, Debug)]
pub struct AuthServerError;
impl fmt::Display for AuthServerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "licensing server failed to respond")
    }
}

#[derive(Clone, Debug)]
pub struct AuthLoginError;

impl fmt::Display for AuthLoginError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "authentication failed, incorrect username or password")
    }
}

#[derive(Debug)]
pub struct Client {
    session_id: String,
    session_salt: String,
    program_key: String,
    variable_key: String,
    version: String,
    username: Arc<Mutex<String>>,
    password: Arc<Mutex<String>>,
    days: Arc<Mutex<u64>>,
    server: String,
    stream: TcpStream,
}

impl Client {
    pub fn get_version(&self) -> String {
        self.version.clone()
    }

    pub fn get_username(&self) -> String {
        self.username.lock().expect("u_lock").clone()
    }

    pub fn get_days(&self) -> u64 {
        *self.days.lock().expect("d_lock")
    }

    pub fn new(p_key: String, v_key: String, version: String) -> Result<Client, AuthServerError> {
        for server in SERVER_LIST {
            let sock_addr = SocketAddr::from_str(format!("{}:7005", server).as_str())
                .ok()
                .ok_or(AuthServerError)?;
            let stream = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(3))
                .ok()
                .ok_or(AuthServerError)?;

            let rng = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect::<String>();
            let rng2 = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect::<String>();

            return Ok(Client {
                session_id: rng,
                session_salt: rng2,
                program_key: p_key,
                variable_key: v_key,
                version,
                username: Arc::new(Mutex::from(String::from(""))),
                password: Arc::new(Mutex::from(String::from(""))),
                days: Arc::new(Mutex::new(0)),
                server: server.to_string(),
                stream,
            });
        }
        Err(AuthServerError)
    }

    pub fn start_heartbeat_thread(&self) {
        let session_id = self.session_id.clone();
        let session_salt = self.session_salt.clone();
        let program_key = self.program_key.clone();
        let variable_key = self.variable_key.clone();
        let version = self.version.clone();

        let username = self.username.lock().unwrap().to_string();
        let password = self.password.lock().unwrap().to_string();

        let stream = self.stream.try_clone().unwrap();
        let hwid = get_id();
        std::thread::spawn(move || {
            Self::heartbeat_thread(
                stream,
                session_id,
                session_salt,
                program_key,
                variable_key,
                username,
                password,
                hwid,
                version,
            )
        });
    }

    fn heartbeat_thread(
        mut stream: TcpStream,
        session_id: String,
        session_salt: String,
        program_key: String,
        variable_key: String,
        username: String,
        password: String,
        hwid: String,
        version: String,
    ) {
        loop {
            let x = Self::communicate(
                stream.try_clone().unwrap(),
                PacketType::Heartbeat,
                serde_json::to_string(&Self::generate_heartbeat(
                    session_id.clone(),
                    session_salt.clone(),
                    program_key.clone(),
                    variable_key.clone(),
                    username.clone(),
                    password.clone(),
                    hwid.clone(),
                    version.clone(),
                ))
                .unwrap(),
            );

            if !x.status.eq("success") {
                /*if let Some(sock_addr) = SocketAddr::from_str(format!("{}:7005", SERVER_LIST.first().unwrap()).as_str())
                    .ok() {
                    if let Ok(s) = TcpStream::connect(&sock_addr) {
                        stream = s;
                        continue;
                    }
                }*/
                println!("Suspicious activity detected.");
                exit(0);
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    fn generate_heartbeat(
        session_id: String,
        session_salt: String,
        program_key: String,
        variable_key: String,
        username: String,
        password: String,
        hwid: String,
        version: String,
    ) -> HeartBeat {
        let cur = Utc::now();
        HeartBeat {
            sd: SessionData {
                session_id,
                session_salt,
            },
            ad: AuthData {
                program_key,
                variable_key,
                username,
                password,
                hwid,
                version,
                timestamp: cur.format("%Y-%m-%dT%H:%M:%S+00:00").to_string(),
            },
        }
    }

    fn communicate(
        mut stream: TcpStream,
        packet_type: PacketType,
        packet_str: String,
    ) -> AuthResponse {
        let mut p_buf = Vec::from(packet_str.as_bytes());
        let mut buf: Vec<u8> = vec![packet_type as u8];
        buf.append(&mut p_buf);
        buf.push(b'\n');
        let write_res = stream.write_all(buf.as_slice());
        if write_res.is_err() {
            return AuthResponse::default();
        }
        let mut recv_buf = vec![];
        loop {
            let mut buf: [u8; 8192] = [0; 8192];
            match stream.read(&mut buf) {
                Ok(n) => {
                    recv_buf.extend_from_slice(&buf);
                    if buf.contains(&('\n' as u8)) {
                        break;
                    }
                }
                Err(_) => {}
            }
        }

        if !(PacketType::Response as u8).eq(&recv_buf[0]) {
            return AuthResponse::default();
        }
        recv_buf.remove(0);
        if let Ok(msg) = std::str::from_utf8(recv_buf.as_slice()) {
            let m = msg.replace(char::from(0), "");
            let m = m.trim_end_matches('\n');

            match serde_json::from_str::<AuthResponse>(m) {
                Ok(response) => {
                    return response;
                }
                Err(_) => {}
            }
        }

        Default::default()
    }

    fn generate_auth_data(&self) -> AuthData {
        let cur = Utc::now();
        AuthData {
            program_key: self.program_key.clone(),
            variable_key: self.variable_key.clone(),
            username: self.username.lock().expect("u_lock").clone(),
            password: self.password.lock().expect("p_lock").clone(),
            hwid: crate::utils::get_id(),
            version: self.version.clone(),
            timestamp: cur.format("%Y-%m-%dT%H:%M:%S+00:00").to_string(),
        }
    }

    pub fn login(&self, username: String, password: String) -> AuthResponse {
        *self.username.lock().expect("u_lock") = username;
        *self.password.lock().expect("p_lock") = password;

        let packet = Login {
            sd: SessionData {
                session_id: self.session_id.clone(),
                session_salt: self.session_salt.clone(),
            },
            ad: self.generate_auth_data(),
        };

        let resp = Self::communicate(
            self.stream.try_clone().unwrap(),
            PacketType::Authenticate,
            serde_json::to_string(&packet).expect("poorly formed"),
        );
        *self.days.lock().expect("d_lock") =
            resp.expiry.signed_duration_since(Utc::now()).num_days() as u64;

        resp
    }

    pub fn register(
        &self,
        username: String,
        password: String,
        email: String,
        token: String,
    ) -> AuthResponse {
        *self.username.lock().expect("u_lock") = username;
        *self.password.lock().expect("p_lock") = password;

        let packet = Register {
            sd: SessionData {
                session_id: self.session_id.clone(),
                session_salt: self.session_salt.clone(),
            },
            ad: self.generate_auth_data(),
            email,
            token,
        };

        Self::communicate(
            self.stream.try_clone().unwrap(),
            PacketType::Register,
            serde_json::to_string(&packet).expect("poorly formed"),
        )
    }

    pub fn redeem(&mut self, username: String, password: String, token: String) -> AuthResponse {
        *self.username.lock().expect("u_lock") = username;
        *self.password.lock().expect("p_lock") = password;

        let packet = Redeem {
            sd: SessionData {
                session_id: self.session_id.clone(),
                session_salt: self.session_salt.clone(),
            },
            ad: self.generate_auth_data(),
            token,
        };

        Self::communicate(
            self.stream.try_clone().unwrap(),
            PacketType::Redeem,
            serde_json::to_string(&packet).expect("poorly formed"),
        )
    }

    pub fn variable(&self, name: &str) -> String {
        let packet = Var {
            sd: SessionData {
                session_id: self.session_id.to_string(),
                session_salt: self.session_salt.to_string(),
            },
            ad: self.generate_auth_data(),
            name: name.to_string(),
        };

        let resp = Self::communicate(
            self.stream.try_clone().unwrap(),
            PacketType::Variable,
            serde_json::to_string(&packet).expect("poorly formed"),
        );
        let data = base64::decode(resp.data.unwrap()).unwrap();

        let iv = &data[..16];
        let data = &data[16..];
        let t = Cipher::aes_256_cbc();
        let mut d = Crypter::new(t, Mode::Decrypt, self.variable_key.as_bytes(), Some(iv))
            .expect("failed to decrypt, possible malicious activity.");
        let mut result = vec![0; data.len() + t.block_size()];
        let mut len = d.update(data, &mut result).unwrap();
        len += d.finalize(&mut result[len..]).unwrap();
        result.truncate(len);

        result
            .into_iter()
            .map(|x| x as char)
            .collect::<String>()
            .replace("}]}]", "}]")
    }

    pub fn all_variables(&mut self) -> HashMap<String, String> {
        let packet = Var {
            sd: SessionData {
                session_id: self.session_id.to_string(),
                session_salt: self.session_salt.to_string(),
            },
            ad: self.generate_auth_data(),
            name: "all".to_string(),
        };

        let resp = Self::communicate(
            self.stream.try_clone().unwrap(),
            PacketType::Variable,
            serde_json::to_string(&packet).expect("poorly formed"),
        );
        let mut map = HashMap::new();
        for (x, y) in resp.arr_data.unwrap() {
            let data = base64::decode(y).unwrap();

            let iv = &data[..16];
            let data = &data[16..];

            let t = Cipher::aes_256_cbc();
            let mut d = Crypter::new(t, Mode::Decrypt, self.variable_key.as_bytes(), Some(iv))
                .expect("failed to decrypt, possible malicious activity.");
            let mut result = vec![0; data.len() + t.block_size()];
            let mut len = d.update(data, &mut result).unwrap();
            len += d.finalize(&mut result[len..]).unwrap();
            result.truncate(len);
            drop(d);

            map.insert(x, result.into_iter().map(|x| x as char).collect::<String>());
        }

        map
    }
}
