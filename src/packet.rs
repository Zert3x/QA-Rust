
use chrono::{DateTime, FixedOffset, Utc};
use serde::{de, Deserialize, Deserializer};
use std::collections::HashMap;
use std::fmt::Display;
use std::str::FromStr;
use num_derive::FromPrimitive;

#[derive(Copy, Clone, Eq, PartialEq, FromPrimitive)]
pub enum PacketType {
    Heartbeat = 0x00,
    Authenticate = 0x01,
    Register = 0x02,
    Redeem = 0x03,
    Variable = 0x04,
    Status = 0x05,

    Response = 0xF0,

    Terminate = 0x99,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SessionData {
    pub(crate) session_id: String,
    pub(crate) session_salt: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct AuthData {
    pub(crate) program_key: String,
    pub(crate) variable_key: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) hwid: String,
    pub(crate) version: String,
    pub(crate) timestamp: String,
}

#[derive(serde::Serialize, Clone)]
pub struct HeartBeat {
    #[serde(flatten)]
    pub(crate) sd: SessionData,
    #[serde(flatten)]
    pub(crate) ad: AuthData,
}

#[derive(serde::Deserialize, Clone, Debug, PartialEq)]
pub struct AuthResponse {
    pub status: String,
    pub message: String,
    pub data: Option<String>,
    pub arr_data: Option<HashMap<String, String>>,
    #[serde(deserialize_with = "deserialize_from_str")]
    pub expiry: DateTime<FixedOffset>,
}

impl AuthResponse{
    pub fn is_default(&self) -> bool{
        Self::default().eq(self)
    }
}

impl Default for AuthResponse {
    fn default() -> Self {
        Self {
            status: "".to_string(),
            message: "".to_string(),
            data: None,
            arr_data: None,
            expiry: DateTime::from(Utc::now()),
        }
    }
}

fn deserialize_from_str<'de, S, D>(deserializer: D) -> Result<S, D::Error>
where
    S: FromStr,      // Required for S::from_str...
    S::Err: Display, // Required for .map_err(de::Error::custom)
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    S::from_str(&s).map_err(de::Error::custom)
}

#[derive(serde::Serialize, Clone)]
pub struct Login {
    #[serde(flatten)]
    pub(crate) sd: SessionData,
    #[serde(flatten)]
    pub(crate) ad: AuthData,
}

#[derive(serde::Serialize, Clone)]
pub struct Register {
    #[serde(flatten)]
    pub(crate) sd: SessionData,
    #[serde(flatten)]
    pub(crate) ad: AuthData,
    pub(crate) email: String,
    pub(crate) token: String,
}

#[derive(serde::Serialize, Clone)]
pub struct Redeem {
    #[serde(flatten)]
    pub(crate) sd: SessionData,
    #[serde(flatten)]
    pub(crate) ad: AuthData,
    pub(crate) token: String,
}

#[derive(serde::Serialize, Clone)]
pub struct Var {
    #[serde(flatten)]
    pub(crate) sd: SessionData,
    #[serde(flatten)]
    pub(crate) ad: AuthData,
    pub(crate) name: String,
}
