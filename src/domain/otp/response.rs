use serde::Deserialize;

#[derive(Debug, Deserialize)]

pub struct OTPResponse {
    pub message: String
}