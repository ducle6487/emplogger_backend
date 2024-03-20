use serde::Deserialize;

#[derive(Debug, Deserialize)]

pub struct OTPRequestInput {
    pub email: String
}