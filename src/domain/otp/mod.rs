use serde::{Deserialize, Serialize};

pub mod response;
pub mod request;
pub mod service;

#[derive(Debug, Serialize, Deserialize)]
pub struct OTPBody<T> {
    pub otp: T,
}