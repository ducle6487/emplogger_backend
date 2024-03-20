#[derive(Debug, Clone)]

pub struct OTPConfig {
    pub secret: String,
    pub exp_in_sec: i64,
}