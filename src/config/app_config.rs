extern crate dotenv;

use dotenv::dotenv;
use std::env;

use super::{ db::DatabaseConfig, jwt::JwtConfig, otp::OTPConfig, smtp::SMTPConfig };

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub port: u16,
    pub log_level: String,
    pub db: DatabaseConfig,
    pub jwt: JwtConfig,
    pub otp: OTPConfig,
    pub smtp: SMTPConfig,
}

impl AppConfig {
    pub fn init() -> Self {
        Self {
            port: get_env("PORT").parse().unwrap(),
            log_level: std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
            db: DatabaseConfig {
                url: get_env("DATABASE_URL"),
            },
            otp: OTPConfig {
                secret: get_env("OTP_SECRET"),
                exp_in_sec: value_to_seconds(
                    get_env("OTP_EXP_VALUE").parse().unwrap(),
                    get_env("OTP_EXP_UNIT")
                ),
            },
            smtp: SMTPConfig {
                name: get_env("SMTP_NAME"),
                email: get_env("SMTP_EMAIL"),
                password: get_env("SMTP_PASSWORD"),
                server: get_env("SMTP_SERVER"),
                port: get_env("SMTP_PORT").parse().unwrap(),
            },
            jwt: JwtConfig {
                secret: get_env("JWT_SECRET"),
                exp_in_sec: value_to_seconds(
                    get_env("JWT_EXP_VALUE").parse().unwrap(),
                    get_env("JWT_EXP_UNIT")
                ),
            },
        }
    }
}

pub fn get_env(key: &str) -> String {
    dotenv().ok();
    env::var(key).unwrap_or_else(|_| panic!("{} must be set", key))
}

pub fn value_to_seconds(value: i64, unit: String) -> i64 {
    match unit.as_str() {
        "seconds" => value,
        "minutes" => value * 60,
        "hours" => value * 3600,
        "days" => value * 86400,
        "weeks" => value * 604800,
        "months" => value * 2592000,
        "years" => value * 31536000,
        _ => panic!("Invalid unit"),
    }
}
