#[derive(Debug, Clone)]
pub struct SMTPConfig {
    pub name: String,
    pub email: String,
    pub password: String,
    pub server: String,
    pub port: u16,
}