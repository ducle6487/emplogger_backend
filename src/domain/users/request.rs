use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct UserCreateInput {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct UserUpdateInput {
    pub email: Option<String>,
    pub username: Option<String>,
    pub bio: Option<String>,
    pub image: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UserLoginInput {
    pub username: String,
    pub password: String,
}
