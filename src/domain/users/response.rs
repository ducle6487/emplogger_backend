use serde::{Deserialize, Serialize};
use prisma_client_rust::chrono::{FixedOffset, TimeZone};

use crate::prisma::user;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: i32,
    pub email: Option<String>,
    pub username: String,
    pub bio: Option<String>,
    pub image: Option<String>,
    pub verified: bool,
    pub created_at:
        ::prisma_client_rust::chrono::DateTime<FixedOffset>,
    pub updated_at:
        ::prisma_client_rust::chrono::DateTime<FixedOffset>,

    pub token: Option<String>,
}

impl User {
    pub fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }
}

impl From<user::Data> for User {
    fn from(data: user::Data) -> Self {
        Self {
            id: data.id,
            email: data.email,
            username: data.username,
            bio: data.bio,
            image: data.image,
            verified: data.verified,
            created_at: data.created_at,
            updated_at: data.updated_at,
            token: None,
        }
    }
}
