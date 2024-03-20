use axum::{extract::Path, Extension, Json};
use std::sync::Arc;

use crate::{
    app_error::AppError,
    extractor::{AuthUser, OptionalAuthUser},
    prisma::{user, PrismaClient},
};

use super::{response::Profile, ProfileBody};

type Prisma = Extension<Arc<PrismaClient>>;

pub struct ProfilesService;

impl ProfilesService {
    pub async fn get_profile(
        Path(username): Path<String>,
        auth_user: OptionalAuthUser,
        prisma: Prisma,
    ) -> Result<Json<ProfileBody<Profile>>, AppError> {
        let user = prisma
            .user()
            .find_unique(user::username::equals(username))
            .exec()
            .await?
            .ok_or(AppError::NotFound(String::from("User not found")))?;

        Ok(Json::from(ProfileBody {
                profile: user.to_profile(false),
            }))
    }
}
