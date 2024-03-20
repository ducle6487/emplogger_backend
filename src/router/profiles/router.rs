use axum::{
    routing::{delete, get, post},
    Router,
};

use crate::{config::AppContext, domain::profiles::service::ProfilesService};

pub struct ProfilesRouter;

impl ProfilesRouter {
    pub fn new() -> Router<AppContext> {
        Router::new()
            .route("/profiles/:username", get(ProfilesService::get_profile))
    }
}
