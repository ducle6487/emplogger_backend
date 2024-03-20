pub mod profiles;
pub mod users;
pub mod otp;

use axum::{routing::get, Router};
use users::router::UsersRouter;

use crate::config::AppContext;

use profiles::router::ProfilesRouter;

use self::otp::router::OTPRouter;

pub struct AppRouter;

impl AppRouter {
    pub fn new() -> Router<AppContext> {
        Router::new()
            .route("/", get(hello))
            .nest("/api", UsersRouter::new())
            .nest("/api", ProfilesRouter::new())
            .nest("/api", OTPRouter::new())
    }
}

async fn hello() -> &'static str {
    "Hello world!"
}
