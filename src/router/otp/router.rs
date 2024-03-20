use axum::{
    routing::post,
    Router,
};

use crate::{config::AppContext, domain::otp::service::OTPService};

pub struct OTPRouter;

impl OTPRouter {
    pub fn new() -> Router<AppContext> {
        Router::new()
            .route("/otp/request/:email", post(OTPService::request_otp))
            .route("/otp/verify/:otp", post(OTPService::verify_otp))
    }
}