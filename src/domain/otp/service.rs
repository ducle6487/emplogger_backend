use axum::{ extract::{ Path, State }, Extension };
use otp_rs::TOTP;
use prisma_client_rust::chrono::{ DateTime, FixedOffset, TimeZone };
use regex::Regex;
use tracing_subscriber::reload::Error;
use std::{ sync::Arc, time::{ SystemTime, UNIX_EPOCH }, u32 };
use lettre::message::{ header as other_header, MultiPart, SinglePart };
use lettre::transport::smtp::authentication::Credentials;
use lettre::{ Message, SmtpTransport, Transport };
use html_to_string_macro::html;
use super::{ request::OTPRequestInput, response::OTPResponse, OTPBody };
use crate::{
    app_error::AppError,
    config::AppContext,
    extractor::AuthUser,
    prisma::{ self, user::{ self, email }, PrismaClient },
};

type Prisma = Extension<Arc<PrismaClient>>;

pub struct OTPService;

impl OTPService {
    pub async fn request_otp(
        Path(email): Path<String>,
        auth_user: AuthUser,
        ctx: State<AppContext>,
        prisma: Prisma
    ) -> Result<String, AppError> {
        let email_input = &email;
        Self::is_valid_email(email_input)?;
        
        let code = Self::generate_otp(email_input, &ctx).await?;
        Self::send_email_otp(email_input, &code, &ctx)?;

        prisma.user().update(user::id::equals(auth_user.user_id), vec![]).exec().await?;

        let response = format!("OTP has been sent to email: {}. code: {}", email, code);
        Ok(response)
    }

    pub async fn verify_otp(
        Path(code): Path<u32>,
        auth_user: AuthUser,
        ctx: State<AppContext>
    ) -> Result<String, AppError> {
        let otp = TOTP::new(&ctx.config.otp.secret);
        /// Generate code with period and current timestamp
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let verified = otp.verify(code, ctx.config.otp.exp_in_sec.try_into().unwrap(), timestamp);
        if verified {
            Ok("Verified successful!".to_string())
        } else {
            Err(AppError::BadRequest(String::from("OTP has expired!")))
        }
    }

    async fn generate_otp(email: &str, ctx: &State<AppContext>) -> anyhow::Result<u32> {
        let otp = TOTP::new(&ctx.config.otp.secret);
        /// Generate code with period and current timestamp
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let code = otp
            .generate(ctx.config.otp.exp_in_sec.try_into().unwrap(), timestamp)
            .map_err(|_| anyhow::anyhow!("Fail to create OTP code!"))?;

        Ok(code)
    }

    fn is_valid_email(email: &str) -> Result<(), AppError> {
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
        if !email_regex.is_match(email) {
            return Err(AppError::BadRequest(String::from("Invalid email format")));
        }
        Ok(())
    }

    fn send_email_otp(
        to_email: &String,
        code: &u32,
        ctx: &State<AppContext>
    ) -> Result<(), AppError> {
        let email = Message::builder()
            .from(
                format!("{} <ducle6487@gmail.com>", &ctx.config.smtp.name).parse().unwrap()
            )
            .to(format!("<{}>", &to_email).parse().unwrap())
            .subject(String::from("Login Code: ".to_string() + &code.to_string()))
            .multipart(
                MultiPart::alternative().singlepart(
                    SinglePart::builder()
                        .header(lettre::message::header::ContentType::TEXT_HTML)
                        .body(String::from(Self::get_email_body(&code)))
                )
            )
            .unwrap();

        let creds = Credentials::new(
            ctx.config.smtp.email.to_owned(),
            ctx.config.smtp.password.to_owned()
        );

        // Open a remote connection to gmail
        let mailer = SmtpTransport::starttls_relay(&ctx.config.smtp.server)
            .unwrap()
            .port(ctx.config.smtp.port)
            .credentials(creds)
            .build();

        // Send the email
        match mailer.send(&email) {
            Ok(_) => Ok(()),
            Err(e) => Err(AppError::BadRequest(String::from(e.to_string()))),
        }
    }

    fn get_email_body(code: &u32) -> String {
        let body =
            html!(<div id=":e0" class="a3s aiL msg6270246753725332129">
    <div class="adM"></div>
    <u></u>
    <div style="padding:0;margin:0;height:100%;width:100%;font-family:'FF Mark W05',Arial,sans-serif">
        <div style="margin:0 auto;max-width:600px;display:block;font-family:inherit">
            <table cellpadding="0" cellspacing="0"
                style="padding:0;border-spacing:0;background:#f0f0f0;border:0;margin:0;text-align:center;vertical-align:middle;font-weight:500;table-layout:fixed;border-collapse:collapse;height:100%;width:100%;line-height:100%"
                width="100%" height="100%" align="center" valign="middle">
                <tbody>
                    <tr
                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                        <td
                            style="margin:0;padding:0;border:none;border-spacing:0;background:#f0f0f0;border-collapse:collapse;font-family:inherit">
                            <table cellpadding="0" cellspacing="0"
                                style="margin:0;border-spacing:0;border:0;padding:0;width:100%;border-collapse:collapse"
                                width="100%">
                                <tbody>
                                    <tr
                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                        <td
                                            style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                            <table cellpadding="0" cellspacing="0"
                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                width="100%">
                                                <tbody>
                                                    <tr
                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                        <td class="m_6270246753725332129dnXDPa"
                                                            style="margin:0;padding:0;border:none;border-spacing:0;background-image:url(https://ci3.googleusercontent.com/meips/ADKq_Nak7ZJfzPYT9YF6NSI8n6egZ8DD4rwuwAUPU-kLtNt926NST4tjb_WwkS4LIavB1dl3VFFt-F_XK0ONCNXuXpcOcCF-s00ySI9kxem5I6LjrJDZzDfqCH9fjZYZB3mPLlYFbZSDhkxZHzsv53PeWrsvJm2Rk2aJs-MzwwON3lE5A3ckDqy1hPEX=s0-d-e1-ft#http://cdn.mcauto-images-production.sendgrid.net/6c20475da3226ec8/484f76b1-56c9-4c73-b20c-8ec7eb01c2be/1836x516.png);background-size:cover;width:612px;height:146px;text-align:center;border-collapse:collapse;font-family:inherit"
                                                            width="612" height="146"
                                                            background="https://ci3.googleusercontent.com/meips/ADKq_Nak7ZJfzPYT9YF6NSI8n6egZ8DD4rwuwAUPU-kLtNt926NST4tjb_WwkS4LIavB1dl3VFFt-F_XK0ONCNXuXpcOcCF-s00ySI9kxem5I6LjrJDZzDfqCH9fjZYZB3mPLlYFbZSDhkxZHzsv53PeWrsvJm2Rk2aJs-MzwwON3lE5A3ckDqy1hPEX=s0-d-e1-ft#http://cdn.mcauto-images-production.sendgrid.net/6c20475da3226ec8/484f76b1-56c9-4c73-b20c-8ec7eb01c2be/1836x516.png"
                                                            align="center"></td>
                                                    </tr>
                                                </tbody>
                                            </table>
                                        </td>
                                    </tr>
                                    <tr
                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                        <td colspan="1"
                                            style="margin:0;padding:0;border:none;border-spacing:0;height:24px;border-collapse:collapse;font-family:inherit"
                                            height="24">
                                            <table
                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                width="100%"></table>
                                        </td>
                                    </tr>
                                    <tr
                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                        <td style="margin:0;padding:0;border:none;border-spacing:0;text-align:center;border-collapse:collapse;font-family:inherit"
                                            align="center">
                                            <table cellpadding="0" cellspacing="0"
                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                width="100%">
                                                <tbody>
                                                    <tr
                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                        <td class="m_6270246753725332129hTfFsy"
                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:100%;overflow:hidden;width:72px;border-collapse:collapse;font-family:inherit"
                                                            width="72" height="100%">
                                                            <div class="m_6270246753725332129hTfFsy"
                                                                style="height:100%;overflow:hidden;width:72px;font-family:inherit">
                                                            </div>
                                                        </td>
                                                        <td style="margin:0;padding:0;border:none;border-spacing:0;text-align:center;border-collapse:collapse;font-family:inherit"
                                                            align="center">
                                                            <h1
                                                                style="font-size:32px;font-weight:500;letter-spacing:.01em;color:#141212;text-align:center;line-height:39px;margin:0;font-family:inherit">
                                                                "Login Code"</h1>
                                                        </td>
                                                        <td class="m_6270246753725332129hTfFsy"
                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:100%;overflow:hidden;width:72px;border-collapse:collapse;font-family:inherit"
                                                            width="72" height="100%">
                                                            <div class="m_6270246753725332129hTfFsy"
                                                                style="height:100%;overflow:hidden;width:72px;font-family:inherit">
                                                            </div>
                                                        </td>
                                                    </tr>
                                                </tbody>
                                            </table>
                                        </td>
                                    </tr>
                                    <tr
                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                        <td style="margin:0;padding:0;border:none;border-spacing:0;text-align:center;border-collapse:collapse;font-family:inherit"
                                            align="center">
                                            <table cellpadding="0" cellspacing="0"
                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                width="100%">
                                                <tbody>
                                                    <tr
                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                        <td colspan="3"
                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:64px;border-collapse:collapse;font-family:inherit"
                                                            height="64">
                                                            <table
                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                                width="100%"></table>
                                                        </td>
                                                    </tr>
                                                    <tr
                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                        <td class="m_6270246753725332129hTfFsy"
                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:100%;overflow:hidden;width:72px;border-collapse:collapse;font-family:inherit"
                                                            width="72" height="100%">
                                                            <div class="m_6270246753725332129hTfFsy"
                                                                style="height:100%;overflow:hidden;width:72px;font-family:inherit">
                                                            </div>
                                                        </td>
                                                        <td style="margin:0;padding:0;border:none;border-spacing:0;text-align:center;border-collapse:collapse;font-family:inherit"
                                                            align="center">
                                                            <table cellpadding="0" cellspacing="0"
                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;background-color:#f9f9f9;border-collapse:collapse"
                                                                width="100%" bgcolor="#F9F9F9">
                                                                <tbody>
                                                                    <tr
                                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                                        <td colspan="3"
                                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:40px;border-collapse:collapse;font-family:inherit"
                                                                            height="40">
                                                                            <table
                                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                                                width="100%"></table>
                                                                        </td>
                                                                    </tr>
                                                                    <tr
                                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                                        <td class="m_6270246753725332129gkvQUv"
                                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:100%;overflow:hidden;width:38px;border-collapse:collapse;font-family:inherit"
                                                                            width="38" height="100%">
                                                                            <div class="m_6270246753725332129gkvQUv"
                                                                                style="height:100%;overflow:hidden;width:38px;font-family:inherit">
                                                                            </div>
                                                                        </td>
                                                                        <td style="margin:0;padding:0;border:none;border-spacing:0;text-align:center;border-collapse:collapse;font-family:inherit"
                                                                            align="center">
                                                                            <table
                                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;table-layout:fixed;border-collapse:collapse"
                                                                                width="100%">
                                                                                <tbody>
                                                                                    <tr>
                                                                                        <td>
                                                                                            <h2
                                                                                                style="font-size:25.63px;font-weight:700;line-height:100%;color:#333;margin:0;text-align:center;font-family:inherit">
                                                                                            </h2>
                                                                                        </td>
                                                                                    </tr>
                                                                                    <tr
                                                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                                                        <td colspan="1"
                                                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:8px;border-collapse:collapse;font-family:inherit"
                                                                                            height="8">
                                                                                            <table
                                                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                                                                width="100%"></table>
                                                                                        </td>
                                                                                    </tr>
                                                                                    <tr
                                                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                                                        <td style="margin:0;padding:0;border:none;border-spacing:0;text-align:center;border-collapse:collapse;font-family:inherit"
                                                                                            align="center">
                                                                                            <p
                                                                                                style="margin:0;padding:0;font-weight:500;font-size:18px;line-height:140%;letter-spacing:-.01em;color:#666;font-family:inherit">
                                                                                                "Here is your login
                                                                                                approval code:"</p>
                                                                                        </td>
                                                                                    </tr>
                                                                                    <tr
                                                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                                                        <td colspan="1"
                                                                                            class="m_6270246753725332129kAINMw"
                                                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:40px;border-collapse:collapse;font-family:inherit"
                                                                                            height="40">
                                                                                            <table
                                                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                                                                width="100%"></table>
                                                                                        </td>
                                                                                    </tr>
                                                                                    <tr
                                                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                                                        <td style="margin:0;padding:0;border:none;border-spacing:0;text-align:center;border-collapse:collapse;font-family:inherit"
                                                                                            align="center">
                                                                                            <table
                                                                                                class="m_6270246753725332129lloNHj"
                                                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;margin-left:.7em;border-collapse:collapse"
                                                                                                width="100%">
                                                                                                <tbody>
                                                                                                    <tr
                                                                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                                                                        <td class="m_6270246753725332129Rnkmq"
                                                                                                            style="margin:0;padding:0;border:none;border-spacing:0;line-height:100%;text-align:center;font-size:37px;line-height:100%;text-transform:uppercase;letter-spacing:.7em;border-collapse:collapse;font-family:inherit"
                                                                                                            align="center">
                                                                                                            {code}</td>
                                                                                                    </tr>
                                                                                                </tbody>
                                                                                            </table>
                                                                                        </td>
                                                                                    </tr>
                                                                                </tbody>
                                                                            </table>
                                                                        </td>
                                                                        <td class="m_6270246753725332129gkvQUv"
                                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:100%;overflow:hidden;width:38px;border-collapse:collapse;font-family:inherit"
                                                                            width="38" height="100%">
                                                                            <div class="m_6270246753725332129gkvQUv"
                                                                                style="height:100%;overflow:hidden;width:38px;font-family:inherit">
                                                                            </div>
                                                                        </td>
                                                                    </tr>
                                                                    <tr
                                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                                        <td colspan="3"
                                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:48px;border-collapse:collapse;font-family:inherit"
                                                                            height="48">
                                                                            <table
                                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                                                width="100%"></table>
                                                                        </td>
                                                                    </tr>
                                                                </tbody>
                                                            </table>
                                                        </td>
                                                        <td class="m_6270246753725332129hTfFsy"
                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:100%;overflow:hidden;width:72px;border-collapse:collapse;font-family:inherit"
                                                            width="72" height="100%">
                                                            <div class="m_6270246753725332129hTfFsy"
                                                                style="height:100%;overflow:hidden;width:72px;font-family:inherit">
                                                            </div>
                                                        </td>
                                                    </tr>
                                                    <tr
                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                        <td colspan="3"
                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:48px;border-collapse:collapse;font-family:inherit"
                                                            height="48">
                                                            <table
                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                                width="100%"></table>
                                                        </td>
                                                    </tr>
                                                </tbody>
                                            </table>
                                        </td>
                                    </tr>
                                    <tr
                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                        <td style="margin:0;padding:0;border:none;border-spacing:0;text-align:center;border-collapse:collapse;font-family:inherit"
                                            align="center">
                                            <table cellpadding="0" cellspacing="0"
                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;font-size:16px;text-align:center;line-height:140%;letter-spacing:-.01em;color:#666;border-collapse:collapse"
                                                width="100%" align="center">
                                                <tbody>
                                                    <tr
                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                        <td class="m_6270246753725332129kETegz"
                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:100%;overflow:hidden;width:100px;border-collapse:collapse;font-family:inherit"
                                                            width="100" height="100%">
                                                            <div class="m_6270246753725332129kETegz"
                                                                style="height:100%;overflow:hidden;width:100px;font-family:inherit">
                                                            </div>
                                                        </td>
                                                        <td style="margin:0;padding:0;border:none;border-spacing:0;text-align:center;border-collapse:collapse;font-family:inherit"
                                                            align="center">"If this request did not come from you, change
                                                            your account password immediately to prevent further
                                                            unauthorized access."</td>
                                                        <td class="m_6270246753725332129kETegz"
                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:100%;overflow:hidden;width:100px;border-collapse:collapse;font-family:inherit"
                                                            width="100" height="100%">
                                                            <div class="m_6270246753725332129kETegz"
                                                                style="height:100%;overflow:hidden;width:100px;font-family:inherit">
                                                            </div>
                                                        </td>
                                                    </tr>
                                                    <tr
                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                        <td colspan="3"
                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:80px;border-collapse:collapse;font-family:inherit"
                                                            height="80">
                                                            <table
                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                                width="100%"></table>
                                                        </td>
                                                    </tr>
                                                </tbody>
                                            </table>
                                        </td>
                                    </tr>
                                    <tr
                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                        <td style="margin:0;padding:0;border:none;border-spacing:0;text-align:center;border-collapse:collapse;font-family:inherit"
                                            align="center">
                                            <table cellpadding="0" cellspacing="0"
                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                width="100%">
                                                <tbody>
                                                    <tr
                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                        <td class="m_6270246753725332129fDKKAz"
                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:100%;overflow:hidden;width:72px;border-collapse:collapse;font-family:inherit"
                                                            width="72" height="100%">
                                                            <div class="m_6270246753725332129fDKKAz"
                                                                style="height:100%;overflow:hidden;width:72px;font-family:inherit">
                                                            </div>
                                                        </td>
                                                        <td style="margin:0;padding:0;border:none;border-spacing:0;text-align:center;border-collapse:collapse;font-family:inherit"
                                                            align="center">
                                                            <table cellpadding="0" cellspacing="0"
                                                                class="m_6270246753725332129dkrsEk"
                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;font-size:11.24px;line-height:140%;letter-spacing:-.01em;color:#999;table-layout:fixed;border-collapse:collapse"
                                                                width="100%">
                                                                <tbody>
                                                                    <tr
                                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                                        <td style="margin:0;padding:0;border:none;border-spacing:0;text-align:center;border-collapse:collapse;font-family:inherit"
                                                                            align="center">
                                                                            <table cellpadding="0" cellspacing="0"
                                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                                                width="100%">
                                                                                <tbody>
                                                                                    <tr
                                                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                                                        <td colspan="1"
                                                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:48px;border-collapse:collapse;font-family:inherit"
                                                                                            height="48">
                                                                                            <table
                                                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                                                                width="100%"></table>
                                                                                        </td>
                                                                                    </tr>
                                                                                    <tr
                                                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                                                        <td style="margin:0;padding:0;border:none;border-spacing:0;text-align:center;border-collapse:collapse;font-family:inherit"
                                                                                            align="center">
                                                                                            <table cellpadding="0"
                                                                                                cellspacing="0"
                                                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;table-layout:fixed;border-collapse:collapse"
                                                                                                width="100%">
                                                                                                <tbody>
                                                                                                    <tr
                                                                                                        style="margin:0;padding:0;border:none;border-spacing:0;height:44px;width:100%;border-collapse:collapse;font-family:inherit">
                                                                                                        <td
                                                                                                            style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                                                                        </td>
                                                                                                        <td style="margin:0;padding:0;border:none;border-spacing:0;width:44px;height:44px;border-collapse:collapse;font-family:inherit"
                                                                                                            width="44"
                                                                                                            height="44">
                                                                                                            <a href="https://links.riotgames.com/ls/click?upn=u001.1qaABrx8Fusbo9A5Atzd5wwClsIDfcbardtjWwwRW-2FkRnqvGhY5TVgn-2BKx-2Fxh70AiQcU_cdSfWOUGH0LYYxyPVRkCwo6PAka5OJ6pL8wIQmjIrupSBfK0WFN9HiGnAZ6V6-2FxdG-2F4tGbHiWfjGh3gQfVCvPIVCtroU-2BvFd4aj7z-2FWsm75xneYGrn16O1iEsUsZpnrJdtjcHNtLYYJLvuI8Sz-2BY0QAOnWoOZHd5WvcKQBDmgRCOMOXo08YP-2BR9T2UBznbtLBRsgTe9ASLvm7EnLr3rD8P2E5m189mQh6cxQNFSIdviWwQ9QBco6QcDPwNX923MRjIRbU87bLibjpAGSPdOxTdAB2KcgNz9C3EGWcpILHQ1JkrmP3KgYs0lEPGDlZiPFq93gAzzM-2Bmwzfw6Nr1pruB9niIvikSEsb-2F44zKkrPBBOQ6wz99fwhcufcNURnnetz53PRVghkbd10-2Fre-2F-2BcvKEEG3bf9k-2B0RSmioIkTu8H2UCGIxCrDyHvJscbKkV4gGExG-2BkeYNAjE1faEayoy8JtGDHlCXWGW62kxh4Pfd0rsp2LM8RimN2mH4in3In6DjZd6BDz2ysS2N-2BxERv3vGUwjHxWuvxQL1yHMRF9rE9HPsOnWJUzkDO2kwo2tp0kSGmcsYQyJv2oz2m-2B0TQeuPbQK39VU3VEPnB5inQjbvPV9apn1g2sR5mpE-2FZ-2F60mIgg43aA8r7H4sj3wBqTBl3Qvite-2FqvQxUuQOvbLkQbc-2Fd0Bdokdf0kY6PoKFIRmiEFz1yeGkSSWbYywDNHIhMNYfMMMS-2FHu2IcDrRa1QfgH85lJu0YifuATSwweAL7XMtcCtQFHz4V7aMWFYzmK-2BQcvISDdOivx4lEKzUrPpKBeR5dDA8PPvrl6BbhtP6j8H-2FvGe-2BNmeRlS-2BZxkYwsVvdO4y8GVSMJ54zPBsp4a2teCqg3-2Far6edjSZLfr9eyu5RZ2MiHzougx5qmAfaxV6GpabnTZHqU73rV9CwZdg8tH7NAgfGl83AorQveDWJLbqgrNF"
                                                                                                                style="color:#bd2225;text-decoration:underline"
                                                                                                                target="_blank"
                                                                                                                data-saferedirecturl="https://www.google.com/url?q=https://links.riotgames.com/ls/click?upn%3Du001.1qaABrx8Fusbo9A5Atzd5wwClsIDfcbardtjWwwRW-2FkRnqvGhY5TVgn-2BKx-2Fxh70AiQcU_cdSfWOUGH0LYYxyPVRkCwo6PAka5OJ6pL8wIQmjIrupSBfK0WFN9HiGnAZ6V6-2FxdG-2F4tGbHiWfjGh3gQfVCvPIVCtroU-2BvFd4aj7z-2FWsm75xneYGrn16O1iEsUsZpnrJdtjcHNtLYYJLvuI8Sz-2BY0QAOnWoOZHd5WvcKQBDmgRCOMOXo08YP-2BR9T2UBznbtLBRsgTe9ASLvm7EnLr3rD8P2E5m189mQh6cxQNFSIdviWwQ9QBco6QcDPwNX923MRjIRbU87bLibjpAGSPdOxTdAB2KcgNz9C3EGWcpILHQ1JkrmP3KgYs0lEPGDlZiPFq93gAzzM-2Bmwzfw6Nr1pruB9niIvikSEsb-2F44zKkrPBBOQ6wz99fwhcufcNURnnetz53PRVghkbd10-2Fre-2F-2BcvKEEG3bf9k-2B0RSmioIkTu8H2UCGIxCrDyHvJscbKkV4gGExG-2BkeYNAjE1faEayoy8JtGDHlCXWGW62kxh4Pfd0rsp2LM8RimN2mH4in3In6DjZd6BDz2ysS2N-2BxERv3vGUwjHxWuvxQL1yHMRF9rE9HPsOnWJUzkDO2kwo2tp0kSGmcsYQyJv2oz2m-2B0TQeuPbQK39VU3VEPnB5inQjbvPV9apn1g2sR5mpE-2FZ-2F60mIgg43aA8r7H4sj3wBqTBl3Qvite-2FqvQxUuQOvbLkQbc-2Fd0Bdokdf0kY6PoKFIRmiEFz1yeGkSSWbYywDNHIhMNYfMMMS-2FHu2IcDrRa1QfgH85lJu0YifuATSwweAL7XMtcCtQFHz4V7aMWFYzmK-2BQcvISDdOivx4lEKzUrPpKBeR5dDA8PPvrl6BbhtP6j8H-2FvGe-2BNmeRlS-2BZxkYwsVvdO4y8GVSMJ54zPBsp4a2teCqg3-2Far6edjSZLfr9eyu5RZ2MiHzougx5qmAfaxV6GpabnTZHqU73rV9CwZdg8tH7NAgfGl83AorQveDWJLbqgrNF&amp;source=gmail&amp;ust=1710841490916000&amp;usg=AOvVaw1j9wy3hDdEV1pr1ndoxWq0">
                                                                                                                <img alt="Facebook icon"
                                                                                                                    src="https://ci3.googleusercontent.com/meips/ADKq_NZ8eWjjrcRIzSf97IShBwkN3hf6EAG7mwr6W_kVv5mlf6jXuaDyCZR-ZHxmIxbRCPnfGib4i13UY0rRnesmU-MdcGrTM2eq65bfR-TVMbW9BRZ42k4MYcppnxxUQcVyOuitL-E=s0-d-e1-ft#https://lolstatic-a.akamaihd.net/email-marketing/betabuddies/facebook-logo.png"
                                                                                                                    style="border:0;line-height:100%;outline:0;text-decoration:none;width:44px;height:44px"
                                                                                                                    width="44"
                                                                                                                    height="44"
                                                                                                                    class="CToWUd"
                                                                                                                    data-bit="iit"></img>
                                                                                                            </a>
                                                                                                        </td>
                                                                                                        <td class="m_6270246753725332129kikspt"
                                                                                                            style="margin:0;padding:0;border:none;border-spacing:0;width:24px;height:44px;border-collapse:collapse;font-family:inherit"
                                                                                                            width="24"
                                                                                                            height="44">
                                                                                                        </td>
                                                                                                        <td style="margin:0;padding:0;border:none;border-spacing:0;width:44px;height:44px;border-collapse:collapse;font-family:inherit"
                                                                                                            width="44"
                                                                                                            height="44">
                                                                                                            <a href="https://links.riotgames.com/ls/click?upn=u001.1qaABrx8Fusbo9A5Atzd57X-2FyDWGIs9qQV48-2BgU4lorlLJxQfx2sFlzBFzD7cgPr4uQE_cdSfWOUGH0LYYxyPVRkCwo6PAka5OJ6pL8wIQmjIrupSBfK0WFN9HiGnAZ6V6-2FxdG-2F4tGbHiWfjGh3gQfVCvPIVCtroU-2BvFd4aj7z-2FWsm75xneYGrn16O1iEsUsZpnrJdtjcHNtLYYJLvuI8Sz-2BY0QAOnWoOZHd5WvcKQBDmgRCOMOXo08YP-2BR9T2UBznbtLBRsgTe9ASLvm7EnLr3rD8P2E5m189mQh6cxQNFSIdviWwQ9QBco6QcDPwNX923MRjIRbU87bLibjpAGSPdOxTdAB2KcgNz9C3EGWcpILHQ1JkrmP3KgYs0lEPGDlZiPFq93gAzzM-2Bmwzfw6Nr1pruB9niIvikSEsb-2F44zKkrPBBOQ6wz99fwhcufcNURnnetz53PRVghkbd10-2Fre-2F-2BcvKEEG3bf9k-2B0RSmioIkTu8H2UCGIxCrDyHvJscbKkV4gGExG-2BkeYNAjE1faEayoy8JtGDHlCXWGW62kxh4Pfd0rsp2LM8RimN2mH4in3In6DjZd6BDz2ysS2N-2BxERv3vGUwjHxWuvxQL1yHMRF9rE9HPsOnWJUzkDO2kwo2tp0kSGmcsYQyJv2oz2m-2B0TQeuPbQK39VU3VEPnB5inQjbvPV9apn1g2sR5mpE-2FZ-2F60mIgg43aA8r7H4sj3wBqTBl3Qvite-2FqvQxUuQOvbLkQbc-2Fd0Bdokdf0kY6PoKFIRmiEFz1yeGkSSWbYywDNHIhMNYfMMMS-2FHu2IcDrRa1QfgH85lJu0YifuATSwweAL7XMtcCtQFHz4V7aMWFYzmK-2BQcvISDdOivx4lEKzUrPpKBeR5cpsOsfoZX74xX4mnbnT26ciYBe29yd-2BxQPvV3dgp4Y8tdYBfTa6jDIL7U1lvHK5WxAegw5tPtAnqTl2RhKymo7G2axlNzhKP-2BrPIkqQu5JdrOP-2BfFM-2BDoJBC-2B3s2ajuEA-2FKkey27k3Mk1nD8zkR8NO"
                                                                                                                style="color:#bd2225;text-decoration:underline"
                                                                                                                target="_blank"
                                                                                                                data-saferedirecturl="https://www.google.com/url?q=https://links.riotgames.com/ls/click?upn%3Du001.1qaABrx8Fusbo9A5Atzd57X-2FyDWGIs9qQV48-2BgU4lorlLJxQfx2sFlzBFzD7cgPr4uQE_cdSfWOUGH0LYYxyPVRkCwo6PAka5OJ6pL8wIQmjIrupSBfK0WFN9HiGnAZ6V6-2FxdG-2F4tGbHiWfjGh3gQfVCvPIVCtroU-2BvFd4aj7z-2FWsm75xneYGrn16O1iEsUsZpnrJdtjcHNtLYYJLvuI8Sz-2BY0QAOnWoOZHd5WvcKQBDmgRCOMOXo08YP-2BR9T2UBznbtLBRsgTe9ASLvm7EnLr3rD8P2E5m189mQh6cxQNFSIdviWwQ9QBco6QcDPwNX923MRjIRbU87bLibjpAGSPdOxTdAB2KcgNz9C3EGWcpILHQ1JkrmP3KgYs0lEPGDlZiPFq93gAzzM-2Bmwzfw6Nr1pruB9niIvikSEsb-2F44zKkrPBBOQ6wz99fwhcufcNURnnetz53PRVghkbd10-2Fre-2F-2BcvKEEG3bf9k-2B0RSmioIkTu8H2UCGIxCrDyHvJscbKkV4gGExG-2BkeYNAjE1faEayoy8JtGDHlCXWGW62kxh4Pfd0rsp2LM8RimN2mH4in3In6DjZd6BDz2ysS2N-2BxERv3vGUwjHxWuvxQL1yHMRF9rE9HPsOnWJUzkDO2kwo2tp0kSGmcsYQyJv2oz2m-2B0TQeuPbQK39VU3VEPnB5inQjbvPV9apn1g2sR5mpE-2FZ-2F60mIgg43aA8r7H4sj3wBqTBl3Qvite-2FqvQxUuQOvbLkQbc-2Fd0Bdokdf0kY6PoKFIRmiEFz1yeGkSSWbYywDNHIhMNYfMMMS-2FHu2IcDrRa1QfgH85lJu0YifuATSwweAL7XMtcCtQFHz4V7aMWFYzmK-2BQcvISDdOivx4lEKzUrPpKBeR5cpsOsfoZX74xX4mnbnT26ciYBe29yd-2BxQPvV3dgp4Y8tdYBfTa6jDIL7U1lvHK5WxAegw5tPtAnqTl2RhKymo7G2axlNzhKP-2BrPIkqQu5JdrOP-2BfFM-2BDoJBC-2B3s2ajuEA-2FKkey27k3Mk1nD8zkR8NO&amp;source=gmail&amp;ust=1710841490916000&amp;usg=AOvVaw1usk0_5Phs4LOmT8xNPnVf">
                                                                                                                <img alt="Instagram icon"
                                                                                                                    src="https://ci3.googleusercontent.com/meips/ADKq_NZUedGKkwdQ9Jw0Y6ClifA4PDpAMyAW1-N0oAWzeWOkcqJmIjw5BHdJOBiVWHCOjj3duW-y3unrjqfIcT4-q92i1dDv5ljZKhjocQMimNWs1PnpumPVQ64k3JBtOtYDCrYTJFUV=s0-d-e1-ft#https://lolstatic-a.akamaihd.net/email-marketing/betabuddies/instagram-logo.png"
                                                                                                                    style="border:0;line-height:100%;outline:0;text-decoration:none;width:44px;height:44px"
                                                                                                                    width="44"
                                                                                                                    height="44"
                                                                                                                    class="CToWUd"
                                                                                                                    data-bit="iit"></img>
                                                                                                            </a>
                                                                                                        </td>
                                                                                                        <td class="m_6270246753725332129kikspt"
                                                                                                            style="margin:0;padding:0;border:none;border-spacing:0;width:24px;height:44px;border-collapse:collapse;font-family:inherit"
                                                                                                            width="24"
                                                                                                            height="44">
                                                                                                        </td>
                                                                                                        <td style="margin:0;padding:0;border:none;border-spacing:0;width:44px;height:44px;border-collapse:collapse;font-family:inherit"
                                                                                                            width="44"
                                                                                                            height="44">
                                                                                                            <a href="https://links.riotgames.com/ls/click?upn=u001.1qaABrx8Fusbo9A5Atzd57xwkj7ZwSoB0IVhNWhmM0jgMtuWCbNjmeOIqLvY3Yk1DQV-2Fvt-2B3Fpg-2BYOdVgTw1YA5y1vbwF4nRMjz4ZzJy7q0-3DPRF-_cdSfWOUGH0LYYxyPVRkCwo6PAka5OJ6pL8wIQmjIrupSBfK0WFN9HiGnAZ6V6-2FxdG-2F4tGbHiWfjGh3gQfVCvPIVCtroU-2BvFd4aj7z-2FWsm75xneYGrn16O1iEsUsZpnrJdtjcHNtLYYJLvuI8Sz-2BY0QAOnWoOZHd5WvcKQBDmgRCOMOXo08YP-2BR9T2UBznbtLBRsgTe9ASLvm7EnLr3rD8P2E5m189mQh6cxQNFSIdviWwQ9QBco6QcDPwNX923MRjIRbU87bLibjpAGSPdOxTdAB2KcgNz9C3EGWcpILHQ1JkrmP3KgYs0lEPGDlZiPFq93gAzzM-2Bmwzfw6Nr1pruB9niIvikSEsb-2F44zKkrPBBOQ6wz99fwhcufcNURnnetz53PRVghkbd10-2Fre-2F-2BcvKEEG3bf9k-2B0RSmioIkTu8H2UCGIxCrDyHvJscbKkV4gGExG-2BkeYNAjE1faEayoy8JtGDHlCXWGW62kxh4Pfd0rsp2LM8RimN2mH4in3In6DjZd6BDz2ysS2N-2BxERv3vGUwjHxWuvxQL1yHMRF9rE9HPsOnWJUzkDO2kwo2tp0kSGmcsYQyJv2oz2m-2B0TQeuPbQK39VU3VEPnB5inQjbvPV9apn1g2sR5mpE-2FZ-2F60mIgg43aA8r7H4sj3wBqTBl3Qvite-2FqvQxUuQOvbLkQbc-2Fd0Bdokdf0kY6PoKFIRmiEFz1yeGkSSWbYywDNHIhMNYfMMMS-2FHu2IcDrRa1QfgH85lJu0YifuATSwweAL7XMtcCtQFHz4V7aMWFYzmK-2BQcvISDdOivx4lEKzUrPpKBeR5dEqoTdoQ2YxbdrkFfuG388rCpXtHBRjEZCKepITDqKX2A6GJ9GHdI7oicqQOoOB7ZmHAB4kxbIOrgCe67eaLeWkVqvg-2BBaEOmrVRXSmaTiKjphZInFrrsN2w-2FeoO2VG7QTlmHYKtAT8RQtNV2uMHop"
                                                                                                                style="color:#bd2225;text-decoration:underline"
                                                                                                                target="_blank"
                                                                                                                data-saferedirecturl="https://www.google.com/url?q=https://links.riotgames.com/ls/click?upn%3Du001.1qaABrx8Fusbo9A5Atzd57xwkj7ZwSoB0IVhNWhmM0jgMtuWCbNjmeOIqLvY3Yk1DQV-2Fvt-2B3Fpg-2BYOdVgTw1YA5y1vbwF4nRMjz4ZzJy7q0-3DPRF-_cdSfWOUGH0LYYxyPVRkCwo6PAka5OJ6pL8wIQmjIrupSBfK0WFN9HiGnAZ6V6-2FxdG-2F4tGbHiWfjGh3gQfVCvPIVCtroU-2BvFd4aj7z-2FWsm75xneYGrn16O1iEsUsZpnrJdtjcHNtLYYJLvuI8Sz-2BY0QAOnWoOZHd5WvcKQBDmgRCOMOXo08YP-2BR9T2UBznbtLBRsgTe9ASLvm7EnLr3rD8P2E5m189mQh6cxQNFSIdviWwQ9QBco6QcDPwNX923MRjIRbU87bLibjpAGSPdOxTdAB2KcgNz9C3EGWcpILHQ1JkrmP3KgYs0lEPGDlZiPFq93gAzzM-2Bmwzfw6Nr1pruB9niIvikSEsb-2F44zKkrPBBOQ6wz99fwhcufcNURnnetz53PRVghkbd10-2Fre-2F-2BcvKEEG3bf9k-2B0RSmioIkTu8H2UCGIxCrDyHvJscbKkV4gGExG-2BkeYNAjE1faEayoy8JtGDHlCXWGW62kxh4Pfd0rsp2LM8RimN2mH4in3In6DjZd6BDz2ysS2N-2BxERv3vGUwjHxWuvxQL1yHMRF9rE9HPsOnWJUzkDO2kwo2tp0kSGmcsYQyJv2oz2m-2B0TQeuPbQK39VU3VEPnB5inQjbvPV9apn1g2sR5mpE-2FZ-2F60mIgg43aA8r7H4sj3wBqTBl3Qvite-2FqvQxUuQOvbLkQbc-2Fd0Bdokdf0kY6PoKFIRmiEFz1yeGkSSWbYywDNHIhMNYfMMMS-2FHu2IcDrRa1QfgH85lJu0YifuATSwweAL7XMtcCtQFHz4V7aMWFYzmK-2BQcvISDdOivx4lEKzUrPpKBeR5dEqoTdoQ2YxbdrkFfuG388rCpXtHBRjEZCKepITDqKX2A6GJ9GHdI7oicqQOoOB7ZmHAB4kxbIOrgCe67eaLeWkVqvg-2BBaEOmrVRXSmaTiKjphZInFrrsN2w-2FeoO2VG7QTlmHYKtAT8RQtNV2uMHop&amp;source=gmail&amp;ust=1710841490916000&amp;usg=AOvVaw24KDvqH6vJMvXIkFLCdRe4">
                                                                                                                <img alt="YouTube icon"
                                                                                                                    src="https://ci3.googleusercontent.com/meips/ADKq_Nbw5BguhKUzXGTPLZsJY9xNhnoGbwqSlFVubmXT-KvYiKA_WihAcokPFB5Ea-02DzZ_OjV7HO2EHFEA2itA_070a13moZT1eOK5cYTzdDH_qKykKVqjbfSSYG95ToiTmZ7qNw=s0-d-e1-ft#https://lolstatic-a.akamaihd.net/email-marketing/betabuddies/youtube-logo.png"
                                                                                                                    style="border:0;line-height:100%;outline:0;text-decoration:none;width:44px;height:44px"
                                                                                                                    width="44"
                                                                                                                    height="44"
                                                                                                                    class="CToWUd"
                                                                                                                    data-bit="iit"></img>
                                                                                                            </a>
                                                                                                        </td>
                                                                                                        <td class="m_6270246753725332129kikspt"
                                                                                                            style="margin:0;padding:0;border:none;border-spacing:0;width:24px;height:44px;border-collapse:collapse;font-family:inherit"
                                                                                                            width="24"
                                                                                                            height="44">
                                                                                                        </td>
                                                                                                        <td style="margin:0;padding:0;border:none;border-spacing:0;width:44px;height:44px;border-collapse:collapse;font-family:inherit"
                                                                                                            width="44"
                                                                                                            height="44">
                                                                                                            <a href="https://links.riotgames.com/ls/click?upn=u001.1qaABrx8Fusbo9A5Atzd5z629fgsn29IpxU-2F5VuVQ3cADHUT8MxfKKxdSwsXmVMwFHG__cdSfWOUGH0LYYxyPVRkCwo6PAka5OJ6pL8wIQmjIrupSBfK0WFN9HiGnAZ6V6-2FxdG-2F4tGbHiWfjGh3gQfVCvPIVCtroU-2BvFd4aj7z-2FWsm75xneYGrn16O1iEsUsZpnrJdtjcHNtLYYJLvuI8Sz-2BY0QAOnWoOZHd5WvcKQBDmgRCOMOXo08YP-2BR9T2UBznbtLBRsgTe9ASLvm7EnLr3rD8P2E5m189mQh6cxQNFSIdviWwQ9QBco6QcDPwNX923MRjIRbU87bLibjpAGSPdOxTdAB2KcgNz9C3EGWcpILHQ1JkrmP3KgYs0lEPGDlZiPFq93gAzzM-2Bmwzfw6Nr1pruB9niIvikSEsb-2F44zKkrPBBOQ6wz99fwhcufcNURnnetz53PRVghkbd10-2Fre-2F-2BcvKEEG3bf9k-2B0RSmioIkTu8H2UCGIxCrDyHvJscbKkV4gGExG-2BkeYNAjE1faEayoy8JtGDHlCXWGW62kxh4Pfd0rsp2LM8RimN2mH4in3In6DjZd6BDz2ysS2N-2BxERv3vGUwjHxWuvxQL1yHMRF9rE9HPsOnWJUzkDO2kwo2tp0kSGmcsYQyJv2oz2m-2B0TQeuPbQK39VU3VEPnB5inQjbvPV9apn1g2sR5mpE-2FZ-2F60mIgg43aA8r7H4sj3wBqTBl3Qvite-2FqvQxUuQOvbLkQbc-2Fd0Bdokdf0kY6PoKFIRmiEFz1yeGkSSWbYywDNHIhMNYfMMMS-2FHu2IcDrRa1QfgH85lJu0YifuATSwweAL7XMtcCtQFHz4V7aMWFYzmK-2BQcvISDdOivx4lEKzUrPpKBeR5e7op-2BgbAVAVOUgueMBCgbT5sJTezM04jNfRxVeYmsCnfRupvkbtD9VgPNuMS5c3d44j-2BYEB1oDRK74ArtXmBfRmvmr1KyNIkF39HuQaAbgXBP7MdkgjGU0FHdNIGuvexBFykfFd6ynJECtlmS6FLnN"
                                                                                                                style="color:#bd2225;text-decoration:underline"
                                                                                                                target="_blank"
                                                                                                                data-saferedirecturl="https://www.google.com/url?q=https://links.riotgames.com/ls/click?upn%3Du001.1qaABrx8Fusbo9A5Atzd5z629fgsn29IpxU-2F5VuVQ3cADHUT8MxfKKxdSwsXmVMwFHG__cdSfWOUGH0LYYxyPVRkCwo6PAka5OJ6pL8wIQmjIrupSBfK0WFN9HiGnAZ6V6-2FxdG-2F4tGbHiWfjGh3gQfVCvPIVCtroU-2BvFd4aj7z-2FWsm75xneYGrn16O1iEsUsZpnrJdtjcHNtLYYJLvuI8Sz-2BY0QAOnWoOZHd5WvcKQBDmgRCOMOXo08YP-2BR9T2UBznbtLBRsgTe9ASLvm7EnLr3rD8P2E5m189mQh6cxQNFSIdviWwQ9QBco6QcDPwNX923MRjIRbU87bLibjpAGSPdOxTdAB2KcgNz9C3EGWcpILHQ1JkrmP3KgYs0lEPGDlZiPFq93gAzzM-2Bmwzfw6Nr1pruB9niIvikSEsb-2F44zKkrPBBOQ6wz99fwhcufcNURnnetz53PRVghkbd10-2Fre-2F-2BcvKEEG3bf9k-2B0RSmioIkTu8H2UCGIxCrDyHvJscbKkV4gGExG-2BkeYNAjE1faEayoy8JtGDHlCXWGW62kxh4Pfd0rsp2LM8RimN2mH4in3In6DjZd6BDz2ysS2N-2BxERv3vGUwjHxWuvxQL1yHMRF9rE9HPsOnWJUzkDO2kwo2tp0kSGmcsYQyJv2oz2m-2B0TQeuPbQK39VU3VEPnB5inQjbvPV9apn1g2sR5mpE-2FZ-2F60mIgg43aA8r7H4sj3wBqTBl3Qvite-2FqvQxUuQOvbLkQbc-2Fd0Bdokdf0kY6PoKFIRmiEFz1yeGkSSWbYywDNHIhMNYfMMMS-2FHu2IcDrRa1QfgH85lJu0YifuATSwweAL7XMtcCtQFHz4V7aMWFYzmK-2BQcvISDdOivx4lEKzUrPpKBeR5e7op-2BgbAVAVOUgueMBCgbT5sJTezM04jNfRxVeYmsCnfRupvkbtD9VgPNuMS5c3d44j-2BYEB1oDRK74ArtXmBfRmvmr1KyNIkF39HuQaAbgXBP7MdkgjGU0FHdNIGuvexBFykfFd6ynJECtlmS6FLnN&amp;source=gmail&amp;ust=1710841490916000&amp;usg=AOvVaw36woQWtSvfJpKaHUPCS3bS">
                                                                                                                <img alt="Twitter icon"
                                                                                                                    src="https://ci3.googleusercontent.com/meips/ADKq_NYDPpMKFfKpK07U8PBz_ZZkCa3lxfy-wSHkgBALHkWzEbaBXgiPGCHsLabi4OzA0cewt01ygRh-io4GT0MpbRvRm41I5P4K8O3m5S_RIKGMuPVvPsxsHKqoeXY-cyl8K3yfLQ=s0-d-e1-ft#https://lolstatic-a.akamaihd.net/email-marketing/betabuddies/twitter-logo.png"
                                                                                                                    style="border:0;line-height:100%;outline:0;text-decoration:none;width:44px;height:44px"
                                                                                                                    width="44"
                                                                                                                    height="44"
                                                                                                                    class="CToWUd"
                                                                                                                    data-bit="iit"></img>
                                                                                                            </a>
                                                                                                        </td>
                                                                                                        <td
                                                                                                            style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                                                                        </td>
                                                                                                    </tr>
                                                                                                </tbody>
                                                                                            </table>
                                                                                        </td>
                                                                                    </tr>
                                                                                    <tr
                                                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                                                        <td colspan="1"
                                                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:32px;border-collapse:collapse;font-family:inherit"
                                                                                            height="32">
                                                                                            <table
                                                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                                                                width="100%"></table>
                                                                                        </td>
                                                                                    </tr>
                                                                                </tbody>
                                                                            </table>
                                                                        </td>
                                                                    </tr>
                                                                </tbody>
                                                            </table>
                                                        </td>
                                                        <td class="m_6270246753725332129fDKKAz"
                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:100%;overflow:hidden;width:72px;border-collapse:collapse;font-family:inherit"
                                                            width="72" height="100%">
                                                            <div class="m_6270246753725332129fDKKAz"
                                                                style="height:100%;overflow:hidden;width:72px;font-family:inherit">
                                                            </div>
                                                        </td>
                                                    </tr>
                                                    <tr
                                                        style="margin:0;padding:0;border:none;border-spacing:0;border-collapse:collapse;font-family:inherit">
                                                        <td colspan="3"
                                                            style="margin:0;padding:0;border:none;border-spacing:0;height:64px;border-collapse:collapse;font-family:inherit"
                                                            height="10">
                                                            <table
                                                                style="margin:0;padding:0;border:none;border-spacing:0;width:100%;border-collapse:collapse"
                                                                width="100%"></table>
                                                        </td>
                                                    </tr>
                                                </tbody>
                                            </table>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
    </div>);
        body.to_string()
    }
}
