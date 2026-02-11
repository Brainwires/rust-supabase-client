use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::types::OtpType;

/// Parameters for updating the current user.
///
/// Matches the `UserAttributes` parameter in Supabase JS `updateUser()`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UpdateUserParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Parameters for verifying an OTP token.
///
/// Matches the `VerifyOtpParams` union type in Supabase JS.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyOtpParams {
    pub token: String,
    #[serde(rename = "type")]
    pub otp_type: OtpType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_hash: Option<String>,
}

/// Parameters for admin user creation.
///
/// Matches `AdminUserAttributes` in Supabase JS `admin.createUser()`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AdminCreateUserParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_confirm: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_confirm: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_metadata: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_metadata: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ban_duration: Option<String>,
}

/// Parameters for admin user update.
///
/// Matches `AdminUserAttributes` in Supabase JS `admin.updateUserById()`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AdminUpdateUserParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_confirm: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_confirm: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_metadata: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_metadata: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ban_duration: Option<String>,
}

/// Parameters for generating a link (admin).
#[derive(Debug, Clone, Serialize)]
pub struct GenerateLinkParams {
    #[serde(rename = "type")]
    pub link_type: GenerateLinkType,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
}

/// Types of links that can be generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GenerateLinkType {
    Signup,
    Invite,
    #[serde(rename = "magiclink")]
    MagicLink,
    Recovery,
    #[serde(rename = "email_change_new")]
    EmailChangeNew,
    #[serde(rename = "email_change_current")]
    EmailChangeCurrent,
}
