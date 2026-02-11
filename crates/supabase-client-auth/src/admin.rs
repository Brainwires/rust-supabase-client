use serde_json::json;

use crate::client::AuthClient;
use crate::error::AuthError;
use crate::params::{
    AdminCreateUserParams, AdminUpdateUserParams, CreateOAuthClientParams, GenerateLinkParams,
    UpdateOAuthClientParams,
};
use crate::types::{AdminUserListResponse, Factor, OAuthClient, OAuthClientListResponse, User};

/// Admin client for Supabase GoTrue admin operations.
///
/// Requires a `service_role` key. These operations should only be used server-side.
///
/// Mirrors `supabase.auth.admin`.
///
/// # Example
/// ```ignore
/// let admin = auth.admin();
/// let users = admin.list_users(None, None).await?;
/// ```
#[derive(Debug)]
pub struct AdminClient<'a> {
    auth: &'a AuthClient,
    service_role_key: Option<&'a str>,
}

impl<'a> AdminClient<'a> {
    /// Create an admin client using the auth client's API key as the service role key.
    pub(crate) fn new(auth: &'a AuthClient) -> Self {
        Self {
            auth,
            service_role_key: None,
        }
    }

    /// Create an admin client with an explicit service role key.
    pub(crate) fn with_key(auth: &'a AuthClient, key: &'a str) -> Self {
        Self {
            auth,
            service_role_key: Some(key),
        }
    }

    fn bearer_token(&self) -> &str {
        self.service_role_key.unwrap_or(self.auth.api_key())
    }

    /// List all users (paginated).
    ///
    /// Mirrors `supabase.auth.admin.listUsers({ page, perPage })`.
    pub async fn list_users(
        &self,
        page: Option<u32>,
        per_page: Option<u32>,
    ) -> Result<AdminUserListResponse, AuthError> {
        let mut url = self.auth.url("/admin/users");
        {
            let mut pairs = url.query_pairs_mut();
            if let Some(page) = page {
                pairs.append_pair("page", &page.to_string());
            }
            if let Some(per_page) = per_page {
                pairs.append_pair("per_page", &per_page.to_string());
            }
        }

        let resp = self
            .auth
            .http()
            .get(url)
            .bearer_auth(self.bearer_token())
            .send()
            .await?;

        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(parse_admin_error(status, resp).await);
        }

        let list: AdminUserListResponse = resp.json().await?;
        Ok(list)
    }

    /// Get a user by their ID.
    ///
    /// Mirrors `supabase.auth.admin.getUserById(uid)`.
    pub async fn get_user_by_id(&self, user_id: &str) -> Result<User, AuthError> {
        let url = self.auth.url(&format!("/admin/users/{}", user_id));
        let resp = self
            .auth
            .http()
            .get(url)
            .bearer_auth(self.bearer_token())
            .send()
            .await?;
        self.auth.handle_user_response(resp).await
    }

    /// Create a new user (admin).
    ///
    /// Does not send confirmation emails. Use `invite_user_by_email` for that.
    ///
    /// Mirrors `supabase.auth.admin.createUser(attributes)`.
    pub async fn create_user(
        &self,
        params: AdminCreateUserParams,
    ) -> Result<User, AuthError> {
        let url = self.auth.url("/admin/users");
        let resp = self
            .auth
            .http()
            .post(url)
            .bearer_auth(self.bearer_token())
            .json(&params)
            .send()
            .await?;
        self.auth.handle_user_response(resp).await
    }

    /// Update a user by their ID (admin).
    ///
    /// Changes are applied immediately without confirmation flows.
    ///
    /// Mirrors `supabase.auth.admin.updateUserById(uid, attributes)`.
    pub async fn update_user_by_id(
        &self,
        user_id: &str,
        params: AdminUpdateUserParams,
    ) -> Result<User, AuthError> {
        let url = self.auth.url(&format!("/admin/users/{}", user_id));
        let resp = self
            .auth
            .http()
            .put(url)
            .bearer_auth(self.bearer_token())
            .json(&params)
            .send()
            .await?;
        self.auth.handle_user_response(resp).await
    }

    /// Delete a user by their ID (hard delete).
    ///
    /// Mirrors `supabase.auth.admin.deleteUser(id)`.
    pub async fn delete_user(&self, user_id: &str) -> Result<(), AuthError> {
        self.delete_user_with_options(user_id, false).await
    }

    /// Delete a user by their ID with soft-delete option.
    ///
    /// When `soft_delete` is true, the user is soft-deleted (identifiable via hashed ID).
    ///
    /// Mirrors `supabase.auth.admin.deleteUser(id, shouldSoftDelete)`.
    pub async fn delete_user_with_options(
        &self,
        user_id: &str,
        soft_delete: bool,
    ) -> Result<(), AuthError> {
        let url = self.auth.url(&format!("/admin/users/{}", user_id));

        let body = if soft_delete {
            json!({ "should_soft_delete": true })
        } else {
            json!({})
        };

        let resp = self
            .auth
            .http()
            .delete(url)
            .bearer_auth(self.bearer_token())
            .json(&body)
            .send()
            .await?;
        self.auth.handle_empty_response(resp).await
    }

    /// Invite a user by email.
    ///
    /// Sends a confirmation/invitation email to the user.
    pub async fn invite_user_by_email(
        &self,
        email: &str,
        redirect_to: Option<&str>,
    ) -> Result<User, AuthError> {
        let mut body = json!({ "email": email });
        if let Some(redirect) = redirect_to {
            body["redirect_to"] = json!(redirect);
        }

        let url = self.auth.url("/invite");
        let resp = self
            .auth
            .http()
            .post(url)
            .bearer_auth(self.bearer_token())
            .json(&body)
            .send()
            .await?;
        self.auth.handle_user_response(resp).await
    }

    /// Generate a link (signup, invite, magic link, recovery, email change).
    pub async fn generate_link(
        &self,
        params: GenerateLinkParams,
    ) -> Result<serde_json::Value, AuthError> {
        let url = self.auth.url("/admin/generate_link");
        let resp = self
            .auth
            .http()
            .post(url)
            .bearer_auth(self.bearer_token())
            .json(&params)
            .send()
            .await?;

        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(parse_admin_error(status, resp).await);
        }

        let value: serde_json::Value = resp.json().await?;
        Ok(value)
    }

    // ─── MFA Admin ─────────────────────────────────────────────

    /// List MFA factors for a user (admin).
    ///
    /// Mirrors `supabase.auth.admin.mfa.listFactors()`.
    pub async fn mfa_list_factors(&self, user_id: &str) -> Result<Vec<Factor>, AuthError> {
        let url = self
            .auth
            .url(&format!("/admin/users/{}/factors", user_id));
        let resp = self
            .auth
            .http()
            .get(url)
            .bearer_auth(self.bearer_token())
            .send()
            .await?;

        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(parse_admin_error(status, resp).await);
        }

        let factors: Vec<Factor> = resp.json().await?;
        Ok(factors)
    }

    // ─── OAuth Client Management ─────────────────────────────

    /// List all registered OAuth clients (paginated).
    ///
    /// Mirrors `supabase.auth.admin.oauth.listClients()`.
    pub async fn oauth_list_clients(
        &self,
        page: Option<u32>,
        per_page: Option<u32>,
    ) -> Result<OAuthClientListResponse, AuthError> {
        let mut url = self.auth.url("/admin/oauth/clients");
        {
            let mut pairs = url.query_pairs_mut();
            if let Some(page) = page {
                pairs.append_pair("page", &page.to_string());
            }
            if let Some(per_page) = per_page {
                pairs.append_pair("per_page", &per_page.to_string());
            }
        }

        let resp = self
            .auth
            .http()
            .get(url)
            .bearer_auth(self.bearer_token())
            .send()
            .await?;

        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(parse_admin_error(status, resp).await);
        }

        let list: OAuthClientListResponse = resp.json().await?;
        Ok(list)
    }

    /// Create a new OAuth client.
    ///
    /// Mirrors `supabase.auth.admin.oauth.createClient()`.
    pub async fn oauth_create_client(
        &self,
        params: CreateOAuthClientParams,
    ) -> Result<OAuthClient, AuthError> {
        let url = self.auth.url("/admin/oauth/clients");
        let resp = self
            .auth
            .http()
            .post(url)
            .bearer_auth(self.bearer_token())
            .json(&params)
            .send()
            .await?;

        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(parse_admin_error(status, resp).await);
        }

        let client: OAuthClient = resp.json().await?;
        Ok(client)
    }

    /// Get an OAuth client by its client ID.
    ///
    /// Mirrors `supabase.auth.admin.oauth.getClient()`.
    pub async fn oauth_get_client(
        &self,
        client_id: &str,
    ) -> Result<OAuthClient, AuthError> {
        let url = self.auth.url(&format!("/admin/oauth/clients/{}", client_id));
        let resp = self
            .auth
            .http()
            .get(url)
            .bearer_auth(self.bearer_token())
            .send()
            .await?;

        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(parse_admin_error(status, resp).await);
        }

        let client: OAuthClient = resp.json().await?;
        Ok(client)
    }

    /// Update an OAuth client.
    ///
    /// Mirrors `supabase.auth.admin.oauth.updateClient()`.
    pub async fn oauth_update_client(
        &self,
        client_id: &str,
        params: UpdateOAuthClientParams,
    ) -> Result<OAuthClient, AuthError> {
        let url = self.auth.url(&format!("/admin/oauth/clients/{}", client_id));
        let resp = self
            .auth
            .http()
            .put(url)
            .bearer_auth(self.bearer_token())
            .json(&params)
            .send()
            .await?;

        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(parse_admin_error(status, resp).await);
        }

        let client: OAuthClient = resp.json().await?;
        Ok(client)
    }

    /// Delete an OAuth client.
    ///
    /// Mirrors `supabase.auth.admin.oauth.deleteClient()`.
    pub async fn oauth_delete_client(
        &self,
        client_id: &str,
    ) -> Result<(), AuthError> {
        let url = self.auth.url(&format!("/admin/oauth/clients/{}", client_id));
        let resp = self
            .auth
            .http()
            .delete(url)
            .bearer_auth(self.bearer_token())
            .send()
            .await?;
        self.auth.handle_empty_response(resp).await
    }

    /// Regenerate the client secret for an OAuth client.
    ///
    /// Mirrors `supabase.auth.admin.oauth.regenerateClientSecret()`.
    pub async fn oauth_regenerate_client_secret(
        &self,
        client_id: &str,
    ) -> Result<OAuthClient, AuthError> {
        let url = self.auth.url(&format!(
            "/admin/oauth/clients/{}/regenerate_secret",
            client_id
        ));
        let resp = self
            .auth
            .http()
            .post(url)
            .bearer_auth(self.bearer_token())
            .send()
            .await?;

        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(parse_admin_error(status, resp).await);
        }

        let client: OAuthClient = resp.json().await?;
        Ok(client)
    }

    /// Delete an MFA factor for a user (admin).
    ///
    /// Mirrors `supabase.auth.admin.mfa.deleteFactor()`.
    pub async fn mfa_delete_factor(
        &self,
        user_id: &str,
        factor_id: &str,
    ) -> Result<(), AuthError> {
        let url = self
            .auth
            .url(&format!("/admin/users/{}/factors/{}", user_id, factor_id));
        let resp = self
            .auth
            .http()
            .delete(url)
            .bearer_auth(self.bearer_token())
            .send()
            .await?;
        self.auth.handle_empty_response(resp).await
    }
}

async fn parse_admin_error(status: u16, resp: reqwest::Response) -> AuthError {
    use crate::error::GoTrueErrorResponse;

    match resp.json::<GoTrueErrorResponse>().await {
        Ok(err_resp) => {
            let error_code = err_resp.error_code.as_deref().map(|s| s.into());
            AuthError::Api {
                status,
                message: err_resp.error_message(),
                error_code,
            }
        }
        Err(_) => AuthError::Api {
            status,
            message: format!("HTTP {}", status),
            error_code: None,
        },
    }
}
