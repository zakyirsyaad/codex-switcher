//! Account switching logic - writes credentials to ~/.codex/auth.json

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use chrono::Utc;

use crate::types::{
    parse_chatgpt_id_token_claims, AuthData, AuthDotJson, StoredAccount, TokenData,
};

/// Get the official Codex home directory
pub fn get_codex_home() -> Result<PathBuf> {
    // Check for CODEX_HOME environment variable first
    if let Ok(codex_home) = std::env::var("CODEX_HOME") {
        return Ok(PathBuf::from(codex_home));
    }

    let home = dirs::home_dir().context("Could not find home directory")?;
    Ok(home.join(".codex"))
}

/// Get the path to the official auth.json file
pub fn get_codex_auth_file() -> Result<PathBuf> {
    Ok(get_codex_home()?.join("auth.json"))
}

/// Switch to a specific account by writing its credentials to ~/.codex/auth.json
pub fn switch_to_account(account: &StoredAccount) -> Result<()> {
    if let AuthData::CodexAccessToken { token, .. } = &account.auth_data {
        return login_with_codex_access_token(token);
    }

    let codex_home = get_codex_home()?;

    // Ensure the codex home directory exists
    fs::create_dir_all(&codex_home)
        .with_context(|| format!("Failed to create codex home: {}", codex_home.display()))?;

    let auth_json = create_auth_json(account)?;

    let auth_path = codex_home.join("auth.json");
    let content =
        serde_json::to_string_pretty(&auth_json).context("Failed to serialize auth.json")?;

    fs::write(&auth_path, content)
        .with_context(|| format!("Failed to write auth.json: {}", auth_path.display()))?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&auth_path, perms)?;
    }

    Ok(())
}

/// Create an AuthDotJson structure from a StoredAccount
fn create_auth_json(account: &StoredAccount) -> Result<AuthDotJson> {
    match &account.auth_data {
        AuthData::ApiKey { key } => Ok(AuthDotJson {
            auth_mode: None,
            openai_api_key: Some(key.clone()),
            tokens: None,
            last_refresh: None,
            agent_identity: None,
            personal_access_token: None,
        }),
        AuthData::ChatGPT {
            id_token,
            access_token,
            refresh_token,
            account_id,
        } => Ok(AuthDotJson {
            auth_mode: None,
            openai_api_key: None,
            tokens: Some(TokenData {
                id_token: id_token.clone(),
                access_token: access_token.clone(),
                refresh_token: refresh_token.clone(),
                account_id: account_id.clone(),
            }),
            last_refresh: Some(Utc::now()),
            agent_identity: None,
            personal_access_token: None,
        }),
        AuthData::CodexAccessToken { token, .. } => Ok(create_access_token_auth_json(token)),
    }
}

fn create_access_token_auth_json(token: &str) -> AuthDotJson {
    let trimmed = token.trim().to_string();
    if trimmed.starts_with("at-") {
        AuthDotJson {
            auth_mode: None,
            openai_api_key: None,
            tokens: None,
            last_refresh: None,
            agent_identity: None,
            personal_access_token: Some(trimmed),
        }
    } else {
        AuthDotJson {
            auth_mode: Some("agentIdentity".to_string()),
            openai_api_key: None,
            tokens: None,
            last_refresh: None,
            agent_identity: Some(serde_json::Value::String(trimmed)),
            personal_access_token: None,
        }
    }
}

fn login_with_codex_access_token(token: &str) -> Result<()> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Codex access token is empty");
    }

    let mut child = Command::new("codex")
        .args(["login", "--with-access-token"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to start Codex CLI. Make sure `codex` is installed and on PATH")?;

    {
        let mut stdin = child
            .stdin
            .take()
            .context("Failed to open Codex CLI stdin")?;
        writeln!(stdin, "{trimmed}").context("Failed to send access token to Codex CLI")?;
    }

    let output = child
        .wait_with_output()
        .context("Failed to wait for Codex CLI login")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("exit status {}", output.status)
        };
        let detail = redact_access_token_from_output(&detail, trimmed);
        anyhow::bail!("Codex access token login failed: {detail}");
    }

    Ok(())
}

fn redact_access_token_from_output(output: &str, token: &str) -> String {
    if token.is_empty() {
        return output.to_string();
    }

    output.replace(token, "[redacted access token]")
}

#[cfg(test)]
mod tests {
    use super::{create_access_token_auth_json, redact_access_token_from_output};

    #[test]
    fn redacts_access_token_from_cli_error_output() {
        let marker = ["sample", "token", "value"].join("-");
        let output = format!("login failed for {marker}");

        assert_eq!(
            redact_access_token_from_output(&output, &marker),
            "login failed for [redacted access token]"
        );
    }

    #[test]
    fn creates_agent_identity_auth_json_for_codex_access_token_jwt() {
        let sample_access_token = ["header", "payload", "signature"].join(".");
        let auth = create_access_token_auth_json(&sample_access_token);

        assert_eq!(auth.auth_mode.as_deref(), Some("agentIdentity"));
        assert_eq!(
            auth.agent_identity
                .as_ref()
                .and_then(|value| value.as_str()),
            Some(sample_access_token.as_str())
        );
        assert!(auth.tokens.is_none());
        assert!(auth.personal_access_token.is_none());
    }
}

/// Import an account from an existing auth.json file
pub fn import_from_auth_json(path: &str, account_name: String) -> Result<StoredAccount> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read auth.json: {path}"))?;

    import_from_auth_json_contents(&content, account_name)
        .with_context(|| format!("Failed to parse auth.json: {path}"))
}

/// Import an account from auth.json file contents.
pub fn import_from_auth_json_contents(
    content: &str,
    account_name: String,
) -> Result<StoredAccount> {
    let auth: AuthDotJson =
        serde_json::from_str(&content).context("Failed to parse auth.json contents")?;

    // Determine auth mode and create account
    if let Some(api_key) = auth.openai_api_key {
        Ok(StoredAccount::new_api_key(account_name, api_key))
    } else if let Some(tokens) = auth.tokens {
        let claims = parse_chatgpt_id_token_claims(&tokens.id_token);

        Ok(StoredAccount::new_chatgpt(
            account_name,
            claims.email,
            claims.plan_type,
            claims.subscription_expires_at,
            tokens.id_token,
            tokens.access_token,
            tokens.refresh_token,
            claims.account_id.or(tokens.account_id),
        ))
    } else if let Some(agent_identity) = auth.agent_identity {
        let token = match agent_identity {
            serde_json::Value::String(token) => token,
            _ => anyhow::bail!("auth.json agent_identity has an unsupported shape"),
        };

        Ok(StoredAccount::new_codex_access_token(account_name, token))
    } else if let Some(personal_access_token) = auth.personal_access_token {
        Ok(StoredAccount::new_codex_access_token(
            account_name,
            personal_access_token,
        ))
    } else {
        anyhow::bail!("auth.json contains neither API key, tokens, nor access-token auth");
    }
}

/// Read the current auth.json file if it exists
pub fn read_current_auth() -> Result<Option<AuthDotJson>> {
    let path = get_codex_auth_file()?;

    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read auth.json: {}", path.display()))?;

    let auth: AuthDotJson = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse auth.json: {}", path.display()))?;

    Ok(Some(auth))
}

/// Check if there is an active Codex login
pub fn has_active_login() -> Result<bool> {
    match read_current_auth()? {
        Some(auth) => Ok(auth.openai_api_key.is_some()
            || auth.tokens.is_some()
            || auth.agent_identity.is_some()
            || auth.personal_access_token.is_some()),
        None => Ok(false),
    }
}
