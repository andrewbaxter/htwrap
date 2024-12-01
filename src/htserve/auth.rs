use {
    crate::constants::HEADER_BEARER_PREFIX,
    http::{
        header::AUTHORIZATION,
        HeaderMap,
    },
    loga::ResultContext,
};

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct AuthTokenHash(sha2::digest::Output<sha2::Sha256>);

pub fn get_auth_token(headers: &HeaderMap) -> Result<String, loga::Error> {
    return Ok(
        headers
            .get(http::header::AUTHORIZATION)
            .context(&format!("Missing {} header", AUTHORIZATION))?
            .to_str()
            .context("Couldn't turn authorization header into string")?
            .strip_prefix(HEADER_BEARER_PREFIX)
            .context(&format!("Missing {} prefix", HEADER_BEARER_PREFIX))?
            .to_string(),
    );
}

pub fn hash_auth_token(s: &str) -> AuthTokenHash {
    return AuthTokenHash(<sha2::Sha256 as sha2::Digest>::digest(s.as_bytes()));
}

pub fn check_auth_token_hash(want: &AuthTokenHash, got: &str) -> bool {
    return &hash_auth_token(got) == want;
}
