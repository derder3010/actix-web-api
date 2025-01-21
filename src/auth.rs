use jsonwebtoken::{decode, DecodingKey, Validation, errors::Error};
use serde::{Deserialize, Serialize};
use bcrypt::{hash, verify, DEFAULT_COST};

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
	pub username: String,
	pub exp: usize,
}

pub fn decode_jwt(token: &str) -> Result<Claims, Error> {
	let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
	decode::<Claims>(
		token,
		&DecodingKey::from_secret(secret.as_ref()),
		&Validation::default(),
	)
	.map(|data| data.claims)
}
