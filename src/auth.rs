use jsonwebtoken::{ encode, decode, DecodingKey, Validation, errors::Error, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use bcrypt::{hash, verify, DEFAULT_COST};
use std::time::{SystemTime, UNIX_EPOCH};
use mongodb::bson::doc;

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
	pub sub: String,
	pub exp: usize,
}

pub fn create_jwt(
	user_id: &str,
	expiry_seconds: usize
) -> Result<String, Error> {
	let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
	let exp = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("Time went backwards")
		.as_secs() as usize
		+ expiry_seconds;

	let claims = Claims {
		sub: user_id.to_owned(),
		exp,
	};

	encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
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
