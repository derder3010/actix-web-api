use actix_web::{get, delete, post, put, web, HttpResponse, Responder};
use mongodb::{bson::{doc, oid::ObjectId}, Database};
use serde_json::json;

use crate::auth::{hash_password, verify_password};
use crate::models::{LoginRequest, UpdateUser, User};

#[get("/user/{id}")]
pub async fn get_user_by_id(
    db: web::Data<Database>,
    user_id: web::Path<String>
) -> impl Responder {
    let users = db.collection::<User>("users");

    // Chuyển đổi user_id thành ObjectId
    let object_id = match ObjectId::parse_str(user_id.into_inner()) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest().json(json!({"error": "Invalid user ID"}));
        }
    };

    // Tìm người dùng
    match users.find_one(doc! { "_id": object_id }, None).await {
        Ok(Some(user)) => HttpResponse::Ok().json(user),
        Ok(None) => HttpResponse::NotFound().json(json!({"error": "User not found"})),
        Err(_) => {
            HttpResponse::InternalServerError().json(json!({"error": "Failed to retrieve user"}))
        }
    }
}

#[get("/user/me")]
pub async fn get_me(
    db: web::Data<Database>,
    req: actix_web::HttpRequest
) -> impl Responder {
    let users = db.collection::<User>("users");

    let auth_header = match req.headers().get("Authorization") {
        Some(header) => header.to_str().unwrap_or(""),
        None => {
            return HttpResponse::Unauthorized().json(json!({"error": "Unauthorized"}));
        }
    };

    // Giai ma token de lay username
    let token = auth_header.trim_start_matches("Bearer ");
    let username = match crate::auth::decode_jwt(token) {
        Ok(claims) => claims.username,
        Err(_) => {
            return HttpResponse::Unauthorized().json(json!({"error": "Invalid token"}));
        }
    };

     // Tìm người dùng bằng username
    match users.find_one(doc! { "username": username }, None).await {
        Ok(Some(user)) => HttpResponse::Ok().json(user),
        Ok(None) => HttpResponse::NotFound().json(json!({"error": "User not found"})),
        Err(_) => {
            HttpResponse::InternalServerError().json(json!({"error": "Failed to retrieve user"}))
        }
    }
}

#[post("/create_user")]
pub async fn create_user(db: web::Data<Database>, user: web::Json<User>) -> impl Responder {
    let users = db.collection::<User>("users");

    let hashed_password = match hash_password(&user.password) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let new_user = User {
        username: user.username.clone(),
        email: user.email.clone(),
        password: hashed_password,
    };

    let result = users.insert_one(new_user, None).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(json!({"message": "User created"})),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[post("/login")]
pub async fn login_user(
    db: web::Data<Database>,
    credentials: web::Json<LoginRequest>,
) -> impl Responder {
    let users = db.collection::<User>("users");

    let filter = doc! { "username": &credentials.username };
    let user = users.find_one(filter, None).await;

    match user {
        Ok(Some(u)) => {
            if verify_password(&credentials.password, &u.password).unwrap_or(false) {
                HttpResponse::Ok().json(json!({"message": "Login successful"}))
            } else {
                HttpResponse::Unauthorized().json(json!({"error": "Invalid credentials"}))
            }
        }
        Ok(None) => HttpResponse::Unauthorized().json(json!({"error": "Invalid credentials"})),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[put("/update_user/{username}")]
pub async fn update_user(
    db: web::Data<Database>,
    username: web::Path<String>, // Không giải nén trực tiếp
    updates: web::Json<UpdateUser>,
) -> impl Responder {
    let users = db.collection::<User>("users");
    let username = username.into_inner(); // Lấy giá trị từ Path

    let mut update_doc = doc! {};
    if let Some(email) = &updates.email {
        update_doc.insert("email", email);
    }
    if let Some(password) = &updates.password {
        if let Ok(hashed_password) = hash_password(password) {
            update_doc.insert("password", hashed_password);
        }
    }

    let filter = doc! { "username": username };
    let update = doc! { "$set": update_doc };

    let result = users.update_one(filter, update, None).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(json!({"message": "User updated"})),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[delete("/delete_user/{username}")]
pub async fn delete_user(
    db: web::Data<Database>,
    username: web::Path<String>, // Không giải nén trực tiếp
) -> impl Responder {
    let users = db.collection::<User>("users");
    let username = username.into_inner(); // Lấy giá trị từ Path

    let filter = doc! { "username": username };
    let result = users.delete_one(filter, None).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(json!({"message": "User deleted"})),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[delete("/delete_user/all")]
pub async fn delete_all(db: web::Data<Database>) -> impl Responder {
    let users = db.collection::<User>("users");

    let result = users.delete_many(doc! {}, None).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(json!({"msg": "Deleted all users"})),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
