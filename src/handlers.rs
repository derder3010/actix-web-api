use actix_web::{delete, post, put, web, HttpResponse, Responder};
use mongodb::{bson::doc, Database};
use serde_json::json;

use crate::auth::{hash_password, verify_password};
use crate::models::{LoginRequest, UpdateUser, User};

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
