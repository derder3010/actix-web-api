use actix_web::{get, delete, post, put, web, HttpResponse, Responder};
use mongodb::{bson::{doc, oid::ObjectId}, Database};
use serde_json::json;

use crate::auth::{create_jwt, hash_password, verify_password};
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

#[get("/me")]
pub async fn get_me(
    db: web::Data<Database>,
    req: actix_web::HttpRequest
) -> impl Responder {
     let users = db.collection::<User>("users");

    // Lấy token từ Authorization Header
    let auth_header = req.headers().get("Authorization");
    if auth_header.is_none() {
        return HttpResponse::Unauthorized().json(json!({"error": "Unauthorized: Missing token"}));
    }

    let token = auth_header.unwrap().to_str().unwrap().trim_start_matches("Bearer ");

    // Giải mã token
    let user_id = match crate::auth::decode_jwt(token) {
        Ok(claims) => claims.sub, // Lấy user_id từ token
        Err(_) => return HttpResponse::Unauthorized().json(json!({"error": "Invalid token"})),
    };

    // Convert user_id to ObjectId
    let object_id = match ObjectId::parse_str(&user_id) {
        Ok(oid) => oid,
        Err(_) => return HttpResponse::BadRequest().json(json!({"error": "Invalid user ID format in token"})),
    };

    println!("User's ID: {}", user_id);
    // Tìm người dùng trong cơ sở dữ liệu
    match users.find_one(doc! { "_id": object_id}, None).await {
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

     // Create a new user without manually specifying `_id`
    let new_user = User {
        id: None,
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
                let user_id = u.id.unwrap();
                match create_jwt(&user_id.to_hex(), 3600) {
                    Ok(token) => HttpResponse::Ok().json(json!({"token": token})),
                    Err(_) => HttpResponse::InternalServerError().json(json!({"error": "Failed to generate token"}))
                }
                // HttpResponse::Ok().json(json!({"message": "Login successful"}))
            } else {
                HttpResponse::Unauthorized().json(json!({"error": "Invalid credentials"}))
            }
        }
        Ok(None) => HttpResponse::Unauthorized().json(json!({"error": "Invalid credentials"})),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[post("/logout")]
pub async fn logout_user(
    req: actix_web::HttpRequest,
    db: web::Data<Database>
) -> impl Responder {
    let auth_header = req.headers().get("Authorization");
    if let Some(header_value) = auth_header {
        let token = header_value.to_str().unwrap_or("").trim_start_matches("Bearer ");
        // co them token vao danh sach thu hoi neu can
        let revoked_tokens = db.collection::<mongodb::bson::Document>("revoked_tokens");

        let _ = revoked_tokens
            .insert_one(doc! { "token": token}, None)
            .await;

        HttpResponse::Ok().json(json!({"msg": "Logged out"}))
    } else {
        HttpResponse::Unauthorized().json(json!({"error": "No token provided"}))
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
