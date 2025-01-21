use actix_web::{web, App, HttpServer};
use dotenv::dotenv;
mod auth;
mod handlers;
mod models;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let mongo_uri = std::env::var("MONGO_URI").expect("MONGO_URI must be set in .env file");
    let client = mongodb::Client::with_uri_str(&mongo_uri).await.unwrap();
    let db = client.database("user_management");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))
            .service(handlers::create_user)
            .service(handlers::update_user)
            .service(handlers::delete_user)
            .service(handlers::login_user)
            .service(handlers::delete_all)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
