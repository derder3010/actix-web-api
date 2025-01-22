use actix_web::{web, App, HttpServer};
use actix_web::middleware::Logger;
use dotenv::dotenv;
mod auth;
mod handlers;
mod models;

#[actix_web::main]
async fn main() -> std::io::Result<()> {

	if std::env::var_os("RUST_LOG").is_none() {
		std::env::set_var("RUST_LOG", "actix_web=info");
	}

    dotenv().ok();
    env_logger::init();

    let mongo_uri = std::env::var("MONGO_URI").expect("MONGO_URI must be set in .env file");
    let client = mongodb::Client::with_uri_str(&mongo_uri).await.unwrap();
    let db = client.database("user_management");

    HttpServer::new(move || {
        App::new()
        	.wrap(Logger::default())
            .app_data(web::Data::new(db.clone()))
            .service(handlers::get_user_by_id)
            .service(handlers::get_me)
            .service(handlers::create_user)
            .service(handlers::login_user)
            .service(handlers::logout_user)
            .service(handlers::update_user)
            .service(handlers::delete_user)
            .service(handlers::delete_all)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
