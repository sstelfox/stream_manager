extern crate actix;
extern crate actix_web;
extern crate dotenv;
extern crate env_logger;

#[macro_use]
extern crate log;

use actix_web::{http, middleware, server, App, HttpRequest};
use dotenv::dotenv;

fn index(_req: HttpRequest<AppState>) -> &'static str {
    "First page"
}

fn oauth_callback(_req: HttpRequest<AppState>) -> &'static str {
    "{\"status\": \"ok\"}"
}

#[derive(Clone)]
struct AppState;

impl AppState {
    fn new() -> AppState {
        AppState {}
    }
}

fn main() {
    dotenv().ok();
    env_logger::init();

    let sys = actix::System::new("stream_manager");

    let state = AppState::new();
    server::new(
        move || {
            let cloned_state = state.clone();
            App::with_state(cloned_state)
                .middleware(middleware::Logger::default())
                .resource("/", |r| r.method(http::Method::GET).with(index))
                .resource("/oauth/callback", |r| r.method(http::Method::GET).with(oauth_callback))
        })
        .keep_alive(30)
        .bind("127.0.0.1:9292")
        .unwrap()
        .start();

    info!("Starting up http server: 127.0.0.1:9292");
    sys.run();
}
