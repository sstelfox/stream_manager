extern crate actix;
extern crate actix_web;
extern crate dotenv;
extern crate env_logger;

#[macro_use]
extern crate log;

use actix_web::{http, middleware, server, App, HttpRequest};
use actix_web::middleware::session::{CookieSessionBackend, SessionStorage, RequestSession};
use dotenv::dotenv;

fn index(req: HttpRequest<AppState>) -> &'static str {
    match req.session().get::<String>("sid") {
        Ok(value) => {
            match value {
                Some(session_id) => {
                    info!("User had session ID value of: {}", session_id);
                }
                _ => {
                    req.session().set("sid", "weeooo")
                        .expect("Unable to set SID");
                }
            }
        }
        _ => {
            error!("Unable to get session value");
        }
    }

    "First page\n"
}

fn oauth_callback(_req: HttpRequest<AppState>) -> &'static str {
    "{\"status\": \"ok\"}\n"
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

    let session_key = std::env::var("COOKIE_SESSION_KEY").unwrap();
    let state = AppState::new();

    let sys = actix::System::new("stream_manager");

    server::new(move || {
        let cloned_state = state.clone();

        App::with_state(cloned_state)
            .middleware(middleware::Logger::default())
            .middleware(
                SessionStorage::new(
                    CookieSessionBackend::private(session_key.as_bytes())
                        .name("sm_ses")
                        // Should be true in production
                        .secure(false)
                )
            )
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
