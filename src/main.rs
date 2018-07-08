extern crate actix;
extern crate actix_web;
extern crate dotenv;
extern crate env_logger;
extern crate hyper;
extern crate rand;
extern crate url;

#[macro_use]
extern crate log;

use actix_web::http::{self, header};
use actix_web::{middleware, server, App, HttpResponse, HttpRequest, Result};
use actix_web::middleware::session::{CookieSessionBackend, SessionStorage, RequestSession};
use dotenv::dotenv;
use url::Url;
use rand::prelude::*;

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

fn login_redirect(req: HttpRequest<AppState>) -> Result<HttpResponse> {
    // TODO: Check if the user is already logged in and choose to redirect them to a reasonable
    // logged in path instead of doing this

    let callback_url = req.url_for_static("callback")?;

    let nonce: String = rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(12).collect();
    // TODO: Need to handle this failure potential
    req.session().set("auth_nonce", nonce.clone())?;

    // TODO: Generate a signed websafe base 64, should include timestamp and
    // user's session ID. Could just be encrypted AEAD preferred.
    let state = "signed-data";

    let auth_url = Url::parse_with_params("https://id.twitch.tv/oauth2/authorize",
        &[("client_id", req.state().twitch_client_id.clone()), ("nonce", nonce.to_string()),
          ("redirect_uri", callback_url.as_str().to_string()), ("response_type", "code".to_string()),
          ("scope", "openid channel_editor chat_login".to_string()), ("state", state.to_string())]
      )?;

    Ok(HttpResponse::Found()
        .header(header::LOCATION, auth_url.as_str())
        .finish())
}

fn oauth_callback(_req: HttpRequest<AppState>) -> &'static str {
    "{\"status\": \"ok\"}\n"
}

#[derive(Clone, Debug)]
struct AppState {
    twitch_client_id: String,
    twitch_client_secret: String,
}

impl AppState {
    fn from_env() -> AppState {
        AppState {
            twitch_client_id: std::env::var("TWITCH_OAUTH_CLIENT_ID").unwrap(),
            twitch_client_secret: std::env::var("TWITCH_OAUTH_CLIENT_SECRET").unwrap(),
        }
    }
}

fn main() {
    dotenv().ok();
    env_logger::init();

    let session_key = std::env::var("COOKIE_SESSION_KEY").unwrap();
    let state = AppState::from_env();

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
            .resource("/login", |r| r.method(http::Method::GET).with(login_redirect))
            .resource("/oauth/callback", |r| {
                r.name("callback");
                r.method(http::Method::GET).with(oauth_callback);
            })
    })
        .keep_alive(30)
        .bind("127.0.0.1:9292")
        .unwrap()
        .start();

    info!("Starting up http server: 127.0.0.1:9292");
    sys.run();
}
