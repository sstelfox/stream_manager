extern crate actix;
extern crate actix_web;
extern crate base64;
extern crate dotenv;
extern crate env_logger;
extern crate hyper;
extern crate rand;
extern crate ring;
extern crate url;

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;

use actix_web::http::{self, header};
use actix_web::{middleware, server, App, HttpResponse, HttpRequest, Query, Result};
use actix_web::middleware::session::{CookieSessionBackend, SessionStorage, RequestSession};
use dotenv::dotenv;
use url::Url;
use rand::prelude::*;
use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};

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

    // TODO: I may want to use the SystemRandom for this as well, but it's probably fine
    let auth_nonce: String = rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(12).collect();
    // TODO: Need to handle this failure potential
    req.session().set("auth_nonce", auth_nonce.clone())?;

    let mut state = b"signed-data".to_vec();
    // Need to make room for the signature in the structure
    for _ in 0..aead::CHACHA20_POLY1305.tag_len() { state.push(0); }

    let additional_data: [u8; 0] = [];

    // Generate a fresh encryption nonce, this must be separate from the auth_nonce
    let mut nonce = vec![0; 12];
    let rand = SystemRandom::new();
    rand.fill(&mut nonce).unwrap();

    // Generate the key we're going to use for sealing
    let raw_key = req.state().session_key.as_bytes();
    let sealing_key = aead::SealingKey::new(&aead::CHACHA20_POLY1305, &raw_key[..]).unwrap();

    aead::seal_in_place(&sealing_key, &nonce, &additional_data, &mut state, aead::CHACHA20_POLY1305.tag_len()).unwrap();
    let safe_state = base64::encode_config(&state, base64::URL_SAFE_NO_PAD);

    let auth_url = Url::parse_with_params("https://id.twitch.tv/oauth2/authorize",
        &[("client_id", req.state().twitch_client_id.clone()), ("nonce", auth_nonce.to_string()),
          ("redirect_uri", callback_url.as_str().to_string()), ("response_type", "code".to_string()),
          ("scope", "openid channel_editor chat_login".to_string()), ("state", safe_state)]
      )?;

    Ok(HttpResponse::Found()
        .header(header::LOCATION, auth_url.as_str())
        .finish())
}

#[derive(Debug, Deserialize)]
struct CallbackInfo {
    // Error fields

    #[serde(default)]
    error: Option<String>,

    #[serde(default)]
    error_description: Option<String>,

    // Success fields

    #[serde(default)]
    code: Option<String>,

    #[serde(default)]
    scope: Option<String>,

    // Always present

    state: String,
}

fn oauth_callback(_data: Query<CallbackInfo>) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().finish())
}

#[derive(Clone, Debug)]
struct AppState {
    session_key: String,
    twitch_client_id: String,
    twitch_client_secret: String,
}

impl AppState {
    fn from_env() -> AppState {
        AppState {
            session_key: std::env::var("COOKIE_SESSION_KEY").unwrap(),
            twitch_client_id: std::env::var("TWITCH_OAUTH_CLIENT_ID").unwrap(),
            twitch_client_secret: std::env::var("TWITCH_OAUTH_CLIENT_SECRET").unwrap(),
        }
    }
}

fn main() {
    dotenv().ok();
    env_logger::init();

    let state = AppState::from_env();
    let sys = actix::System::new("stream_manager");

    server::new(move || {
        let cloned_state = state.clone();
        let cookie_key = cloned_state.session_key.clone();

        App::with_state(cloned_state)
            .middleware(middleware::Logger::default())
            .middleware(
                SessionStorage::new(
                    CookieSessionBackend::private(&cookie_key.as_bytes())
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
