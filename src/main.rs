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
use actix_web::{middleware, server, App, HttpResponse, HttpRequest, Query, Result, State};
use actix_web::middleware::session::{CookieSessionBackend, SessionStorage, RequestSession};
use dotenv::dotenv;
use url::Url;
use rand::prelude::*;
use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};
use std::error::Error;
use std::fmt;

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

    let encoded_nonce = base64::encode_config(&nonce, base64::URL_SAFE_NO_PAD);

    // Generate the key we're going to use for sealing
    let raw_key = req.state().session_key.as_bytes();
    let sealing_key = aead::SealingKey::new(&aead::CHACHA20_POLY1305, &raw_key[..]).unwrap();

    aead::seal_in_place(&sealing_key, &nonce, &additional_data, &mut state, aead::CHACHA20_POLY1305.tag_len()).unwrap();
    let safe_state = vec![
        encoded_nonce,
        base64::encode_config(&state, base64::URL_SAFE_NO_PAD),
    ].join(".");

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
struct CallbackError {
    error: String,
    error_description: String,
}

#[derive(Debug, Deserialize)]
struct CallbackSuccess {
    code: String,
    scope: String,
}

#[derive(Debug, Deserialize)]
struct CallbackInfo {
    state: String,

    #[serde(default, flatten)]
    error: Option<CallbackError>,

    #[serde(default, flatten)]
    success: Option<CallbackSuccess>,
}

#[derive(Debug)]
enum OAuthError {
    IncorrectComponentCount(usize),

    // TODO could probably collect this more specific error on all of these
    InvalidBase64,
    InvalidStateKey,
    DecryptionFailure,
    InvalidContent,
}

impl Error for OAuthError {
    fn description(&self) -> &str {
        use self::OAuthError::*;

        match *self {
            IncorrectComponentCount(_) => "returned state component had an incorrect number of entries",
            InvalidBase64 => "part of the state had invalid web safe base64",
            InvalidStateKey => "an error occurred generating the key for the state",
            DecryptionFailure => "failed to properly decrypt the state",
            InvalidContent => "decrypted content wasn't good",
        }
    }
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::OAuthError::*;

        match *self {
            IncorrectComponentCount(count) => write!(f, "Returned state had {} components instead of the expected 2", count),
            InvalidBase64 => write!(f, "One of the returned state components wasn't valid web-base64"),
            _ => write!(f, "A weird OAuth error occurred: {}", self.description()),
        }
    }
}

fn decrypt_callback_state(state: &str, key: &[u8]) -> Result<String, OAuthError> {
    let components: Vec<&str> = state.split(".").collect();
    if components.len() != 2 {
        // This app apparently didn't generate the returned state as it has the wrong number of
        // components. There could be a couple of reasons for this, most likely something broke on
        // Twitch's end. Someone could also be enumerating the endpoint to see happens with
        // different changes...
        return Err(OAuthError::IncorrectComponentCount(components.len()));
    }

    let nonce = match base64::decode_config(&components[0], base64::URL_SAFE_NO_PAD) {
        Ok(nonce) => nonce,
        Err(_) => return Err(OAuthError::InvalidBase64),
    };

    let mut enc_data = match base64::decode_config(&components[1], base64::URL_SAFE_NO_PAD) {
        Ok(enc_data) => enc_data,
        Err(_) => return Err(OAuthError::InvalidBase64),
    };

    // TODO: This needs to be more specific
    let opening_key = match aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &key[..]) {
        Ok(key) => key,
        Err(_) => return Err(OAuthError::InvalidStateKey),
    };

    // Unused but mandatory
    let additional_data: [u8; 0] = [];

    let decrypted_state = match aead::open_in_place(&opening_key, &nonce, &additional_data, 0, &mut enc_data) {
        Ok(state) => state,
        Err(_) => return Err(OAuthError::DecryptionFailure),
    };

    match std::str::from_utf8(decrypted_state) {
        Ok(state) => return Ok(String::from(state)),
        Err(_) => return Err(OAuthError::InvalidContent),
    };
}

fn oauth_callback(data: (Query<CallbackInfo>, State<AppState>)) -> Result<HttpResponse> {
    let (callback, app_state) = data;

    let state_string = decrypt_callback_state(&callback.state, app_state.session_key.as_bytes());

    // TODO: when this state is meaningful I should do a better check. This is still useful as it
    // stands now.
    if state_string.unwrap() != "signed-data" {
        // This was malformed, the decryption should have caught any modifications. Replays are
        // possible, but the internal contents should eventually have timestamp and user's session
        // ID in.
        return Ok(HttpResponse::BadRequest().body("This was a bad request. Bad user.\n"));
    }

    if callback.error.is_some() {
        return Ok(HttpResponse::Unauthorized().body("You didn't grant us permission\n"));
    }

    if callback.success.is_some() {
        // Continue handling the request, for now we'll end the back and forth here.
        return Ok(HttpResponse::Ok().body("Everything is all right\n"));
    }

    // This was neither an error or a success, but had at least a 'state' attribute otherwise this
    // handler wouldn't have been called at all.
    Ok(HttpResponse::BadRequest().body("This was a bad request. Bad user.\n"))
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
