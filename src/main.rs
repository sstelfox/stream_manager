extern crate actix;
extern crate actix_web;
extern crate base64;
extern crate dotenv;
extern crate env_logger;
extern crate hyper;
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
use ring::aead::{open_in_place, seal_in_place, CHACHA20_POLY1305, OpeningKey, SealingKey};
use ring::rand::{SecureRandom, SystemRandom};
use std::convert::From;
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

fn rand_nonce() -> [u8; 12] {
    let rand = SystemRandom::new();
    let mut nonce: [u8; 12] = [0; 12];

    if let Err(_e) = rand.fill(&mut nonce) {
        panic!("No entropy is available for nonce generation");
    }

    nonce
}

fn login_redirect(req: HttpRequest<AppState>) -> Result<HttpResponse> {
    // TODO: Check if the user is already logged in and choose to redirect them to a reasonable
    // logged in path instead of doing this

    let callback_url = req.url_for_static("callback")?;

    // Unique identifier for this user's browser session, will be used for the lifetime of the
    // browser's login session
    let session_id = rand_nonce();
    let session_id = base64::encode_config(&session_id, base64::URL_SAFE_NO_PAD);
    if let Err(e) = req.session().set("sid", session_id) {
        error!("Unable to set the session ID: {}", e);
        return Ok(HttpResponse::InternalServerError().finish());
    }

    // Nonce used to validate the final user token is being connected to the browser session that
    // initially requested and was redirected to the authentication endpoint.
    let nonce = rand_nonce();
    let nonce = base64::encode_config(&nonce, base64::URL_SAFE_NO_PAD);
    if let Err(e) = req.session().set("auth_nonce", nonce.clone()) {
        error!("Unable to set the auth_nonce on the session: {}", e);
        return Ok(HttpResponse::InternalServerError().finish());
    }

    // Generate some information we can use to ensure we don't hand out session identifiers to
    // other browsers.
    let _int_state = InternalState {
        address: req.connection_info().remote().unwrap().to_string(),
        session_id: req.session().get::<String>("sid").unwrap().unwrap(),
    };

    // Pull in the key we're going to use for sealing
    let raw_key = req.state().session_key.as_bytes();

    let safe_state = match encrypt_callback_state("signed-data", &raw_key) {
        Ok(state) => state,
        Err(e) => {
            error!("Unable to encrypt the callback state: {}", e);
            return Ok(HttpResponse::InternalServerError().finish());
        }
    };

    let auth_url = Url::parse_with_params("https://id.twitch.tv/oauth2/authorize",
        &[("client_id", req.state().twitch_client_id.clone()), ("nonce", nonce),
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

#[derive(Debug, Deserialize, Serialize)]
struct InternalState {
    address: String,
    session_id: String,
}

#[derive(Debug)]
enum OAuthError {
    DecryptionFailure,
    EncryptionFailure,
    IncorrectComponentCount(usize),
    InvalidBase64(base64::DecodeError),
    InvalidContent,
    InvalidStateKey,
}

impl Error for OAuthError {
    fn description(&self) -> &str {
        use self::OAuthError::*;

        match *self {
            DecryptionFailure => "failed to authenticate or decrypt the state",
            EncryptionFailure => "failed to encrypt the provided state",
            IncorrectComponentCount(_) => "returned state component had an incorrect number of entries",
            InvalidBase64(_) => "the state had invalid base64",
            InvalidStateKey => "an error occurred building the state encryption key",
            InvalidContent => "decrypted bytes couldn't be converted to a valid string",
        }
    }
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl From<base64::DecodeError> for OAuthError {
    fn from(err: base64::DecodeError) -> OAuthError {
        OAuthError::InvalidBase64(err)
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
        Err(e) => return Err(OAuthError::from(e)),
    };

    let mut enc_data = match base64::decode_config(&components[1], base64::URL_SAFE_NO_PAD) {
        Ok(enc_data) => enc_data,
        Err(e) => return Err(OAuthError::from(e)),
    };

    // The ring crate does not provide a specific error implementation so we don't need to be more
    // specific than this.
    let opening_key = match OpeningKey::new(&CHACHA20_POLY1305, &key[..]) {
        Ok(key) => key,
        Err(_) => return Err(OAuthError::InvalidStateKey),
    };

    let decrypted_state = match open_in_place(&opening_key, &nonce, &[], 0, &mut enc_data) {
        Ok(state) => state,
        Err(_) => return Err(OAuthError::DecryptionFailure),
    };

    match std::str::from_utf8(decrypted_state) {
        Ok(state) => return Ok(String::from(state)),
        Err(_) => return Err(OAuthError::InvalidContent),
    };
}

fn encrypt_callback_state(state: &str, key: &[u8]) -> Result<String, OAuthError> {
    let nonce = rand_nonce();
    let encoded_nonce = base64::encode_config(&nonce, base64::URL_SAFE_NO_PAD);

    let mut padded_state = state.as_bytes().to_vec();
    for _ in 0..CHACHA20_POLY1305.tag_len() { padded_state.push(0); }

    let sealing_key = match SealingKey::new(&CHACHA20_POLY1305, &key) {
        Ok(key) => key,
        Err(_) => return Err(OAuthError::InvalidStateKey),
    };

    if let Err(_) = seal_in_place(&sealing_key, &nonce, &[], &mut padded_state, CHACHA20_POLY1305.tag_len()) {
        return Err(OAuthError::EncryptionFailure);
    };

    let safe_state = vec![
        encoded_nonce,
        base64::encode_config(&padded_state, base64::URL_SAFE_NO_PAD),
    ].join(".");

    Ok(safe_state)
}

fn oauth_callback((callback, app_state): (Query<CallbackInfo>, State<AppState>)) -> Result<HttpResponse> {
    let state_string = match decrypt_callback_state(&callback.state, app_state.session_key.as_bytes()) {
        Ok(state_string) => state_string,
        Err(e) => {
            error!("Failed to decrypt callback state: {}", e);
            return Ok(HttpResponse::BadRequest().body("This was a bad request. Bad user.\n"));
        }
    };

    // TODO: when this state is meaningful I should do a better check. This is still useful as it
    // stands now.
    if state_string != "signed-data" {
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
