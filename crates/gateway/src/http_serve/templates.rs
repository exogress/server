use crate::http_serve::auth::github::GithubOauth2Client;
use crate::http_serve::auth::google::GoogleOauth2Client;
use crate::url_mapping::mapping::JwtEcdsa;
use cookie::Cookie;
use exogress_config_core::{Auth, AuthProvider};
use exogress_entities::HandlerName;
use handlebars::Handlebars;
use http::header::{LOCATION, SET_COOKIE};
use hyper::Body;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
use serde_json::json;
use std::convert::TryInto;
use typed_headers::{ContentType, HeaderMapExt};
use url::Url;
use warp::http::StatusCode;
use warp::reply::Response;

const LOGIN_TEMPLATE: &str = include_str!("../../templates/login.html.handlebars");

#[derive(Serialize, Clone, Debug)]
struct ProviderInfo {
    name: String,
    link: String,
}

fn render(url: &Url, requested_url: &Url, handler_name: &HandlerName, auth: &Auth) -> String {
    let mut handlebars = Handlebars::new();

    let mut url = url.clone();

    url.path_segments_mut().unwrap().push("_exg").push("auth");
    url.set_query(Some(
        format!(
            "url={}",
            percent_encode(requested_url.as_str().as_ref(), NON_ALPHANUMERIC)
        )
        .as_str(),
    ));
    url.set_host(Some("strip")).unwrap();
    url.set_scheme("http").unwrap();

    let providers: Vec<_> = auth
        .providers
        .iter()
        .map(|provider| {
            let mut url = url.clone();
            url.query_pairs_mut()
                .append_pair("provider", provider.name.to_string().as_str())
                .append_pair("handler", handler_name.to_string().as_str());

            let link = url
                .to_string()
                .strip_prefix("http://strip")
                .unwrap()
                .to_string();

            ProviderInfo {
                name: provider.name.to_string(),
                link,
            }
        })
        .collect();

    handlebars
        .render_template(LOGIN_TEMPLATE, &json!({ "providers": providers }))
        .unwrap()
}

pub async fn respond_with_login(
    base_url: &Url,
    maybe_provider: &Option<AuthProvider>,
    requested_url: &Url,
    handler_name: &HandlerName,
    auth: &Auth,
    jwt_ecdsa: &JwtEcdsa,
    resp: &mut Response,
    google_oauth2_client: GoogleOauth2Client,
    github_oauth2_client: GithubOauth2Client,
) {
    match maybe_provider {
        None => {
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut()
                .typed_insert::<ContentType>(&ContentType(mime::TEXT_HTML_UTF_8));
            *resp.body_mut() = Body::from(render(base_url, requested_url, handler_name, auth));
        }
        Some(provider) => {
            let redirect_to = match provider {
                AuthProvider::Google => google_oauth2_client
                    .save_state_and_retrieve_authorization_url(
                        &base_url,
                        jwt_ecdsa,
                        requested_url,
                        handler_name,
                    )
                    .await
                    .expect("FIXME"),
                AuthProvider::Github => github_oauth2_client
                    .save_state_and_retrieve_authorization_url(
                        &base_url,
                        jwt_ecdsa,
                        requested_url,
                        handler_name,
                    )
                    .await
                    .expect("FIXME"),
            };

            let delete_cookie = Cookie::build(format!("x-exg-auth-{}", handler_name), "deleted")
                .http_only(true)
                .secure(true)
                .path(base_url.path())
                .expires(time::OffsetDateTime::unix_epoch())
                .finish();

            resp.headers_mut()
                .insert(SET_COOKIE, delete_cookie.to_string().try_into().unwrap());
            resp.headers_mut()
                .insert(LOCATION, redirect_to.try_into().unwrap());
            *resp.status_mut() = StatusCode::TEMPORARY_REDIRECT;
        }
    }
}
