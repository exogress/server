use crate::http_serve::auth::{
    github::GithubOauth2Client, google::GoogleOauth2Client, JwtEcdsa, Oauth2Provider,
};
use cookie::Cookie;
use exogress_common::entities::{url_prefix::MountPointBaseUrl, HandlerName};
use handlebars::Handlebars;
use http::{
    header::{LOCATION, SET_COOKIE},
    Response, StatusCode,
};
use hyper::Body;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
use serde_json::json;
use std::convert::TryInto;
use typed_headers::{ContentType, HeaderMapExt};
use url::Url;

const LOGIN_TEMPLATE: &str = include_str!("../../templates/login.html.handlebars");
const LIMIT_REACHED_TEMPLATE: &str = include_str!("../../templates/limit-reached.html.handlebars");

#[derive(Serialize, Clone, Debug)]
struct ProviderInfo {
    name: String,
    display_name: String,
    link: String,
}

pub fn render_limit_reached() -> String {
    let handlebars = Handlebars::new();

    handlebars
        .render_template(LIMIT_REACHED_TEMPLATE, &json!({}))
        .unwrap()
}

fn render_login(
    mount_point_base_url: &MountPointBaseUrl,
    requested_url: &Url,
    handler_name: &HandlerName,
    auth: &[Oauth2Provider],
) -> String {
    let handlebars = Handlebars::new();

    let mut url = mount_point_base_url.to_url();

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
        .iter()
        .map(|provider| {
            let mut url = url.clone();
            url.query_pairs_mut()
                .append_pair("provider", provider.to_string().as_str())
                .append_pair("handler", handler_name.to_string().as_str());

            let link = url
                .to_string()
                .strip_prefix("http://strip")
                .unwrap()
                .to_string();

            ProviderInfo {
                name: provider.to_string(),
                display_name: provider.display_name(),
                link,
            }
        })
        .collect();

    handlebars
        .render_template(LOGIN_TEMPLATE, &json!({ "providers": providers }))
        .unwrap()
}

pub async fn respond_with_login(
    res: &mut Response<Body>,
    base_url: &MountPointBaseUrl,
    provided_oauth2_provider: &Option<Oauth2Provider>,
    requested_url: &Url,
    handler_name: &HandlerName,
    auth: &[Oauth2Provider],
    jwt_ecdsa: &JwtEcdsa,
    google_oauth2_client: &GoogleOauth2Client,
    github_oauth2_client: &GithubOauth2Client,
) {
    match provided_oauth2_provider {
        None => {
            *res.status_mut() = StatusCode::OK;
            res.headers_mut()
                .typed_insert::<ContentType>(&ContentType(mime::TEXT_HTML_UTF_8));
            *res.body_mut() = Body::from(render_login(base_url, requested_url, handler_name, auth));
        }
        Some(provider) => {
            let redirect_to = match provider {
                Oauth2Provider::Google => google_oauth2_client
                    .save_state_and_retrieve_authorization_url(
                        &base_url,
                        jwt_ecdsa,
                        requested_url,
                        handler_name,
                    )
                    .await
                    .expect("FIXME"),
                Oauth2Provider::Github => github_oauth2_client
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

            res.headers_mut()
                .insert(SET_COOKIE, delete_cookie.to_string().try_into().unwrap());
            res.headers_mut()
                .insert(LOCATION, redirect_to.try_into().unwrap());
            *res.status_mut() = StatusCode::TEMPORARY_REDIRECT;
        }
    }
}
