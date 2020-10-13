use crate::mime_helpers::{is_mime_match, ordered_by_quality};
use chrono::Utc;
use exogress_config_core::{RawResponse, RedirectResponse, StaticResponse, TemplateEngine};
use handlebars::Handlebars;
use http::header::LOCATION;
use http::Response;
use hyper::Body;
use typed_headers::{Accept, ContentType, HeaderMapExt};

#[derive(thiserror::Error, Debug)]
pub enum StaticResponseError {
    #[error("can't satisfy Accept header")]
    NotAcceptable,

    #[error("handlebars render template error: {_0}")]
    Handlebars(#[from] handlebars::TemplateRenderError),

    #[error("invalid HTTP header: {_0}")]
    InvalidHeader(#[from] http::header::InvalidHeaderValue),
}

pub trait StaticResponseExt {
    fn try_respond(
        &self,
        accept: &Accept,
        response: &mut Response<Body>,
    ) -> Result<(), StaticResponseError>;
}

impl StaticResponseExt for StaticResponse {
    fn try_respond(
        &self,
        accept: &Accept,
        http_response: &mut Response<Body>,
    ) -> Result<(), StaticResponseError> {
        match self {
            StaticResponse::Redirect(RedirectResponse {
                redirect_type,
                destination,
                common,
            }) => {
                let status_code = redirect_type.status_code();
                *http_response.body_mut() = Body::from(String::new());
                *http_response.status_mut() = status_code;
                for (k, v) in &common.headers {
                    http_response.headers_mut().append(k, v.clone());
                }
                http_response
                    .headers_mut()
                    .insert(LOCATION, destination.as_str().parse()?);
            }
            StaticResponse::Raw(RawResponse {
                status_code,
                body,
                common,
            }) => {
                if !body.is_empty() {
                    let (resp_content_type, resp) = ordered_by_quality(accept)
                        .filter_map(|mime_pattern| {
                            body.iter()
                                .filter_map(|resp_candidate| {
                                    Some((
                                        resp_candidate.content_type.as_str().parse().ok()?,
                                        resp_candidate,
                                    ))
                                })
                                .find(|(content_type, _resp_candidate)| {
                                    is_mime_match(mime_pattern, &content_type)
                                })
                        })
                        .next()
                        .ok_or(StaticResponseError::NotAcceptable)?;

                    http_response
                        .headers_mut()
                        .typed_insert::<ContentType>(&ContentType(resp_content_type.clone()));

                    let body = match &resp.engine {
                        None => resp.content.clone(),

                        Some(TemplateEngine::Handlebars) => {
                            let handlebars = Handlebars::new();
                            let data = hashmap! {
                                "time" => Utc::now()
                            };
                            handlebars.render_template(&resp.content, &data)?
                        }
                    };

                    *http_response.body_mut() = Body::from(body);
                }

                *http_response.status_mut() = status_code.clone();

                for (k, v) in &common.headers {
                    http_response.headers_mut().append(k, v.clone());
                }
            }
        }
        Ok(())
    }
}
