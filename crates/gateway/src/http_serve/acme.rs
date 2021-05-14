use http::{header::CONTENT_TYPE, Response};
use std::{io, net::SocketAddr, path::PathBuf};
use tokio::{fs::File, io::AsyncReadExt};
use warp::Filter;

pub async fn acme_server(
    webroot: PathBuf,
    listen_http_acme_challenge_addr: SocketAddr,
) -> io::Result<()> {
    let own_acme = warp::path!(".well-known" / "acme-challenge" / String).and_then({
        shadow_clone!(webroot);

        move |token: String| {
            shadow_clone!(webroot);

            async move {
                let filename = format!(".well-known/acme-challenge/{}", token);

                let read_local_file = async {
                    let full_path = webroot.clone().join(&filename);

                    info!("check ACME challenges in {}", full_path.display());
                    let mut file = File::open(full_path).await?;
                    let mut content = String::new();
                    file.read_to_string(&mut content).await?;

                    Ok::<_, io::Error>(content)
                };

                match read_local_file.await {
                    Ok(content) => {
                        info!("validation request successfully served from local folder");
                        Ok(Response::builder()
                            .header(CONTENT_TYPE, "text/plain")
                            .body(content)
                            .unwrap())
                    }
                    Err(_) => {
                        info!("validation request successfully served from local folder");
                        Err(warp::reject::not_found())
                    }
                }
            }
        }
    });

    warp::serve(own_acme)
        .bind(listen_http_acme_challenge_addr)
        .await;

    Ok(())
}
