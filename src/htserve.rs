use std::path::Path;
use futures::TryStreamExt;
use http::{
    header::AUTHORIZATION,
    HeaderMap,
    Response,
};
use http_body::Frame;
use http_body_util::{
    combinators::BoxBody,
    BodyExt,
};
use hyper::body::Bytes;
use loga::{
    ea,
    ErrContext,
    ResultContext,
};
use serde::Serialize;
use tokio::{
    fs::File,
    io::{
        AsyncReadExt,
        AsyncSeekExt,
    },
};

pub type Body = BoxBody<Bytes, std::io::Error>;

pub fn body_empty() -> Body {
    return http_body_util::Full::new(Bytes::new())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, ""))
        .boxed();
}

pub fn body_full(data: Vec<u8>) -> Body {
    return http_body_util::Full::new(Bytes::from(data))
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, ""))
        .boxed();
}

pub fn body_json(data: impl Serialize) -> Body {
    return body_full(serde_json::to_vec(&data).unwrap());
}

pub fn response_400(message: impl ToString) -> Response<Body> {
    return Response::builder().status(400).body(body_full(message.to_string().into_bytes())).unwrap();
}

pub fn response_200() -> Response<Body> {
    return Response::builder().status(200).body(body_empty()).unwrap();
}

pub fn response_200_json(v: impl Serialize) -> Response<Body> {
    return Response::builder().status(200).body(body_json(v)).unwrap();
}

pub fn response_404() -> Response<Body> {
    return Response::builder().status(404).body(body_empty()).unwrap();
}

pub fn response_401() -> Response<Body> {
    return Response::builder().status(401).body(body_empty()).unwrap();
}

pub fn response_503() -> Response<Body> {
    return Response::builder().status(503).body(body_empty()).unwrap();
}

pub fn response_503_text(message: impl ToString) -> Response<Body> {
    return Response::builder().status(503).body(body_full(message.to_string().into_bytes())).unwrap();
}

pub fn get_auth_token(headers: &HeaderMap) -> Result<String, loga::Error> {
    const AUTH_PREFIX: &'static str = "Bearer ";
    return Ok(
        headers
            .get(http::header::AUTHORIZATION)
            .context(&format!("Missing {} header", AUTHORIZATION))?
            .to_str()
            .context("Couldn't turn authorization header into string")?
            .strip_prefix(AUTH_PREFIX)
            .context(&format!("Missing {} prefix", AUTH_PREFIX))?
            .to_string(),
    );
}

pub async fn response_file(
    req_headers: &HeaderMap,
    mimetype: &str,
    local_path: &Path,
) -> Result<Response<Body>, loga::Error> {
    let meta1 = match local_path.metadata() {
        Ok(m) => m,
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    return Ok(response_404());
                },
                _ => {
                    return Err(
                        e.context_with("Error opening stored file to read", ea!(path = local_path.to_string_lossy())),
                    );
                },
            }
        },
    };
    let mut file = File::open(&local_path).await?;
    if let Some(ranges) = req_headers.get("Accept-Ranges") {
        let Some(ranges_text) = ranges.to_str() ?.strip_prefix("bytes=") else {
            return Ok(response_400("Ranges missing bytes= prefix"));
        };
        let mut ranges = vec![];
        for range in ranges_text.split(",") {
            let Some((start, end)) = range.trim().split_once("-") else {
                return Ok(response_400("Ranges missing -"));
            };
            let start = if start == "" {
                None
            } else {
                Some(usize::from_str_radix(start, 10)?)
            };
            let end = if end == "" {
                None
            } else {
                let v = usize::from_str_radix(end, 10)?;
                if v == 0 {
                    return Ok(response_400("Zero end range"));
                }
                Some(v + 1)
            };
            let actual_start;
            let actual_end;
            match (start, end) {
                (Some(start), Some(end)) => {
                    actual_start = start;
                    actual_end = end;
                },
                (Some(start), None) => {
                    actual_start = start;
                    actual_end = meta1.len() as usize;
                },
                (None, Some(rev_start)) => {
                    actual_end = meta1.len() as usize;
                    actual_start = actual_end.saturating_sub(rev_start);
                },
                (None, None) => {
                    return Ok(response_400("Invalid range unbounded on both sides"));
                },
            }
            ranges.push((actual_start, actual_end));
        }
        if ranges.len() == 1 {
            let (start, end) = ranges.pop().unwrap();
            file.seek(tokio::io::SeekFrom::Start(start as u64)).await?;
            return Ok(
                Response::builder()
                    .status(206)
                    .header("Accept-Ranges", "bytes")
                    .header("Content-Type", mimetype)
                    .header("Cache-Control", format!("max-age=2147483648,immutable"))
                    .header("Content-Range", format!("bytes {}-{}/{}", start, end - 1, meta1.len()))
                    .header("Content-Length", end - start)
                    .body(
                        http_body_util::StreamBody::new(
                            tokio_util::io::ReaderStream::new(
                                file.take((end - start) as u64),
                            ).map_ok(http_body::Frame::data),
                        ).boxed(),
                    )
                    .unwrap(),
            );
        } else {
            let boundary = "3d6b6a416f9b5";
            let mut content_len = 0;
            let mut ranges2 = vec![];
            for (i, (start, end)) in ranges.into_iter().enumerate() {
                let subheader = format!("{}--{}\nContent-Type: {}\nContent-Range: bytes {}-{}/{}\n\n", if i == 0 {
                    ""
                } else {
                    "\r\n"
                }, boundary, mimetype, start, end - 1, meta1.len()).into_bytes();
                content_len += subheader.len() + (end - start);
                ranges2.push((start, end, subheader));
            }
            let ranges = ranges2;
            let footer = format!("\r\n--{}--", boundary).into_bytes();
            content_len += footer.len();
            return Ok(
                Response::builder()
                    .status(206)
                    .header("Accept-Ranges", "bytes")
                    .header("Content-Type", format!("multipart/byteranges; boundary={boundary}"))
                    .header("Content-Length", content_len)
                    .body(BoxBody::new(http_body_util::StreamBody::new(async_stream::try_stream!{
                        for (start, end, subheader) in ranges {
                            yield Frame::data(Bytes::from(subheader));
                            file.seek(tokio::io::SeekFrom::Start(start as u64)).await?;
                            let mut remaining = end - start;
                            while remaining > 0 {
                                let mut buf = vec![];
                                let subchunk_len = (8 * 1024 * 1024).min(remaining);
                                buf.resize(subchunk_len, 0);
                                file.read(&mut buf).await?;
                                remaining -= subchunk_len;
                                yield Frame::data(Bytes::from(buf));
                            }
                        }
                        yield Frame::data(Bytes::from(footer));
                    })))
                    .unwrap(),
            );
        }
    } else {
        return Ok(
            Response::builder()
                .status(200)
                .header("Accept-Ranges", "bytes")
                .header("Content-Type", mimetype)
                .header("Cache-Control", format!("max-age=2147483648,immutable"))
                .header("Content-Length", meta1.len().to_string())
                .body(
                    http_body_util::StreamBody::new(
                        tokio_util::io::ReaderStream::new(file).map_ok(Frame::data),
                    ).boxed(),
                )
                .unwrap(),
        );
    }
}
