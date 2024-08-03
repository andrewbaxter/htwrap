use {
    futures::{
        TryStreamExt,
    },
    http::{
        header::AUTHORIZATION,
        HeaderMap,
        Response,
        StatusCode,
    },
    http_body::Frame,
    http_body_util::{
        combinators::BoxBody,
        BodyExt,
    },
    hyper::{
        body::{
            Bytes,
            Incoming,
        },
        service::service_fn,
    },
    hyper_util::rt::{
        TokioExecutor,
        TokioIo,
    },
    loga::{
        ea,
        ErrContext,
        Log,
        ResultContext,
    },
    rustls::{
        server::ResolvesServerCert,
        ServerConfig,
    },
    serde::Serialize,
    std::{
        collections::BTreeMap,
        net::SocketAddr,
        path::Path,
        sync::Arc,
    },
    tokio::{
        fs::File,
        io::{
            AsyncRead,
            AsyncReadExt,
            AsyncSeekExt,
            AsyncWrite,
        },
        net::TcpStream,
    },
    tokio_rustls::TlsAcceptor,
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

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct AuthTokenHash(sha2::digest::Output<sha2::Sha256>);

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

pub fn hash_auth_token(s: &str) -> AuthTokenHash {
    return AuthTokenHash(<sha2::Sha256 as sha2::Digest>::digest(s.as_bytes()));
}

pub fn check_auth_token_hash(want: &AuthTokenHash, got: &str) -> bool {
    return &hash_auth_token(got) == want;
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
        let Some(ranges_text) = ranges.to_str()?.strip_prefix("bytes=") else {
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

pub struct HandlerArgs<'a> {
    pub peer_addr: SocketAddr,
    /// Zero or more segments preceeded by `/`. Never ends with `/`.
    pub subpath: &'a str,
    /// The query string not including `?`.
    pub query: &'a str,
    pub head: &'a http::request::Parts,
    pub body: Incoming,
}

/// A generic http request handler trait to ease composition.
#[async_trait::async_trait]
pub trait Handler<O>: 'static + Send + Sync {
    async fn handle(&self, args: HandlerArgs<'_>) -> Response<O>;
}

/// Republish for `handler` macro
pub use async_trait;

/// Build a handler from captured values and a body.
#[macro_export]
macro_rules! handler{
    (($($i: ident: $it: ty), *)($r: ident -> $o: ty) $b: expr) => {
        {
            struct Impl {
                $($i: $it,) *
            };
            #[$crate:: htserve:: async_trait:: async_trait] impl $crate:: htserve:: Handler < $o > for Impl {
                async fn handle(&self, $r: $crate:: htserve:: HandlerArgs < '_ >) -> http:: response:: Response < $o > {
                    $(let $i =& self.$i;) * 
                    //. .
                    $b
                }
            }
            Impl {
                $($i: $i.clone()),
                *
            }
        }
    };
}

fn check_path_router_key(k: &str) -> bool {
    return k == "" || (k.starts_with("/") && !k.ends_with("/"));
}

/// A minimal path-based request router using the `Handler` trait.
pub struct PathRouter<O>(BTreeMap<String, Box<dyn Handler<O>>>);

impl<O> Default for PathRouter<O> {
    fn default() -> Self {
        return Self(Default::default());
    }
}

impl<O> PathRouter<O> {
    pub fn new(routes: BTreeMap<String, Box<dyn Handler<O>>>) -> Self {
        assert!(routes.keys().all(|x| check_path_router_key(&x)));
        return Self(routes);
    }

    pub fn insert(&mut self, key: impl AsRef<str>, handler: Box<dyn Handler<O>>) {
        let key = key.as_ref().to_string();
        assert!(check_path_router_key(&key));
        self.0.insert(key, handler);
    }
}

#[async_trait::async_trait]
impl<O: 'static + Send + Default> Handler<O> for PathRouter<O> {
    async fn handle(&self, args: HandlerArgs<'_>) -> Response<O> {
        let Some((prefix, subhandler)) = self.0.range(..=args.subpath.to_string()).rev().next() else {
            return Response::builder().status(StatusCode::NOT_FOUND).body(Default::default()).unwrap();
        };
        let Some(subpath) = args.subpath.strip_prefix(prefix) else {
            return Response::builder().status(StatusCode::NOT_FOUND).body(Default::default()).unwrap();
        };
        return subhandler.handle(HandlerArgs {
            peer_addr: args.peer_addr,
            subpath: subpath,
            query: args.query,
            head: args.head,
            body: args.body,
        }).await;
    }
}

pub fn root_handle_http_inner<
    I: 'static + Send + AsyncRead + AsyncWrite + Unpin,
    OD: 'static + Send,
    OE: 'static + Send + Sync + std::error::Error,
    O: 'static + Send + http_body::Body<Data = OD, Error = OE>,
>(log: &Log, peer_addr: SocketAddr, stream: I, handler: Arc<dyn Handler<O>>) {
    let log = log.clone();
    tokio::task::spawn(async move {
        match async {
            hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service_fn({
                    move |req| {
                        let handler = handler.clone();
                        async move {
                            let (head, body) = req.into_parts();
                            let path;
                            let query;
                            match head.uri.path_and_query() {
                                Some(pq) => {
                                    path = pq.path().trim_end_matches('/');
                                    query = pq.query().unwrap_or_default();
                                },
                                None => {
                                    path = "";
                                    query = "";
                                },
                            }
                            return Ok(handler.handle(HandlerArgs {
                                peer_addr: peer_addr,
                                subpath: path,
                                query: query,
                                head: &head,
                                body: body,
                            }).await) as Result<_, std::io::Error>;
                        }
                    }
                }))
                .await
                .map_err(|_| loga::err("Unknown error serving connection"))?;
            return Ok(()) as Result<(), loga::Error>;
        }.await {
            Ok(_) => (),
            Err(e) => {
                log.log_err(loga::DEBUG, e.context("Error serving connection"));
            },
        }
    });
}

pub async fn root_handle_http<
    OD: 'static + Send,
    OE: 'static + Send + Sync + std::error::Error,
    O: 'static + Send + http_body::Body<Data = OD, Error = OE>,
>(log: &Log, handler: Arc<dyn Handler<O>>, stream: TcpStream) -> Result<(), loga::Error> {
    match async {
        let peer_addr = stream.peer_addr().context("Error getting connection peer address")?;
        root_handle_http_inner(log, peer_addr, stream, handler);
        return Ok(()) as Result<_, loga::Error>;
    }.await {
        Ok(_) => (),
        Err(e) => {
            log.log_err(loga::DEBUG, e.context("Error setting up connection"));
        },
    }
    return Ok(());
}

pub fn tls_acceptor(certs: Arc<dyn ResolvesServerCert>) -> TlsAcceptor {
    return TlsAcceptor::from(Arc::new({
        let mut server_config = ServerConfig::builder().with_no_client_auth().with_cert_resolver(certs);
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
        server_config
    }));
}

pub async fn root_handle_https<
    OD: 'static + Send,
    OE: 'static + Send + Sync + std::error::Error,
    O: 'static + Send + http_body::Body<Data = OD, Error = OE>,
>(
    log: &Log,
    tls_acceptor: TlsAcceptor,
    handler: Arc<dyn Handler<O>>,
    stream: TcpStream,
) -> Result<(), loga::Error> {
    match async {
        let peer_addr = stream.peer_addr().context("Error getting connection peer address")?;
        root_handle_http_inner(
            log,
            peer_addr,
            tls_acceptor.accept(stream).await.context("Error establishing TLS connection")?,
            handler,
        );
        return Ok(()) as Result<_, loga::Error>;
    }.await {
        Ok(_) => (),
        Err(e) => {
            log.log_err(loga::DEBUG, e.context("Error setting up connection"));
        },
    }
    return Ok(());
}
