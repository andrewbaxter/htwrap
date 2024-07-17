use {
    chrono::Duration,
    futures::future::join_all,
    hickory_resolver::config::LookupIpStrategy,
    http::header::AUTHORIZATION,
    http_body_util::{
        BodyExt,
        Full,
        Limited,
    },
    hyper::{
        body::Bytes,
        client::conn::http1::{
            Connection,
            SendRequest,
        },
        HeaderMap,
        Request,
        StatusCode,
        Uri,
    },
    hyper_rustls::{
        ConfigBuilderExt,
        HttpsConnectorBuilder,
    },
    loga::{
        ea,
        DebugDisplay,
        Log,
        ResultContext,
    },
    rand::{
        seq::SliceRandom,
        thread_rng,
    },
    rustls::ClientConfig,
    serde::{
        de::DeserializeOwned,
        Serialize,
    },
    std::{
        collections::HashMap,
        net::{
            IpAddr,
            Ipv4Addr,
            Ipv6Addr,
        },
        str::FromStr,
        sync::OnceLock,
    },
    tokio::{
        io::{
            AsyncWrite,
            AsyncWriteExt,
        },
        join,
        select,
        sync::mpsc::{
            self,
            channel,
        },
        time::sleep,
    },
    tower_service::Service,
};

/// Get a once-initialized rustls native roots client config, avoiding scanning the
/// filesystem multiple times.
pub fn default_tls() -> rustls::ClientConfig {
    static S: OnceLock<rustls::ClientConfig> = OnceLock::new();
    return S.get_or_init(move || {
        ClientConfig::builder()
            .with_native_roots()
            .context("Error loading native roots")
            .unwrap()
            .with_no_client_auth()
    }).clone();
}

/// This is a light wrapper around a connection to allow mut-ref access rather than
/// moving.
pub struct Conn<B: 'static + http_body::Body = Full<Bytes>> {
    pub inner: Option<
        (
            SendRequest<B>,
            Connection<hyper_rustls::MaybeHttpsStream<hyper_util::rt::tokio::TokioIo<tokio::net::TcpStream>>, B>,
        ),
    >,
}

impl<B: 'static + http_body::Body> Conn<B> {
    /// For typical use cases you'll want to use `connect()` to create a `Conn`, but if
    /// you're setting up the connection manually you can use this to produce a `Conn`
    /// object.  This takes the return of `hyper::client::conn::http1::handshake`.
    pub fn new(
        c:
            (
                SendRequest<B>,
                Connection<
                    hyper_rustls::MaybeHttpsStream<hyper_util::rt::tokio::TokioIo<tokio::net::TcpStream>>,
                    B,
                >,
            ),
    ) -> Self {
        return Conn { inner: Some(c) };
    }
}

pub enum Host {
    Ip(IpAddr),
    Name(String),
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Ip(i) => return i.fmt(f),
            Host::Name(i) => return i.fmt(f),
        }
    }
}

/// Return the scheme, host, and numeric port from a URI. This should be simple,
/// but it unexpectedly needs some parsing due to the Uri interface.
pub fn uri_parts(url: &Uri) -> Result<(String, Host, u16), loga::Error> {
    let host = url.host().context("Url is missing host")?;
    if host.is_empty() {
        return Err(loga::err("Host portion of url is empty"));
    }
    let host = if host.as_bytes()[0] as char == '[' {
        Host::Ip(
            IpAddr::V6(
                Ipv6Addr::from_str(
                    &String::from_utf8(
                        host.as_bytes()[1..]
                            .split_last()
                            .context("URL ipv6 missing ending ]")?
                            .1
                            .iter()
                            .cloned()
                            .collect(),
                    ).unwrap(),
                ).context("Invalid ipv6 address in URL")?,
            ),
        )
    } else if host.as_bytes().iter().all(|b| (*b as char) == '.' || ('0' ..= '9').contains(&(*b as char))) {
        Host::Ip(IpAddr::V4(Ipv4Addr::from_str(host).context("Invalid ipv4 address in URL")?))
    } else {
        Host::Name(host.to_string())
    };
    let scheme = url.scheme().context("Url is missing scheme")?.to_string();
    let port = match url.port_u16() {
        Some(p) => p,
        None => match scheme.as_str() {
            "http" => 80,
            "https" => 443,
            _ => return Err(loga::err("Only http/https urls are supported")),
        },
    };
    return Ok((scheme, host, port));
}

pub struct Ips {
    pub ipv4s: Vec<IpAddr>,
    pub ipv6s: Vec<IpAddr>,
}

impl From<IpAddr> for Ips {
    fn from(value: IpAddr) -> Self {
        match &value {
            IpAddr::V4(_) => return Ips {
                ipv4s: vec![value],
                ipv6s: vec![],
            },
            IpAddr::V6(_) => return Ips {
                ipv4s: vec![],
                ipv6s: vec![value],
            },
        }
    }
}

/// Resolve ipv4 and ipv6 addresses for a url using hickory.
pub async fn resolve(host: &Host) -> Result<Ips, loga::Error> {
    let mut ipv4s = vec![];
    let mut ipv6s = vec![];
    match host {
        Host::Ip(i) => {
            match i {
                IpAddr::V4(_) => ipv4s.push(*i),
                IpAddr::V6(_) => ipv6s.push(*i),
            };
        },
        Host::Name(host) => {
            let (hickory_config, mut hickory_options) =
                hickory_resolver
                ::system_conf
                ::read_system_conf().context("Error reading system dns resolver config for http request")?;
            hickory_options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
            for ip in hickory_resolver::TokioAsyncResolver::tokio(hickory_config, hickory_options)
                .lookup_ip(&format!("{}.", host))
                .await
                .context("Failed to look up lookup host ip addresses")? {
                match ip {
                    std::net::IpAddr::V4(_) => {
                        ipv4s.push(ip);
                    },
                    std::net::IpAddr::V6(_) => {
                        ipv6s.push(ip);
                    },
                }
            };
        },
    };
    {
        let mut r = thread_rng();
        ipv4s.shuffle(&mut r);
        ipv6s.shuffle(&mut r);
    }
    return Ok(Ips {
        ipv4s: ipv4s,
        ipv6s: ipv6s,
    });
}

/// Create a connection to a host. This does something like "happy eyes" where ipv4
/// and ipv6 connections are attempted in parallel with the first to succeed
/// returned.
pub async fn connect_ips<
    D: hyper::body::Buf + Send,
    E: 'static + std::error::Error + Send + Sync,
    B: 'static + http_body::Body<Data = D, Error = E>,
>(ips: Ips, tls: rustls::ClientConfig, scheme: String, host: Host, port: u16) -> Result<Conn<B>, loga::Error> {
    let mut bg = vec![];
    let (found_tx, mut found_rx) = mpsc::channel(1);
    for ips in [ips.ipv6s, ips.ipv4s] {
        bg.push({
            let found_tx = found_tx.clone();
            let scheme = &scheme;
            let host = &host;
            let tls = tls.clone();
            async move {
                let mut errs = vec![];
                for ip in &ips {
                    let connect = async {
                        return Ok(
                            HttpsConnectorBuilder::new()
                                .with_tls_config(tls.clone())
                                .https_or_http()
                                .with_server_name(host.to_string())
                                .enable_http1()
                                .build()
                                .call(Uri::from_str(&format!("{}://{}:{}", scheme, match ip {
                                    IpAddr::V4(i) => i.to_string(),
                                    IpAddr::V6(i) => format!("[{}]", i),
                                }, port)).unwrap())
                                .await
                                .map_err(
                                    |e| loga::err_with(
                                        "Connection failed",
                                        ea!(err = e.to_string(), dest_addr = ip, host = host, port = port),
                                    ),
                                )?,
                        );
                    };
                    let res = select!{
                        _ = sleep(
                            Duration::try_seconds(10).unwrap().to_std().unwrap()
                        ) => Err(loga::err("Timeout connecting")),
                        res = connect => res,
                    };
                    match res {
                        Ok(conn) => {
                            _ =
                                found_tx.try_send(
                                    Conn::new(
                                        hyper::client::conn::http1::handshake(conn)
                                            .await
                                            .context("Error completing http handshake")?,
                                    ),
                                );
                            return Ok(());
                        },
                        Err(e) => {
                            errs.push(e);
                        },
                    }
                }
                return Err(
                    loga::agg_err_with(
                        "Couldn't establish a connection to any ip in version set",
                        errs,
                        ea!(ips = ips.dbg_str()),
                    ),
                );
            }
        });
    }
    let results = select!{
        results = join_all(bg) => results,
        found = found_rx.recv() => {
            return Ok(found.unwrap());
        }
    };
    if results.is_empty() {
        return Err(loga::err("No addresses found when looking up host"));
    }
    let mut failed = vec![];
    for res in results {
        match res {
            Ok(_) => {
                let found = found_rx.recv().await.unwrap();
                return Ok(found);
            },
            Err(e) => {
                failed.push(e);
            },
        }
    }
    return Err(loga::agg_err("Unable to connect to host", failed));
}

/// Creates a new HTTPS/HTTP connection with default settings.  `base_uri` is just
/// used for schema, host, and port.
pub async fn connect<
    D: hyper::body::Buf + Send,
    E: 'static + std::error::Error + Send + Sync,
    B: 'static + http_body::Body<Data = D, Error = E>,
>(base_url: &Uri) -> Result<Conn<B>, loga::Error> {
    let log = &Log::new().fork(ea!(url = base_url));
    let (scheme, host, port) = uri_parts(base_url).stack_context(log, "Incomplete url")?;
    let ips = resolve(&host).await.stack_context(log, "Error resolving ips for url")?;
    return Ok(
        connect_ips(ips, default_tls(), scheme, host, port)
            .await
            .stack_context(log, "Failed to establish connection")?,
    );
}

/// Like `connect` but with a specified tls config.
pub async fn connect_with_tls<
    D: hyper::body::Buf + Send,
    E: 'static + std::error::Error + Send + Sync,
    B: 'static + http_body::Body<Data = D, Error = E>,
>(base_url: &Uri, tls: rustls::ClientConfig) -> Result<Conn<B>, loga::Error> {
    let log = &Log::new().fork(ea!(url = base_url));
    let (scheme, host, port) = uri_parts(base_url).stack_context(log, "Incomplete url")?;
    let ips = resolve(&host).await.stack_context(log, "Error resolving ips for url")?;
    return Ok(
        connect_ips(ips, tls, scheme, host, port).await.stack_context(log, "Failed to establish connection")?,
    );
}

#[must_use]
pub struct ContinueSend<'a, B: 'static + http_body::Body> {
    body: hyper::body::Incoming,
    conn_send: SendRequest<B>,
    conn_bg: Connection<hyper_rustls::MaybeHttpsStream<hyper_util::rt::TokioIo<tokio::net::TcpStream>>, B>,
    conn: &'a mut Conn<B>,
}

/// Send a request on a connection, return the header and a `ContinueSend` object
/// to continue receiving the response body. If the body isn't consumed, the
/// connection will be closed.
pub async fn send<
    'a,
    D: hyper::body::Buf + Send,
    E: 'static + std::error::Error + Send + Sync,
    B: 'static + http_body::Body<Data = D, Error = E>,
>(
    log: &Log,
    conn: &'a mut Conn<B>,
    max_time: Duration,
    req: Request<B>,
) -> Result<(StatusCode, HeaderMap, ContinueSend<'a, B>), loga::Error> {
    let Some((mut conn_send, mut conn_bg)) = conn.inner.take() else {
        return Err(loga::err("Connection already lost"));
    };
    let method = req.method().to_string();
    let url = req.uri().to_string();
    let read = async move {
        let work = conn_send.send_request(req);
        let resp = select!{
            _ =& mut conn_bg => {
                return Err(loga::err("Connection failed while sending request"));
            }
            r = work => r,
        }.context("Error sending request")?;
        let status = resp.status();
        let headers = resp.headers().clone();
        return Ok((status, headers, ContinueSend {
            body: resp.into_body(),
            conn_send: conn_send,
            conn_bg: conn_bg,
            conn: conn,
        }));
    };
    let (status, headers, continue_send) = select!{
        _ = sleep(max_time.to_std().unwrap()) => {
            return Err(loga::err("Timeout sending request and waiting for headers from server"));
        }
        x = read => x ?,
    };
    log.log_with(
        loga::DEBUG,
        "Receive (streamed)",
        ea!(method = method, url = url, status = status, headers = headers.dbg_str()),
    );
    if !status.is_success() {
        match receive(continue_send, 10 * 1024, Duration::try_seconds(30).unwrap()).await {
            Ok(body) => {
                return Err(
                    loga::err_with(
                        "Server returned error response",
                        ea!(status = status, body = String::from_utf8_lossy(&body)),
                    ),
                );
            },
            Err(e) => {
                let err = loga::err_with("Server returned error response", ea!(status = status));
                return Err(err.also(e));
            },
        }
    }
    return Ok((status, headers, continue_send));
}

/// Stream the response body (returned by `send`) to the provided writer.
pub async fn receive_stream<
    'a,
    D: hyper::body::Buf + Send,
    E: 'static + std::error::Error + Send + Sync,
    B: 'static + http_body::Body<Data = D, Error = E>,
>(mut continue_send: ContinueSend<'a, B>, mut writer: impl Unpin + AsyncWrite) -> Result<(), loga::Error> {
    let (chan_tx, mut chan_rx) = channel(10);
    let work_read = async {
        loop {
            let work = continue_send.body.frame();
            let frame = match select!{
                _ =& mut continue_send.conn_bg => {
                    return Err(loga::err("Connection failed while reading body"));
                }
                r = work => r,
            } {
                Some(f) => {
                    f
                        .map_err(|e| loga::err_with("Error reading response", ea!(err = e)))?
                        .into_data()
                        .map_err(|e| loga::err_with("Received unexpected non-data frame", ea!(err = e.dbg_str())))?
                        .to_vec()
                },
                None => {
                    break;
                },
            };
            chan_tx.send(frame).await.context("Error writing frame to channel for writer")?;
        }
        return Ok(()) as Result<(), loga::Error>;
    };
    let work_write = async {
        while let Some(frame) = chan_rx.recv().await {
            writer.write_all(&frame).await.context("Error sending frame to writer")?;
        }
        return Ok(()) as Result<(), loga::Error>;
    };
    let (read_res, write_res) = join!(work_read, work_write);
    let mut errs = vec![];
    if let Err(e) = read_res {
        errs.push(e);
    }
    if let Err(e) = write_res {
        errs.push(e);
    }
    if !errs.is_empty() {
        return Err(loga::agg_err("Encountered errors while streaming response body", errs));
    }
    continue_send.conn.inner = Some((continue_send.conn_send, continue_send.conn_bg));
    return Ok(());
}

/// Read the entire body into memory, return as a byte vec.
pub async fn receive<
    'a,
    D: hyper::body::Buf + Send,
    E: 'static + std::error::Error + Send + Sync,
    B: 'static + http_body::Body<Data = D, Error = E>,
>(mut continue_send: ContinueSend<'a, B>, max_size: usize, max_time: Duration) -> Result<Vec<u8>, loga::Error> {
    let read = async move {
        let work = Limited::new(continue_send.body, max_size).collect();
        let body = select!{
            _ =& mut continue_send.conn_bg => {
                return Err(loga::err("Connection failed while reading body"));
            }
            r = work => r,
        }.map_err(|e| loga::err_with("Error reading response", ea!(err = e)))?.to_bytes().to_vec();
        return Ok((body, continue_send.conn_send, continue_send.conn_bg));
    };
    let (body, conn_send, conn_bg) = select!{
        _ = sleep(max_time.to_std().unwrap()) => {
            return Err(loga::err("Timeout waiting for response from server"));
        }
        x = read => x ?,
    };
    continue_send.conn.inner = Some((conn_send, conn_bg));
    return Ok(body);
}

/// Send and read the response body into memory as a single call.
pub async fn send_simple<
    D: hyper::body::Buf + Send,
    E: 'static + std::error::Error + Send + Sync,
    B: 'static + http_body::Body<Data = D, Error = E>,
>(
    log: &Log,
    conn: &mut Conn<B>,
    max_size: usize,
    max_time: Duration,
    req: Request<B>,
) -> Result<Vec<u8>, loga::Error> {
    let work = async {
        let (code, _, continue_send) = send(log, conn, max_time, req).await?;
        return Ok((code, receive(continue_send, max_size, max_time).await?)) as
            Result<(StatusCode, Vec<u8>), loga::Error>;
    };
    let (code, body) = select!{
        _ = sleep(max_time.to_std().unwrap()) => {
            return Err(loga::err("Timeout waiting for response from server"));
        }
        x = work => x ?,
    };
    if !code.is_success() {
        return Err(
            loga::err_with("Received invalid status in http response", ea!(body = String::from_utf8_lossy(&body))),
        );
    }
    return Ok(body);
}

/// Send a `POST` request, return body as `Vec<u8>`.
pub async fn post(
    log: &Log,
    conn: &mut Conn,
    url: &Uri,
    headers: &HashMap<String, String>,
    body: Vec<u8>,
    max_size: usize,
) -> Result<Vec<u8>, loga::Error> {
    let req = Request::builder();
    let mut req = req.method("POST").uri(url.clone());
    for (k, v) in headers.iter() {
        req = req.header(k, v);
    }
    log.log_with(
        loga::DEBUG,
        "Send",
        ea!(method = "POST", url = url, headers = req.headers_ref().dbg_str(), body = String::from_utf8_lossy(&body)),
    );
    return Ok(
        send_simple(
            log,
            conn,
            max_size,
            Duration::try_seconds(10).unwrap(),
            req.body(Full::new(Bytes::from(body))).unwrap(),
        )
            .await
            .context_with("Error sending POST", ea!(url = url))?,
    );
}

/// Send a JSON-serializable object and parse a JSON-deserializable object from the
/// response.
pub async fn post_json<
    T: DeserializeOwned,
>(
    log: &Log,
    conn: &mut Conn,
    url: &Uri,
    headers: &HashMap<String, String>,
    body: impl Serialize,
    max_size: usize,
) -> Result<T, loga::Error> {
    let res = post(log, conn, url, headers, serde_json::to_vec(&body).unwrap(), max_size).await?;
    return Ok(serde_json::from_slice(&res).context_with("Error deserializing response as json", ea!(url = url))?);
}

pub fn auth_token_headers(token: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    out.insert(AUTHORIZATION.to_string(), token.to_string());
    return out;
}

/// Make a GET request, return body as `Vec<u8>`.
pub async fn get(
    log: &Log,
    conn: &mut Conn,
    url: &Uri,
    headers: &HashMap<String, String>,
    max_size: usize,
) -> Result<Vec<u8>, loga::Error> {
    let req = Request::builder();
    const METHOD: &'static str = "GET";
    let mut req = req.method(METHOD).uri(url.clone());
    for (k, v) in headers.iter() {
        req = req.header(k, v);
    }
    return Ok(
        send_simple(
            log,
            conn,
            max_size,
            Duration::try_seconds(10).unwrap(),
            req.body(Full::<Bytes>::new(Bytes::new())).unwrap(),
        )
            .await
            .context_with("Error sending GET", ea!(url = url))?,
    );
}

/// Make a GET request, return body as String.
pub async fn get_text(
    log: &Log,
    conn: &mut Conn,
    url: &Uri,
    headers: &HashMap<String, String>,
    max_size: usize,
) -> Result<String, loga::Error> {
    let body = get(log, conn, url, headers, max_size).await?;
    return Ok(
        String::from_utf8(
            body,
        ).map_err(
            |e| loga::err_with(
                "Received data isn't valid utf-8",
                ea!(err = e.to_string(), body = String::from_utf8_lossy(e.as_bytes())),
            ),
        )?,
    );
}

/// Make a GET request and decode body as JSON before returning.
pub async fn get_json<
    T: DeserializeOwned,
>(
    log: &Log,
    conn: &mut Conn,
    url: &Uri,
    headers: &HashMap<String, String>,
    max_size: usize,
) -> Result<T, loga::Error> {
    let res = get(log, conn, url, headers, max_size).await?;
    return Ok(serde_json::from_slice(&res).context_with("Error deserializing response as json", ea!(url = url))?);
}

/// Make a `DELETE` request, return body as `Vec<u8>`.
pub async fn delete(
    log: &Log,
    conn: &mut Conn,
    url: &Uri,
    headers: &HashMap<String, String>,
    max_size: usize,
) -> Result<Vec<u8>, loga::Error> {
    let req = Request::builder();
    const METHOD: &'static str = "DELETE";
    let mut req = req.method(METHOD).uri(url.clone());
    for (k, v) in headers.iter() {
        req = req.header(k, v);
    }
    return Ok(
        send_simple(
            log,
            conn,
            max_size,
            Duration::try_seconds(10).unwrap(),
            req.body(Full::<Bytes>::new(Bytes::new())).unwrap(),
        )
            .await
            .context_with("Error sending DELETE", ea!(url = url))?,
    );
}
