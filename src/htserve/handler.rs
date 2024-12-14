use {
    flowcontrol::shed,
    http::{
        header::FORWARDED,
        HeaderMap,
        Response,
        StatusCode,
        Uri,
    },
    hyper::{
        body::Incoming,
        service::service_fn,
    },
    hyper_util::rt::{
        TokioExecutor,
        TokioIo,
    },
    loga::{
        Log,
        ResultContext,
    },
    rustls::{
        pki_types::IpAddr,
        server::ResolvesServerCert,
        ServerConfig,
    },
    std::{
        collections::BTreeMap,
        net::SocketAddr,
        sync::Arc,
    },
    tokio::{
        io::{
            AsyncRead,
            AsyncWrite,
        },
        net::TcpStream,
    },
    tokio_rustls::TlsAcceptor,
};

pub struct HandlerArgs<'a> {
    pub peer_addr: SocketAddr,
    /// Zero or more segments preceeded by `/`. Never ends with `/`.
    pub subpath: &'a str,
    /// The query string not including `?`.
    pub query: &'a str,
    pub head: &'a http::request::Parts,
    pub body: Incoming,
}

pub fn get_original_peer_ip(headers: &HeaderMap, direct_peer: IpAddr) -> IpAddr {
    shed!{
        let Some(f) = headers.get("x-forwarded-for") else {
            break;
        };
        let Ok(f) = f.to_str() else {
            break;
        };
        let Ok(addr) = IpAddr::try_from(f.splitn(1, ",").next().unwrap()) else {
            break;
        };
        return addr;
    };
    shed!{
        let Some(f) = headers.get(FORWARDED) else {
            break;
        };
        let Ok(f) = f.to_str() else {
            break;
        };
        for part in f.split(";") {
            let Some((k, v)) = part.split_once("=") else {
                continue;
            };
            if k == "for" {
                if let Ok(addr) = IpAddr::try_from(v) {
                    return addr;
                } else {
                    break;
                }
            }
        }
    };
    return direct_peer;
}

/// Try to reconstruct the original url from the `x-forwarded-host` `-proto`
/// `-prefix` and/or `forwarded: prefix=` headers.
pub fn get_original_base_url(headers: &HeaderMap) -> Option<Uri> {
    let mut proto = None;
    let mut host = None;
    let mut prefix = None;
    shed!{
        let Some(f) = headers.get("x-forwarded-proto") else {
            break;
        };
        let Ok(f) = f.to_str() else {
            break;
        };
        proto = Some(f);
    };
    shed!{
        let Some(f) = headers.get("x-forwarded-host") else {
            break;
        };
        let Ok(f) = f.to_str() else {
            break;
        };
        host = Some(f);
    };
    shed!{
        let Some(f) = headers.get("x-forwarded-prefix") else {
            break;
        };
        let Ok(f) = f.to_str() else {
            break;
        };
        prefix = Some(f);
    };
    shed!{
        let Some(f) = headers.get(FORWARDED) else {
            break;
        };
        let Ok(f) = f.to_str() else {
            break;
        };
        for part in f.split(";") {
            let Some((k, v)) = part.split_once("=") else {
                continue;
            };
            match k {
                "host" => {
                    host = Some(v);
                },
                "proto" => {
                    proto = Some(v);
                },
                "prefix" => {
                    prefix = Some(v);
                },
                _ => { },
            }
        }
    };
    let Some(proto) = proto else {
        return None;
    };
    let Some(host) = host else {
        return None;
    };
    let prefix = prefix.unwrap_or("");
    let Ok(out) = Uri::try_from(format!("{}://{}{}", proto, host, prefix)) else {
        return None;
    };
    return Some(out);
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
            #[
                $crate:: htserve:: handler:: async_trait:: async_trait
            ] impl $crate:: htserve:: handler:: Handler < $o > for Impl {
                async fn handle(
                    &self,
                    $r: $crate:: htserve:: handler:: HandlerArgs < '_ >
                ) -> http:: response:: Response < $o > {
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

fn check_path_router_key(k: &str) -> Result<(), String> {
    if k == "" || (k.starts_with("/") && !k.ends_with("/")) {
        return Ok(());
    } else {
        return Err(
            format!(
                "Router path [{}] doesn't match expected format: it must be an empty string, or else start with / and end with no /",
                k
            ),
        );
    }
}

/// A minimal path-based request router using the `Handler` trait.
pub struct PathRouter<O>(BTreeMap<String, Box<dyn Handler<O>>>);

impl<O> Default for PathRouter<O> {
    fn default() -> Self {
        return Self(Default::default());
    }
}

impl<O> PathRouter<O> {
    pub fn new(routes: BTreeMap<String, Box<dyn Handler<O>>>) -> Result<Self, Vec<String>> {
        let mut errors = vec![];
        for key in routes.keys() {
            if let Err(e) = check_path_router_key(&key) {
                errors.push(e);
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        return Ok(Self(routes));
    }

    pub fn insert(&mut self, key: impl AsRef<str>, handler: Box<dyn Handler<O>>) -> Result<(), String> {
        let key = key.as_ref().to_string();
        if let Err(e) = check_path_router_key(&key) {
            return Err(e)
        }
        self.0.insert(key, handler);
        return Ok(());
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
