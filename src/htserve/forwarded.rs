use {
    crate::url::UriJoin,
    flowcontrol::shed,
    format_bytes::format_bytes,
    http::{
        HeaderMap,
        HeaderValue,
        Uri,
    },
    loga::{
        ea,
        DebugDisplay,
        ResultContext,
    },
    std::{
        borrow::Cow,
        net::{
            IpAddr,
            SocketAddr,
        },
        str::FromStr,
    },
};

pub const FORWARDED_FOR: &str = "X-Forwarded-For";
pub const FORWARDED_PROTO: &str = "X-Forwarded-Proto";
pub const FORWARDED_HOST: &str = "X-Forwarded-Host";
pub const FORWARDED_PATH: &str = "X-Forwarded-Path";

pub struct ForwardedHop<'a> {
    pub for_: Option<(IpAddr, Option<u16>)>,
    pub proto: Option<Cow<'a, [u8]>>,
    pub host: Option<Cow<'a, [u8]>>,
    pub path: Option<Cow<'a, [u8]>>,
}

impl<'a> ForwardedHop<'a> {
    pub fn to_owned(&self) -> ForwardedHop<'static> {
        return ForwardedHop {
            for_: self.for_.clone(),
            proto: self.proto.as_ref().map(|x| Cow::Owned(x.to_vec())),
            host: self.host.as_ref().map(|x| Cow::Owned(x.to_vec())),
            path: self.path.as_ref().map(|x| Cow::Owned(x.to_vec())),
        };
    }

    pub fn uri(&self) -> Result<Uri, loga::Error> {
        let proto = self.proto.as_ref().context("Missing forwarded proto")?;
        let host = self.host.as_ref().clone().context("Missing forwarded host")?;
        let opt_path = Cow::Borrowed(b"" as &[u8]);
        let path = self.path.as_ref().unwrap_or_else(|| &opt_path);
        let uri_str =
            format!(
                "{}://{}{}",
                String::from_utf8(proto.to_vec())
                    .map_err(loga::err)
                    .context_with("Forwarded proto is invalid UTF-8", ea!(proto = String::from_utf8_lossy(proto)))?,
                String::from_utf8(host.to_vec())
                    .map_err(loga::err)
                    .context_with("Forwarded host is invalid UTF-8", ea!(host = String::from_utf8_lossy(host)))?,
                String::from_utf8(path.to_vec())
                    .map_err(loga::err)
                    .context_with("Forwarded path is invalid UTF-8", ea!(path = String::from_utf8_lossy(path)))?
            );
        return Ok(
            Uri::from_str(&uri_str).map_err(loga::err).context_with("Assembled URL is invalid", ea!(url = uri_str))?,
        );
    }
}

pub type Forwarded<'a> = Vec<ForwardedHop<'a>>;

pub fn parse_forwarded_for(v: &HeaderValue) -> Result<Vec<(IpAddr, Option<u16>)>, loga::Error> {
    let v =
        String::from_utf8(v.as_bytes().to_vec())
            .map_err(loga::err)
            .context_with(format!("Invalid UTF-8 in {} header", FORWARDED_FOR), ea!(value = v.dbg_str()))?;
    let mut out = vec![];
    for addr in v.split(',') {
        let addr =
            IpAddr::from_str(
                addr,
            ).context_with(format!("Failed to parse IP address in {} header", FORWARDED_FOR), ea!(addr = addr))?;
        out.push((addr, None));
    }
    return Ok(out);
}

pub fn parse_forwarded<'a>(v: &'a HeaderValue) -> Result<Forwarded<'a>, loga::Error> {
    let mut out = vec![];
    for hop in v.as_bytes().split(|x| *x == b',') {
        let mut r#for = None;
        let mut proto = None;
        let mut host = None;
        let mut path = None;
        for kv in hop.split(|x| *x == b';') {
            let mut kv_splits = kv.splitn(2, |x| *x == b'=');
            let k = kv_splits.next().unwrap().to_ascii_lowercase();
            let Some(mut v) = kv_splits.next() else {
                return Err(loga::err_with("Invalid forwarded kv pair", ea!(pair = String::from_utf8_lossy(kv))));
            };
            if let Some(v1) = v.strip_prefix(b"\"") {
                if let Some(v1) = v1.strip_suffix(b"\"") {
                    v = v1;
                }
            }
            match k.as_slice() {
                b"for" => {
                    if r#for.is_some() {
                        return Err(
                            loga::err_with(
                                "Invalid forwarded header hop, has repeated `for`",
                                ea!(for_ = String::from_utf8_lossy(hop)),
                            ),
                        );
                    }
                    let v =
                        String::from_utf8(v.to_vec())
                            .map_err(loga::err)
                            .context_with(
                                "Invalid utf-8 in forwarded `for`",
                                ea!(hop = String::from_utf8_lossy(hop)),
                            )?;
                    let ip_str;
                    let port_str;
                    if let Some(v) = v.strip_prefix("[") {
                        let Some(v) = v.strip_suffix("]") else {
                            return Err(
                                loga::err_with(
                                    "Invalid forwarded header hop IPv6 `for` brackets",
                                    ea!(hop = String::from_utf8_lossy(hop)),
                                ),
                            );
                        };
                        let mut parts = v.splitn(2, ':');
                        ip_str = parts.next().unwrap();
                        port_str = parts.next();
                    } else {
                        let mut parts = v.splitn(2, ':');
                        ip_str = parts.next().unwrap();
                        port_str = parts.next();
                    }
                    let ip =
                        IpAddr::from_str(
                            ip_str,
                        ).context_with("Invalid IP addr in forwarded `for`", ea!(value = v))?;
                    if let Some(port_str) = port_str {
                        let port =
                            u16::from_str(
                                port_str,
                            ).context_with("Invalid port in forwarded `for`", ea!(value = v))?;
                        r#for = Some((ip, Some(port)));
                    } else {
                        r#for = Some((ip, None));
                    }
                },
                b"proto" => {
                    if proto.is_some() {
                        return Err(
                            loga::err_with(
                                "Invalid forwarded header hop, has repeated `proto`",
                                ea!(hop = String::from_utf8_lossy(&hop)),
                            ),
                        );
                    }
                    proto = Some(Cow::Borrowed(v));
                },
                b"host" => {
                    if host.is_some() {
                        return Err(
                            loga::err_with(
                                "Invalid forwarded header hop, has repeated `host`",
                                ea!(hop = String::from_utf8_lossy(hop)),
                            ),
                        );
                    }
                    host = Some(Cow::Borrowed(v));
                },
                b"path" => {
                    if path.is_some() {
                        return Err(
                            loga::err_with(
                                "Invalid forwarded header hop, has repeated `path`",
                                ea!(hop = String::from_utf8_lossy(hop)),
                            ),
                        );
                    }
                    path = Some(Cow::Borrowed(v));
                },
                _ => { },
            }
        }
        out.push(ForwardedHop {
            for_: r#for,
            proto: proto,
            host: host,
            path: path,
        });
    }
    return Ok(out);
}

pub fn parse_all_forwarded<'a>(headers: &'a mut HeaderMap) -> Result<Forwarded<'a>, loga::Error> {
    let mut separate_for = vec![];
    let mut separate_proto = vec![];
    let mut separate_host = vec![];
    let mut separate_path = vec![];
    while let Some(v) = headers.remove(FORWARDED_FOR) {
        separate_for.extend(parse_forwarded_for(&v)?);
    }
    while let Some(v) = headers.remove(FORWARDED_PROTO) {
        separate_proto.push(v);
    }
    while let Some(v) = headers.remove(FORWARDED_HOST) {
        separate_host.push(v);
    }
    while let Some(v) = headers.remove(FORWARDED_PATH) {
        separate_path.push(v);
    }
    if let Some(v) = headers.remove(http::header::FORWARDED) {
        let mut out = parse_forwarded(&v)?.into_iter().map(|x| x.to_owned()).collect::<Vec<_>>();
        while let Some(v) = headers.remove(http::header::FORWARDED) {
            out.extend(parse_forwarded(&v)?.into_iter().map(|x| x.to_owned()));
        }
        return Ok(out);
    } else {
        let want_len;
        if !separate_for.is_empty() {
            want_len = separate_for.len();
        } else if !separate_proto.is_empty() {
            want_len = separate_proto.len();
        } else if !separate_host.is_empty() {
            want_len = separate_host.len();
        } else if !separate_path.is_empty() {
            want_len = separate_path.len();
        } else {
            return Ok(vec![]);
        }
        if (!separate_for.is_empty() && separate_for.len() != want_len) ||
            (!separate_proto.is_empty() && separate_proto.len() != want_len) ||
            (!separate_host.is_empty() && separate_host.len() != want_len) ||
            (!separate_path.is_empty() && separate_path.len() != want_len) {
            return Err(loga::err("Mismatched x-forwarded header value counts"));
        }
        separate_for.reverse();
        separate_proto.reverse();
        separate_host.reverse();
        separate_path.reverse();
        let mut out = vec![];
        for _ in 0 .. want_len {
            out.push(ForwardedHop {
                for_: separate_for.pop(),
                proto: separate_proto.pop().map(|x| Cow::Owned(x.as_bytes().to_vec())),
                host: separate_host.pop().map(|x| Cow::Owned(x.as_bytes().to_vec())),
                path: separate_path.pop().map(|x| Cow::Owned(x.as_bytes().to_vec())),
            });
        }
        return Ok(out);
    }
}

pub fn parse_forwarded_current<'a>(req_uri: &'a Uri, peer: SocketAddr) -> ForwardedHop<'a> {
    let host;
    match req_uri.authority() {
        Some(authority) => {
            host = authority.as_str().rsplit("@").next();
        },
        None => {
            host = None;
        },
    }
    return ForwardedHop {
        for_: Some((peer.ip(), Some(peer.port()))),
        proto: req_uri.scheme_str().map(|x| Cow::Borrowed(x.as_bytes())),
        host: host.map(|x| Cow::Borrowed(x.as_bytes())),
        path: Some(Cow::Borrowed(req_uri.path().as_bytes())),
    };
}

pub fn add_forwarded(m: &mut HeaderMap, f: &Forwarded) -> Result<(), loga::Error> {
    let mut out = vec![];
    for (hop_i, hop) in f.iter().enumerate() {
        if hop_i > 0 {
            out.extend(b"; ");
        }
        let mut kv_i = 0;
        if let Some((addr, port)) = &hop.for_ {
            out.extend(b"for=");
            match addr {
                IpAddr::V4(addr) => {
                    if let Some(port) = port {
                        out.extend(format_bytes!(b"{}:{}", addr.to_string().into_bytes(), *port));
                    } else {
                        out.extend(format_bytes!(b"{}", addr.to_string().into_bytes()));
                    }
                },
                IpAddr::V6(addr) => {
                    if let Some(port) = port {
                        out.extend(format_bytes!(b"\"[{}]:{}\"", addr.to_string().into_bytes(), *port));
                    } else {
                        out.extend(format_bytes!(b"\"[{}]\"", addr.to_string().into_bytes()));
                    }
                },
            }
            #[allow(unused_assignments)]
            {
                kv_i += 1;
            }
        }
        if let Some(proto) = &hop.proto {
            if kv_i > 0 {
                out.extend(b"; ");
            }
            out.extend(b"proto=");
            out.extend(format_bytes!(b"{}", proto));
            #[allow(unused_assignments)]
            {
                kv_i += 1;
            }
        }
        if let Some(host) = &hop.host {
            if kv_i > 0 {
                out.extend(b"; ");
            }
            out.extend(b"host={}");
            out.extend(format_bytes!(b"{}", host));
            #[allow(unused_assignments)]
            {
                kv_i += 1;
            }
        }
        if let Some(path) = &hop.path {
            if kv_i > 0 {
                out.extend(b"; ");
            }
            out.extend(b"path=");
            out.extend(format_bytes!(b"{}", path));
            #[allow(unused_assignments)]
            {
                kv_i += 1;
            }
        }
    }
    let out_bytes = format_bytes!(b"{}", format_bytes::join(out, b", "));
    m.insert(
        http::header::FORWARDED,
        HeaderValue::from_bytes(
            &out_bytes,
        ).context_with(
            "Forwarded header values produced invalid header",
            ea!(header = String::from_utf8_lossy(&out_bytes)),
        )?,
    );
    return Ok(());
}

pub fn add_x_forwarded(m: &mut HeaderMap, f: &Forwarded) -> Result<(), loga::Error> {
    let mut for_out = vec![];
    for hop in f {
        if let Some((addr, _)) = &hop.for_ {
            for_out.push(addr.to_string());
        }
        if let Some(proto) = &hop.proto {
            m.append(
                FORWARDED_PROTO,
                HeaderValue::from_bytes(
                    &proto,
                ).context_with(
                    "Forwarded proto is invalid as header value",
                    ea!(proto = String::from_utf8_lossy(&proto)),
                )?,
            );
        }
        if let Some(host) = &hop.host {
            m.append(
                FORWARDED_HOST,
                HeaderValue::from_bytes(
                    &host,
                ).context_with(
                    "Forwarded host is invalid as header value",
                    ea!(host = String::from_utf8_lossy(&host)),
                )?,
            );
        }
        if let Some(path) = &hop.path {
            m.append(
                FORWARDED_PATH,
                HeaderValue::from_bytes(
                    &path,
                ).context_with(
                    "Forwarded path is invalid as header value",
                    ea!(path = String::from_utf8_lossy(&path)),
                )?,
            );
        }
    }
    if !for_out.is_empty() {
        let joined = for_out.join(", ");
        m.append(
            FORWARDED_FOR,
            HeaderValue::from_str(
                &joined,
            ).context_with("Forwarded for is invalid as header value", ea!(for_ = joined))?,
        );
    }
    return Ok(());
}

pub fn get_original_peer_ip(forwarded: &Forwarded, current_peer: IpAddr) -> IpAddr {
    shed!{
        let Some(v) = forwarded.iter().next() else {
            break;
        };
        let Some((addr, _)) = v.for_ else {
            break;
        };
        return addr;
    };
    return current_peer;
}

pub fn get_original_base_url(forwarded: &Forwarded, current_subpath: &str) -> Result<Uri, loga::Error> {
    let url = forwarded[0].uri()?;
    return Ok(
        url
            .trim_suffix(current_subpath)
            .context_with(
                "Current subpath isn't a suffix of the original request path; complex rewrites are not supported",
                ea!(original = url),
            )?,
    );
}
