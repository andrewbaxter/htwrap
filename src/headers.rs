use {
    format_bytes::format_bytes,
    http::{
        HeaderMap,
        HeaderValue,
        Uri,
    },
    std::{
        borrow::Cow,
        net::IpAddr,
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

    pub fn uri(&self) -> Result<Uri, String> {
        let proto = self.proto.as_ref().ok_or_else(|| "Missing forwarded proto".to_string())?;
        let host = self.host.as_ref().clone().ok_or_else(|| "Missing forwarded host".to_string())?;
        let opt_path = Cow::Borrowed(b"" as &[u8]);
        let path = self.path.as_ref().unwrap_or_else(|| &opt_path);
        let uri_str =
            format!(
                "{}://{}{}",
                String::from_utf8(
                    proto.to_vec(),
                ).map_err(
                    |e| format!("Forwarded proto is invalid UTF-8 [{}]: {}", String::from_utf8_lossy(&proto), e),
                )?,
                String::from_utf8(
                    host.to_vec(),
                ).map_err(
                    |e| format!("Forwarded host is invalid UTF-8 [{}]: {}", String::from_utf8_lossy(&host), e),
                )?,
                String::from_utf8(
                    path.to_vec(),
                ).map_err(
                    |e| format!("Forwarded path is invalid UTF-8 [{}]: {}", String::from_utf8_lossy(&path), e),
                )?
            );
        return Ok(
            Uri::from_str(
                &uri_str,
            ).map_err(|e| format!("Assembled forwarding information [{}] produced invalid URI: {}", uri_str, e))?,
        );
    }
}

pub type Forwarded<'a> = Vec<ForwardedHop<'a>>;

pub fn parse_forwarded_for(v: &HeaderValue) -> Result<Vec<(IpAddr, Option<u16>)>, String> {
    let v =
        String::from_utf8(
            v.as_bytes().to_vec(),
        ).map_err(
            |e| format!(
                "Invalid UTF-8 in {} header [{}]: {}",
                FORWARDED_FOR,
                String::from_utf8_lossy(v.as_bytes()),
                e
            ),
        )?;
    let mut out = vec![];
    for addr in v.split(',') {
        let addr =
            IpAddr::from_str(
                addr,
            ).map_err(|e| format!("Failed to parse IP address in {} header [{}]: {}", FORWARDED_FOR, addr, e))?;
        out.push((addr, None));
    }
    return Ok(out);
}

pub fn parse_forwarded<'a>(v: &'a HeaderValue) -> Result<Forwarded<'a>, String> {
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
                return Err(format!("Invalid forwarded kv pair: [{}]", String::from_utf8_lossy(kv)));
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
                            format!(
                                "Invalid forwarded header hop, has repeated `for`: [{}]",
                                String::from_utf8_lossy(hop)
                            ),
                        );
                    }
                    let v =
                        String::from_utf8(
                            v.to_vec(),
                        ).map_err(
                            |e| format!("Invalid utf-8 in forwarded `for` [{}]: {}", String::from_utf8_lossy(hop), e),
                        )?;
                    let ip_str;
                    let port_str;
                    if let Some(v) = v.strip_prefix("[") {
                        let Some(v) = v.strip_suffix("]") else {
                            return Err(
                                format!(
                                    "Invalid forwarded header hop IPv6 `for` brackets: [{}]",
                                    String::from_utf8_lossy(hop)
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
                        ).map_err(|e| format!("Invalid IP addr in forwarded `for` [{}]: {}", v, e))?;
                    if let Some(port_str) = port_str {
                        let port =
                            u16::from_str(
                                port_str,
                            ).map_err(|e| format!("Invalid port in forwarded `for` [{}]: {}", v, e))?;
                        r#for = Some((ip, Some(port)));
                    } else {
                        r#for = Some((ip, None));
                    }
                },
                b"proto" => {
                    if proto.is_some() {
                        return Err(
                            format!(
                                "Invalid forwarded header hop, has repeated `proto`: [{}]",
                                String::from_utf8_lossy(hop)
                            ),
                        );
                    }
                    proto = Some(Cow::Borrowed(v));
                },
                b"host" => {
                    if host.is_some() {
                        return Err(
                            format!(
                                "Invalid forwarded header hop, has repeated `host`: [{}]",
                                String::from_utf8_lossy(hop)
                            ),
                        );
                    }
                    host = Some(Cow::Borrowed(v));
                },
                b"path" => {
                    if path.is_some() {
                        return Err(
                            format!(
                                "Invalid forwarded header hop, has repeated `path`: [{}]",
                                String::from_utf8_lossy(hop)
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

pub fn parse_all_forwarded<'a>(headers: &'a mut HeaderMap) -> Result<Forwarded<'a>, String> {
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
            return Err(format!("Mismatched x-forwarded header value counts"));
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

pub fn add_forwarded(m: &mut HeaderMap, f: &Forwarded) -> Result<(), String> {
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
        ).map_err(
            |e| format!(
                "Forwarded header values produced invalid header [{}]: {}",
                String::from_utf8_lossy(&out_bytes),
                e
            ),
        )?,
    );
    return Ok(());
}

pub fn add_x_forwarded(m: &mut HeaderMap, f: &Forwarded) -> Result<(), String> {
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
                ).map_err(
                    |e| format!(
                        "Forwarded proto [{}] is invalid as header value: {}",
                        String::from_utf8_lossy(&proto),
                        e
                    ),
                )?,
            );
        }
        if let Some(host) = &hop.host {
            m.append(
                FORWARDED_HOST,
                HeaderValue::from_bytes(
                    &host,
                ).map_err(
                    |e| format!(
                        "Forwarded host [{}] is invalid as header value: {}",
                        String::from_utf8_lossy(&host),
                        e
                    ),
                )?,
            );
        }
        if let Some(path) = &hop.path {
            m.append(
                FORWARDED_PATH,
                HeaderValue::from_bytes(
                    &path,
                ).map_err(
                    |e| format!(
                        "Forwarded path [{}] is invalid as header value: {}",
                        String::from_utf8_lossy(&path),
                        e
                    ),
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
            ).map_err(|e| format!("Forwarded for [{}] is invalid as header value: {}", joined, e))?,
        );
    }
    return Ok(());
}
