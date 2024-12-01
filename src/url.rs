use {
    http::{
        uri::{
            Parts,
            PathAndQuery,
        },
        Uri,
    },
    loga::{
        ea,
        ResultContext,
    },
    std::{
        net::{
            IpAddr,
            Ipv4Addr,
            Ipv6Addr,
        },
        os::unix::ffi::OsStringExt,
        path::PathBuf,
        str::FromStr,
    },
};

pub fn new_abs_url(raw: impl AsRef<str>) -> Result<Uri, loga::Error> {
    let raw = raw.as_ref();
    let out = Uri::from_str(raw).context_with("Invalid URL", ea!(url = raw))?;
    if out.scheme().is_none() || out.authority().is_none() {
        return Err(loga::err_with("URL is missing scheme and/or authority", ea!(url = raw)));
    }
    return Ok(out);
}

pub trait IpUrl {
    fn as_url_host(self) -> String;
}

impl IpUrl for IpAddr {
    fn as_url_host(self) -> String {
        match self {
            IpAddr::V4(i) => return i.as_url_host(),
            IpAddr::V6(i) => return i.as_url_host(),
        }
    }
}

impl IpUrl for Ipv4Addr {
    fn as_url_host(self) -> String {
        return format!("{}", self);
    }
}

impl IpUrl for Ipv6Addr {
    fn as_url_host(self) -> String {
        return format!("[{}]", self);
    }
}

pub trait UriJoin {
    fn join(&self, other: impl AsRef<str>) -> Uri;
}

impl UriJoin for Uri {
    fn join(&self, other: impl AsRef<str>) -> Uri {
        let other = other.as_ref();

        // Absolute - contains `://`
        if other.contains("://") {
            return Uri::from_str(other).context_with("Invalid join url", ea!(other = other)).unwrap();
        }

        // Relative
        let path;
        let query;
        if let Some((path1, query1)) = other.split_once("?") {
            path = path1;
            query = Some(query1);
        } else {
            path = other;
            query = None;
        }
        let mut parts = Parts::default();
        parts.scheme = self.scheme().cloned();
        parts.authority = self.authority().cloned();
        let mut new_path_and_query = PathBuf::from(self.path()).join(path).into_os_string().into_vec();
        if let Some(query) = query {
            new_path_and_query.extend(b"?");
            new_path_and_query.extend(query.as_bytes());
        }
        parts.path_and_query = Some(PathAndQuery::try_from(new_path_and_query).unwrap());
        return Uri::from_parts(parts)
            .context_with("Failed to create URI from parts", ea!(own = self, other = other))
            .unwrap();
    }
}

#[cfg(test)]
mod test {
    use {
        crate::url::{
            new_abs_url,
            UriJoin,
        },
    };

    #[test]
    fn test_uri_join_abs() {
        assert_eq!(new_abs_url("https://a.b").unwrap().join("udp://c.d"), new_abs_url("udp://c.d").unwrap());
    }

    #[test]
    fn test_uri_join_new_root_path() {
        assert_eq!(new_abs_url("https://a.b").unwrap().join("/x"), new_abs_url("https://a.b/x").unwrap());
    }

    #[test]
    fn test_uri_join_new_path() {
        assert_eq!(new_abs_url("https://a.b").unwrap().join("x"), new_abs_url("https://a.b/x").unwrap());
    }

    #[test]
    fn test_uri_join_merge_root_path() {
        assert_eq!(new_abs_url("https://a.b/c").unwrap().join("/x"), new_abs_url("https://a.b/x").unwrap());
    }

    #[test]
    fn test_uri_join_merge_path() {
        assert_eq!(new_abs_url("https://a.b/c").unwrap().join("x"), new_abs_url("https://a.b/c/x").unwrap());
    }

    #[test]
    fn test_uri_join_new_query() {
        assert_eq!(new_abs_url("https://a.b/c").unwrap().join("x?y"), new_abs_url("https://a.b/c/x?y").unwrap());
    }

    #[test]
    fn test_uri_join_replace_query() {
        assert_eq!(new_abs_url("https://a.b/c?d").unwrap().join("x?y"), new_abs_url("https://a.b/c/x?y").unwrap());
    }
}
