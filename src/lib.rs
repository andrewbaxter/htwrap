use {
    http::{
        uri::{
            InvalidUri,
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
        os::unix::ffi::OsStringExt,
        path::PathBuf,
        str::FromStr,
    },
};

pub mod htreq;
pub mod htserve;

pub fn new_abs_url(raw: impl AsRef<str>) -> Result<Uri, loga::Error> {
    let raw = raw.as_ref();
    let out = Uri::from_str(raw).context_with("Invalid URL", ea!(url = raw))?;
    if out.scheme().is_none() || out.authority().is_none() {
        return Err(loga::err_with("URL is missing scheme and/or authority", ea!(url = raw)));
    }
    return Ok(out);
}

pub trait UriJoin {
    fn join(&self, other: impl TryInto<Uri, Error = InvalidUri>) -> Uri;
}

impl UriJoin for Uri {
    fn join(&self, other: impl TryInto<Uri, Error = InvalidUri>) -> Uri {
        let other: Uri = other.try_into().unwrap();
        if other.scheme().is_some() {
            // Other has scheme (`x://`)
            return other;
        }

        // Other has no scheme...
        if let Some(authority) = other.authority() {
            // Other has no scheme but host.
            //
            // Use own scheme but `other` for everything else.
            let mut parts = Parts::default();
            parts.scheme = self.scheme().cloned();
            parts.authority = Some(authority.clone());
            parts.path_and_query = other.path_and_query().cloned();
            return Uri::from_parts(parts)
                .context_with("Failed to create URI from parts", ea!(own = self, other = other))
                .unwrap();
        }

        // Other has no scheme and no host...
        let path_and_query = other.path_and_query().cloned().unwrap_or_else(|| PathAndQuery::from_static("/"));
        if let Some(own_path_and_query) = self.path_and_query() {
            // Self has path and query, need to join path
            let path = if path_and_query.path().is_empty() {
                "/"
            } else {
                path_and_query.path()
            };
            let own_path = if own_path_and_query.path().is_empty() {
                "/"
            } else {
                own_path_and_query.path()
            };
            let mut parts = Parts::default();
            parts.scheme = self.scheme().cloned();
            parts.authority = self.authority().cloned();
            let mut new_path_and_query = PathBuf::from(own_path).join(path).into_os_string().into_vec();
            if let Some(query) = path_and_query.query() {
                new_path_and_query.extend(b"?");
                new_path_and_query.extend(query.as_bytes());
            }
            parts.path_and_query = Some(PathAndQuery::try_from(new_path_and_query).unwrap());
            return Uri::from_parts(parts)
                .context_with("Failed to create URI from parts", ea!(own = self, other = other))
                .unwrap();
        }

        // Self has no path, use other path and query wholesale
        let mut parts = Parts::default();
        parts.scheme = self.scheme().cloned();
        parts.authority = self.authority().cloned();
        parts.path_and_query = other.path_and_query().cloned();
        return Uri::from_parts(parts)
            .context_with("Failed to create URI from parts", ea!(own = self, other = other))
            .unwrap();
    }
}
