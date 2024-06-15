use {
    std::{
        os::unix::ffi::OsStringExt,
        path::PathBuf,
    },
    http::{
        uri::{
            InvalidUri,
            Parts,
            PathAndQuery,
        },
        Uri,
    },
};

pub mod htreq;
pub mod htserve;

pub trait UriJoin {
    fn join(&self, other: impl TryInto<Uri, Error = InvalidUri>) -> Uri;
}

impl UriJoin for Uri {
    fn join(&self, other: impl TryInto<Uri, Error = InvalidUri>) -> Uri {
        let other = other.try_into().unwrap();
        if other.scheme().is_some() {
            return other;
        }
        if let Some(authority) = other.authority() {
            let mut parts = Parts::default();
            parts.scheme = self.scheme().cloned();
            parts.authority = Some(authority.clone());
            parts.path_and_query = other.path_and_query().cloned();
            return Uri::from_parts(parts).unwrap();
        }
        let path_and_query = other.path_and_query().unwrap();
        if let Some(own_path_and_query) = self.path_and_query() {
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
            return Uri::from_parts(parts).unwrap();
        } else {
            let mut parts = Parts::default();
            parts.scheme = self.scheme().cloned();
            parts.authority = self.authority().cloned();
            parts.path_and_query = other.path_and_query().cloned();
            return Uri::from_parts(parts).unwrap();
        }
    }
}
