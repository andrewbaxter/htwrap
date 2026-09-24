#![cfg(test)]
use {
    super::handler::{
        Handler,
        HandlerArgs,
        PathRouter,
    },
    crate::htreq,
    http::{
        Response,
        Uri,
    },
    http_body_util::Full,
    hyper::body::Bytes,
    loga::Log,
    std::{
        collections::HashMap,
        str::FromStr,
        sync::Arc,
    },
    tokio::net::TcpListener,
};

type Body = Full<Bytes>;

struct Echo {
    route: String,
}

#[async_trait::async_trait]
impl Handler<Body> for Echo {
    async fn handle(&self, args: HandlerArgs<'_>) -> Response<Body> {
        return Response::builder()
            .body(Body::new(Bytes::from(format!("{} {}", self.route, args.subpath))))
            .unwrap();
    }
}

async fn serve(routes: &[&str]) -> u16 {
    let mut router = PathRouter::<Body>::default();
    for route in routes {
        router.insert(route, Box::new(Echo { route: route.to_string() })).unwrap();
    }
    let handler = Arc::new(router) as Arc<dyn Handler<Body>>;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            crate::htserve::handler::root_handle_http(&Log::new(), handler.clone(), stream).await.unwrap();
        }
    });
    return port;
}

async fn route(routes: &[&str], path: &str) -> Option<String> {
    let port = serve(routes).await;
    let url = Uri::from_str(&format!("http://127.0.0.1:{}{}", port, path)).unwrap();
    let mut conn = htreq::connect(Default::default(), &url).await.unwrap();
    match htreq::get_text(&Log::new(), Default::default(), &mut conn, &url, &HashMap::new()).await {
        Ok(body) => return Some(body),
        Err(e) => {
            let e = format!("{:?}", e);
            assert!(e.contains("404"), "Unexpected request failure: {}", e);
            return None;
        },
    }
}

#[tokio::test]
async fn route_exact() {
    assert_eq!(route(&["", "/a", "/a/b"], "/a/b").await.as_deref(), Some("/a/b "));
}

#[tokio::test]
async fn route_longest_prefix() {
    assert_eq!(route(&["", "/a", "/a/b"], "/a/b/c/d").await.as_deref(), Some("/a/b /c/d"));
}

#[tokio::test]
async fn route_root_fallback() {
    assert_eq!(route(&[""], "/a/b").await.as_deref(), Some(" /a/b"));
    assert_eq!(route(&[""], "").await.as_deref(), Some(" "));
}

#[tokio::test]
async fn route_segment_boundary() {
    assert_eq!(route(&["/a"], "/ab").await, None);
    assert_eq!(route(&["/a"], "/ab/c").await, None);
    assert_eq!(route(&["", "/a"], "/ab/c").await.as_deref(), Some(" /ab/c"));
}

#[tokio::test]
async fn route_fall_back_past_near_miss() {
    assert_eq!(route(&["", "/foo"], "/fop").await.as_deref(), Some(" /fop"));
    assert_eq!(route(&["/a", "/a/bb"], "/a/b").await.as_deref(), Some("/a /b"));
    assert_eq!(route(&["/a", "/a/b/c"], "/a/b/d").await.as_deref(), Some("/a /b/d"));
}

#[tokio::test]
async fn route_no_match() {
    assert_eq!(route(&["/a"], "/b").await, None);
    assert_eq!(route(&["/a"], "").await, None);
}

#[test]
fn route_rejects_bad_keys() {
    let mut router = PathRouter::<Body>::default();
    assert!(router.insert("a", Box::new(Echo { route: "a".to_string() })).is_err());
    assert!(router.insert("/a/", Box::new(Echo { route: "/a/".to_string() })).is_err());
}
