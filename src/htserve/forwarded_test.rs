#![cfg(test)]
use {
    super::forwarded::{
        parse_forwarded,
        ForwardedHop,
    },
    crate::htserve::forwarded::render_to_forwarded,
    http::{
        header::FORWARDED,
        HeaderMap,
        HeaderValue,
    },
    std::{
        net::IpAddr,
        str::FromStr,
    },
};

fn do_test_forwarded(want_str: &str, want_hop: Vec<ForwardedHop>) {
    let want_str = HeaderValue::from_str(want_str).unwrap();
    let got_hop = parse_forwarded(&want_str).unwrap();
    assert_eq!(got_hop, want_hop);
    let mut m = HeaderMap::new();
    render_to_forwarded(&mut m, &got_hop).unwrap();
    let got_str = m.get(FORWARDED).unwrap();
    assert_eq!(got_str, want_str);
}

#[test]
fn rt_forwarded1() {
    do_test_forwarded(
        "for=\"[::1]:59954\"; proto=https; host=xyz.abc; path=/.well-known/openid-configuration",
        vec![ForwardedHop {
            for_: Some((IpAddr::from_str("::1").unwrap(), Some(59954))),
            proto: Some(b"https".into()),
            host: Some(b"xyz.abc".into()),
            path: Some(b"/.well-known/openid-configuration".into()),
        }],
    );
}
