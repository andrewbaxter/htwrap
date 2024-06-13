Minimal wrappers and common utilities for using `hyper` as an http client or server.

## Server

Using `hyper` as a http server directly is easy, so there's not much here, mostly:

- Utilities for generating common responses and
- A static file serving method that supports range access (tested with http audio/video media serving in Chrome and Firefox)

In my experience the main thing missing vs a larger http server framework is a router, i.e. an efficient prefix-based map so that dynamic paths can be matched.

### Example

```rust
async fn handle_req(state: Arc<State>, req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    return Ok(response_200());
}

let mut listener = TcpSocket::bind(&addr)?;
while let Some((conn, _)) = listener.accept().await.ok() {
    tokio::spawn({
        let state = state.clone();
        async move {
            match async move {
                hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(conn),
                        hyper::service::service_fn(move |req| handle_req(state, req)),
                    )
                    .await
                    .map_err(
                        |e| loga::err_with(
                            "Error serving HTTP on connection",
                            ea!(err = e.to_string()),
                        ),
                    )?;
                return Ok(()) as Result<(), loga::Error>;
            }.await {
                Ok(_) => (),
                Err(e) => {
                    log.log_err(StandardFlag::Debug, e.context("Error serving connection"));
                },
            }
        }
    });
}
```

## Client

Requests are split in to three stages and there are functions for each:

1. Establish a connection (`connect`).

   This does address resolution including "happy eyes" for ipv4/ipv6 resolution.

   You can reuse this connection, or create your own connection pool. There's no connection management beyond this.

2. Send a request and wait for the headers (`send`)
3. Read the body (`receive` or `receive_stream`)

There are helper methods that combine 2 and 3 above:

- `send_simple`
- `post`
- `post_json`

## Why

Various interfaces of popular libraries weren't type safe and made various edge case custom behaviors hard or impossible to implement. The implementations were large and internally tightly coupled, and the maintainers weren't amenable to uncommon use cases.

This library is primarily for my own consumption, but I'd like it to be useful to other people with a similar vision (composable, minimal abstraction, minimal generic usage, minimal macro usage).
