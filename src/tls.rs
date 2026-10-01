use {
    rustls::crypto::CryptoProvider,
    std::sync::{
        Arc,
        LazyLock,
    },
};

#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
compile_error!("One of the `ring` or `aws-lc-rs` features must be enabled");

pub fn crypto_provider() -> Arc<CryptoProvider> {
    static S: LazyLock<Arc<CryptoProvider>> = LazyLock::new(|| {
        #[cfg(feature = "aws-lc-rs")]
        return Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
        return Arc::new(rustls::crypto::ring::default_provider());
    });
    return S.clone();
}
