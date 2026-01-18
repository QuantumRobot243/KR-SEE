use secrecy::{Secret, ExposeSecret};
use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref SECRET_REGISTRY: Mutex<Vec<Box<dyn Fn() + Send + Sync>>> = Mutex::new(Vec::new());
}

pub struct SecureSecret {
    inner: Secret<[u8; 32]>,
}

impl SecureSecret {
    pub fn new(initial_data: [u8; 32]) -> Self {
        Self {
            inner: Secret::new(initial_data),
        }
    }

    pub fn expose(&self) -> &[u8; 32] {
        self.inner.expose_secret()
    }
}

pub fn wipe_all_registered_secrets() {
    if let Ok(mut registry) = SECRET_REGISTRY.lock() {
        for wipe_fn in registry.iter() {
            wipe_fn();
        }
        registry.clear();
    }
}
