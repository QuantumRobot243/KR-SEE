use secrecy::{Secret, ExposeSecret};
use std::sync::{Mutex, Arc};
use lazy_static::lazy_static;

lazy_static! {
    static ref SECRET_REGISTRY: Mutex<Vec<Box<dyn Fn() + Send + Sync>>> = Mutex::new(Vec::new());
}

pub struct SecureSecret {
    #[allow(dead_code)]
    inner: Arc<Mutex<Secret<[u8; 32]>>>,
}

impl SecureSecret {
    pub fn new(initial_data: [u8; 32]) -> Self {
        let inner = Arc::new(Mutex::new(Secret::new(initial_data)));
        let weak_inner = Arc::downgrade(&inner);

        if let Ok(mut registry) = SECRET_REGISTRY.lock() {
            registry.push(Box::new(move || {
                if let Some(strong_inner) = weak_inner.upgrade() {
                    if let Ok(mut secret) = strong_inner.lock() {
                        *secret = Secret::new([0u8; 32]);
                    }
                }
            }));
        }

        Self { inner }
    }

    #[allow(dead_code)]
    pub fn expose(&self) -> [u8; 32] {
        if let Ok(secret) = self.inner.lock() {
            *secret.expose_secret()
        } else {
            [0u8; 32]
        }
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
