use crate::signature::{Signature, SIG_LEN};
pub const ED25519_PUBKEY_LEN: usize = 32;
pub const ED25519_PRIVKEY_LEN: usize = 32;

pub struct Ed25519;

#[derive(Clone)]
pub struct Ed25519PrivateKey {
    bytes: [u8; ED25519_PRIVKEY_LEN],
}

impl Ed25519PrivateKey {
    #[inline]
    pub fn from_bytes(bytes: [u8; ED25519_PRIVKEY_LEN]) -> Self {
        Self { bytes }
    }
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == ED25519_PRIVKEY_LEN {
            let mut bytes = [0; ED25519_PRIVKEY_LEN];
            bytes.copy_from_slice(slice);
            Some(Self::from_bytes(bytes))
        } else {
            None
        }
    }
    pub fn public_key(&self) -> Ed25519PublicKey {
        let mut bytes = [0; ED25519_PUBKEY_LEN];
        unsafe { sys::ed25519_publickey(self.bytes.as_ptr() as *mut u8, bytes.as_mut_ptr()) }
        Ed25519PublicKey::from_bytes(bytes)
    }
    pub fn sign(&self, data: impl AsRef<[u8]>) -> Signature<Ed25519> {
        let data = data.as_ref();
        let mut public_key = self.public_key();
        let mut signature = [0; SIG_LEN];
        unsafe {
            sys::ed25519_sign(
                data.as_ptr(),
                data.len() as u64,
                self.bytes.as_ptr() as *mut u8,
                public_key.bytes.as_mut_ptr(),
                signature.as_mut_ptr(),
            );
        }
        Signature::from_bytes(signature)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519PublicKey {
    bytes: [u8; ED25519_PUBKEY_LEN],
}

impl Ed25519PublicKey {
    #[inline]
    pub fn from_bytes(bytes: [u8; ED25519_PUBKEY_LEN]) -> Self {
        Self { bytes }
    }
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == ED25519_PUBKEY_LEN {
            let mut bytes = [0; ED25519_PUBKEY_LEN];
            bytes.copy_from_slice(slice);
            Some(Self::from_bytes(bytes))
        } else {
            None
        }
    }
    pub fn serialize(&self) -> [u8; ED25519_PUBKEY_LEN] {
        self.bytes.clone()
    }
}
