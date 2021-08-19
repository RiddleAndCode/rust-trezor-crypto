use crate::curve::{Curve, CurveInfoLock, CurveLock, PrivateKey, PublicKey};
use crate::hasher::{HashingAlgorithm, Sha2, Sha3, Sha3k};
use crate::hd_node::{HDNODE_PRIVKEY_LEN, HDNODE_PUBKEY_LEN};
use crate::signature::{Signature, SIG_LEN};

pub const ED25519_PUBKEY_LEN: usize = 32;
pub const ED25519_PRIVKEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy)]
pub struct Ed25519;

#[doc(hidden)]
/// Does nothing
pub struct Ed25519Lock;

const STATIC_ED25519_LOCK_DOES_NOTHING: Ed25519Lock = Ed25519Lock;

impl CurveLock for Ed25519Lock {}

#[doc(hidden)]
/// Does nothing
pub struct Ed25519InfoLock;

impl CurveInfoLock for Ed25519InfoLock {
    type CurveLock = Ed25519Lock;
    unsafe fn curve(&self) -> &Self::CurveLock {
        &STATIC_ED25519_LOCK_DOES_NOTHING
    }
}

impl Curve for Ed25519 {
    type PublicKey = Ed25519PublicKey;
    type PrivateKey = Ed25519PrivateKey;
    type CurveInfoLock = Ed25519InfoLock;
    unsafe fn curve_info_lock() -> Self::CurveInfoLock {
        Ed25519InfoLock
    }
    unsafe fn name_ptr() -> *const std::os::raw::c_char {
        sys::ED25519_NAME.as_ptr()
    }
}

pub struct Ed25519Cardano;

impl Curve for Ed25519Cardano {
    type PublicKey = Ed25519PublicKey;
    type PrivateKey = Ed25519PrivateKey;
    type CurveInfoLock = Ed25519InfoLock;
    unsafe fn curve_info_lock() -> Self::CurveInfoLock {
        Ed25519InfoLock
    }
    fn is_cardano() -> bool {
        true
    }
    unsafe fn name_ptr() -> *const std::os::raw::c_char {
        sys::ED25519_CARDANO_NAME.as_ptr()
    }
}

#[doc(hidden)]
pub type Ed25519SignAlgo = unsafe extern "C" fn(*const u8, u64, *mut u8, *mut u8, *mut u8);
#[doc(hidden)]
pub type Ed25519VerifyAlgo = unsafe extern "C" fn(*const u8, u64, *mut u8, *mut u8) -> i32;

pub trait Ed25519HashingAlgorithm: HashingAlgorithm {
    #[doc(hidden)]
    fn sign_algo() -> Ed25519SignAlgo;
    #[doc(hidden)]
    fn verify_algo() -> Ed25519VerifyAlgo;
}

macro_rules! ed25519_hashing_algo {
    ($algo:ident, $sign_algo:path, $verify_algo:path) => {
        impl Ed25519HashingAlgorithm for $algo {
            fn sign_algo() -> Ed25519SignAlgo {
                $sign_algo
            }
            fn verify_algo() -> Ed25519VerifyAlgo {
                $verify_algo
            }
        }
    };
}

ed25519_hashing_algo!(Sha2, sys::ed25519_sign, sys::ed25519_sign_open);
ed25519_hashing_algo!(Sha3, sys::ed25519_sign_sha3, sys::ed25519_sign_open_sha3);
ed25519_hashing_algo!(
    Sha3k,
    sys::ed25519_sign_keccak,
    sys::ed25519_sign_open_keccak
);

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
    pub fn sign<H: Ed25519HashingAlgorithm, D: AsRef<[u8]>>(&self, data: D) -> Signature<Ed25519> {
        let data = data.as_ref();
        let mut public_key = self.public_key();
        let mut signature = [0; SIG_LEN];
        unsafe {
            H::sign_algo()(
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

impl PrivateKey for Ed25519PrivateKey {
    #[inline]
    fn from_bytes_unchecked(bytes: [u8; HDNODE_PRIVKEY_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
    #[inline]
    fn to_bytes(self) -> [u8; HDNODE_PRIVKEY_LEN] {
        self.bytes
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
    pub fn verify<H: Ed25519HashingAlgorithm, D: AsRef<[u8]>>(
        &self,
        signature: &Signature<Ed25519>,
        data: D,
    ) -> bool {
        let data = data.as_ref();
        let res = unsafe {
            H::verify_algo()(
                data.as_ptr(),
                data.len() as u64,
                self.bytes.as_ptr() as *mut u8,
                signature.bytes.as_ptr() as *mut u8,
            )
        };
        res == 0
    }
}

impl PublicKey for Ed25519PublicKey {
    #[inline]
    fn from_bytes_unchecked(bytes: [u8; HDNODE_PUBKEY_LEN]) -> Self {
        let mut pubkey = [0; 32];
        pubkey.copy_from_slice(&bytes[0..ED25519_PUBKEY_LEN]);
        Self::from_bytes(pubkey)
    }
    #[inline]
    fn to_bytes(self) -> [u8; HDNODE_PUBKEY_LEN] {
        let mut out = [0; HDNODE_PUBKEY_LEN];
        out[..ED25519_PUBKEY_LEN].copy_from_slice(&self.bytes);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curve_name() {
        assert_eq!("ed25519", Ed25519::name());
    }

    fn public_key_test_vector(priv_key_hex: &str, public_key_hex: &str) {
        let private_key =
            Ed25519PrivateKey::from_slice(&hex::decode(priv_key_hex).unwrap()).unwrap();
        assert_eq!(
            &private_key.public_key().serialize(),
            hex::decode(public_key_hex).unwrap().as_slice()
        );
    }

    #[test]
    fn ed25519_public_key() {
        public_key_test_vector(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        );
        public_key_test_vector(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        );
        public_key_test_vector(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        );
    }

    fn signature_test_vector(priv_key_hex: &str, message_hex: &str, signature_hex: &str) {
        let private_key =
            Ed25519PrivateKey::from_slice(&hex::decode(priv_key_hex).unwrap()).unwrap();
        let message = hex::decode(message_hex).unwrap();
        let signature = private_key.sign::<Sha2, _>(&message);
        assert_eq!(
            signature.serialize(),
            hex::decode(signature_hex).unwrap().as_slice()
        );
        let public_key = private_key.public_key();
        assert!(public_key.verify::<Sha2, _>(&signature, &message));
    }

    #[test]
    fn ed25519_sign() {
        signature_test_vector(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        signature_test_vector(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        signature_test_vector(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        );
    }

    #[test]
    fn ed25519_multi_thread() {
        let mut children = Vec::new();
        for _ in 0..10 {
            children.push(std::thread::spawn(|| {
                ed25519_public_key();
                ed25519_sign();
            }))
        }
        for child in children {
            child.join().unwrap();
        }
    }
}
