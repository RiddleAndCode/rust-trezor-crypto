use crate::hasher::{Digest, HashingAlgorithm, DIGEST_LEN};
use core::marker::PhantomData;
use core::{mem, ops};
use std::sync::{Mutex, MutexGuard};

pub const ECDSA_PUBKEY_COMPRESSED_LEN: usize = 33;
pub const ECDSA_PUBKEY_UNCOMPRESSED_LEN: usize = 65;
pub const ECDSA_PRIVKEY_LEN: usize = 32;
pub const ECDSA_SIG_LEN: usize = 64;

lazy_static! {
    static ref ECDSA_CURVE_LOCK: Mutex<()> = Mutex::new(());
}

pub struct EcdsaCurveLock {
    curve: &'static sys::ecdsa_curve,
    _lock: MutexGuard<'static, ()>,
}

impl EcdsaCurveLock {
    unsafe fn as_ptr(&self) -> *const sys::ecdsa_curve {
        self.curve
    }
}

impl ops::Deref for EcdsaCurveLock {
    type Target = sys::ecdsa_curve;
    fn deref(&self) -> &Self::Target {
        self.curve
    }
}

pub trait EcdsaCurve {
    #[doc(hidden)]
    unsafe fn curve_lock() -> EcdsaCurveLock;
}

trait EcdsaCurveExt: EcdsaCurve {
    fn get_public_key(priv_key: &[u8; ECDSA_PRIVKEY_LEN]) -> [u8; ECDSA_PUBKEY_COMPRESSED_LEN] {
        let mut out = [0; ECDSA_PUBKEY_COMPRESSED_LEN];
        unsafe {
            let curve = Self::curve_lock();
            sys::ecdsa_get_public_key33(curve.as_ptr(), priv_key.as_ptr(), out.as_mut_ptr())
        }
        out
    }
    fn uncompress_public_key(
        pub_key: &[u8; ECDSA_PUBKEY_COMPRESSED_LEN],
    ) -> Option<[u8; ECDSA_PUBKEY_UNCOMPRESSED_LEN]> {
        let mut out = [0; ECDSA_PUBKEY_UNCOMPRESSED_LEN];
        let res = unsafe {
            let curve = Self::curve_lock();
            sys::ecdsa_uncompress_pubkey(curve.as_ptr(), pub_key.as_ptr(), out.as_mut_ptr())
        };
        if res == 1 {
            Some(out)
        } else {
            None
        }
    }
    fn read_public_key(pub_key: &[u8; ECDSA_PUBKEY_COMPRESSED_LEN]) -> Option<sys::curve_point> {
        let mut point;
        let res = unsafe {
            point = mem::zeroed();
            let curve = Self::curve_lock();
            sys::ecdsa_read_pubkey(curve.as_ptr(), pub_key.as_ptr(), &mut point)
        };
        if res == 1 {
            Some(point)
        } else {
            None
        }
    }
    fn sign_digest(
        priv_key: &[u8; ECDSA_PRIVKEY_LEN],
        digest: &[u8; DIGEST_LEN],
    ) -> Option<([u8; ECDSA_SIG_LEN], u8)> {
        let mut sig = [0; ECDSA_SIG_LEN];
        let mut by = 0;
        let res = unsafe {
            let curve = Self::curve_lock();
            sys::ecdsa_sign_digest(
                curve.as_ptr(),
                priv_key.as_ptr(),
                digest.as_ptr(),
                sig.as_mut_ptr(),
                &mut by,
                None,
            )
        };
        if res == 1 {
            Some((sig, by))
        } else {
            None
        }
    }
    fn sign(
        priv_key: &[u8; ECDSA_PRIVKEY_LEN],
        hasher_type: sys::HasherType,
        data: &[u8],
    ) -> Option<([u8; ECDSA_SIG_LEN], u8)> {
        let mut sig = [0; ECDSA_SIG_LEN];
        let mut by = 0;
        let res = unsafe {
            let curve = Self::curve_lock();
            sys::ecdsa_sign(
                curve.as_ptr(),
                hasher_type,
                priv_key.as_ptr(),
                data.as_ptr(),
                data.len() as u32,
                sig.as_mut_ptr(),
                &mut by,
                None,
            )
        };
        if res == 1 {
            Some((sig, by))
        } else {
            None
        }
    }
}

impl<T> EcdsaCurveExt for T where T: EcdsaCurve {}

macro_rules! ecdsa_curve {
    ($name:ident, $ty:path) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;
        impl EcdsaCurve for $name {
            #[inline]
            unsafe fn curve_lock() -> EcdsaCurveLock {
                EcdsaCurveLock {
                    curve: &$ty,
                    _lock: ECDSA_CURVE_LOCK.lock().unwrap(),
                }
            }
        }
    };
}
ecdsa_curve!(Secp256k1, sys::secp256k1);
ecdsa_curve!(Nist256p1, sys::nist256p1);

#[derive(Clone)]
pub struct EcdsaPrivateKey<C: EcdsaCurve> {
    bytes: [u8; ECDSA_PRIVKEY_LEN],
    curve: PhantomData<C>,
}

impl<C: EcdsaCurve> EcdsaPrivateKey<C> {
    #[inline]
    pub fn from_bytes(bytes: [u8; ECDSA_PRIVKEY_LEN]) -> Self {
        Self {
            bytes,
            curve: PhantomData,
        }
    }
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == ECDSA_PRIVKEY_LEN {
            let mut bytes = [0; ECDSA_PRIVKEY_LEN];
            bytes.copy_from_slice(slice);
            Some(Self::from_bytes(bytes))
        } else {
            None
        }
    }
    pub fn public_key(&self) -> EcdsaPublicKey<C> {
        unsafe { EcdsaPublicKey::from_bytes_unchecked(C::get_public_key(&self.bytes)) }
    }
    #[inline]
    pub fn cast<U>(self) -> EcdsaPrivateKey<U>
    where
        U: EcdsaCurve,
    {
        EcdsaPrivateKey::from_bytes(self.bytes)
    }
    pub fn sign<H: HashingAlgorithm, D: AsRef<[u8]>>(
        &self,
        data: D,
    ) -> Option<RecoverableSignature> {
        C::sign(&self.bytes, H::hasher_type(), data.as_ref())
            .map(|(sig, by)| RecoverableSignature::new(Signature::from_bytes(sig), by))
    }
    pub fn sign_digest(&self, digest: &Digest) -> Option<RecoverableSignature> {
        C::sign_digest(&self.bytes, digest.as_bytes())
            .map(|(sig, by)| RecoverableSignature::new(Signature::from_bytes(sig), by))
    }
}

#[derive(Clone, Debug)]
pub struct EcdsaPublicKey<C: EcdsaCurve> {
    bytes: [u8; ECDSA_PUBKEY_COMPRESSED_LEN],
    curve: PhantomData<C>,
}

impl<C: EcdsaCurve> EcdsaPublicKey<C> {
    #[inline]
    pub unsafe fn from_bytes_unchecked(bytes: [u8; ECDSA_PUBKEY_COMPRESSED_LEN]) -> Self {
        Self {
            bytes,
            curve: PhantomData,
        }
    }
    pub fn from_bytes(bytes: [u8; ECDSA_PUBKEY_COMPRESSED_LEN]) -> Option<Self> {
        let pub_key = unsafe { Self::from_bytes_unchecked(bytes) };
        if pub_key.is_valid() {
            Some(pub_key)
        } else {
            None
        }
    }
    pub fn is_valid(&self) -> bool {
        C::read_public_key(&self.bytes).is_some()
    }
    pub fn serialize(&self) -> [u8; ECDSA_PUBKEY_COMPRESSED_LEN] {
        self.bytes.clone()
    }
    pub fn serialize_uncompressed(&self) -> [u8; ECDSA_PUBKEY_UNCOMPRESSED_LEN] {
        C::uncompress_public_key(&self.bytes).unwrap()
    }
}

pub struct Signature {
    bytes: [u8; ECDSA_SIG_LEN],
}

impl Signature {
    #[inline]
    pub fn from_bytes(bytes: [u8; ECDSA_SIG_LEN]) -> Self {
        Self { bytes }
    }
    pub fn serialize(&self) -> &[u8; ECDSA_SIG_LEN] {
        &self.bytes
    }
}

pub struct RecoverableSignature {
    signature: Signature,
    recovery_byte: u8,
}

impl RecoverableSignature {
    #[inline]
    pub fn new(signature: Signature, recovery_byte: u8) -> Self {
        Self {
            signature,
            recovery_byte,
        }
    }
}

impl ops::Deref for RecoverableSignature {
    type Target = Signature;
    fn deref(&self) -> &Signature {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secp256k1_public_key_test_vector(
        priv_key_hex: impl AsRef<str>,
        x_hex: impl AsRef<str>,
        y_hex: impl AsRef<str>,
    ) {
        let priv_key =
            EcdsaPrivateKey::<Secp256k1>::from_slice(&hex::decode(priv_key_hex.as_ref()).unwrap())
                .unwrap();
        let pub_key = priv_key.public_key();
        assert!(pub_key.is_valid());
        let pub_key = pub_key.serialize_uncompressed();
        assert_eq!(hex::encode(&pub_key[1..33]), x_hex.as_ref().to_lowercase());
        assert_eq!(hex::encode(&pub_key[33..]), y_hex.as_ref().to_lowercase());
    }

    #[test]
    fn secp256k1_public_key_test_vectors() {
        secp256k1_public_key_test_vector(
            "AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522",
            "34F9460F0E4F08393D192B3C5133A6BA099AA0AD9FD54EBCCFACDFA239FF49C6",
            "0B71EA9BD730FD8923F6D25A7A91E7DD7728A960686CB5A901BB419E0F2CA232",
        );
        secp256k1_public_key_test_vector(
            "7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3",
            "D74BF844B0862475103D96A611CF2D898447E288D34B360BC885CB8CE7C00575",
            "131C670D414C4546B88AC3FF664611B1C38CEB1C21D76369D7A7A0969D61D97D",
        );
        secp256k1_public_key_test_vector(
            "6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D",
            "E8AECC370AEDD953483719A116711963CE201AC3EB21D3F3257BB48668C6A72F",
            "C25CAF2F0EBA1DDB2F0F3F47866299EF907867B7D27E95B3873BF98397B24EE1",
        );
        secp256k1_public_key_test_vector(
            "376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC",
            "14890E61FCD4B0BD92E5B36C81372CA6FED471EF3AA60A3E415EE4FE987DABA1",
            "297B858D9F752AB42D3BCA67EE0EB6DCD1C2B7B0DBE23397E66ADC272263F982",
        );
        secp256k1_public_key_test_vector(
            "1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9",
            "F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3",
            "F449A8376906482A84ED01479BD18882B919C140D638307F0C0934BA12590BDE",
        );
    }

    #[test]
    fn secp256k1_multi_thread() {
        let mut children = Vec::new();
        for _ in 0..10 {
            children.push(std::thread::spawn(|| {
                secp256k1_public_key_test_vector(
                    "AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522",
                    "34F9460F0E4F08393D192B3C5133A6BA099AA0AD9FD54EBCCFACDFA239FF49C6",
                    "0B71EA9BD730FD8923F6D25A7A91E7DD7728A960686CB5A901BB419E0F2CA232",
                );
            }))
        }
        for child in children {
            child.join().unwrap();
        }
    }

    fn nist256p1_public_key_test_vector(
        priv_key_hex: impl AsRef<str>,
        x_hex: impl AsRef<str>,
        y_hex: impl AsRef<str>,
    ) {
        let priv_key =
            EcdsaPrivateKey::<Nist256p1>::from_slice(&hex::decode(priv_key_hex.as_ref()).unwrap())
                .unwrap();
        let pub_key = priv_key.public_key();
        assert!(pub_key.is_valid());
        let pub_key = pub_key.serialize_uncompressed();
        assert_eq!(hex::encode(&pub_key[1..33]), x_hex.as_ref().to_lowercase());
        assert_eq!(hex::encode(&pub_key[33..]), y_hex.as_ref().to_lowercase());
    }

    #[test]
    fn nist256p1_public_key_test_vectors() {
        nist256p1_public_key_test_vector(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        )
    }
}
