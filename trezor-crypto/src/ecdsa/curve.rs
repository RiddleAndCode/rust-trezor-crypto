use super::canonical::{CanonicalFnLock, IsCanonicalFn};
use crate::curve::{Curve, CurveInfoLock, CurveLock, PrivateKey, PublicKey};
use crate::hasher::{Digest, HashingAlgorithm, DIGEST_LEN};
use crate::hd_node::{HDNODE_PRIVKEY_LEN, HDNODE_PUBKEY_LEN};
use crate::signature::{RecoverableSignature, Signature, SIG_LEN};
use core::marker::PhantomData;
use core::{fmt, mem, ops};
use generic_array::typenum::{U32, U33, U65};
use generic_array::GenericArray;
use std::os::raw::c_char;
use std::sync::{Mutex, MutexGuard};

pub const ECDSA_PUBKEY_COMPRESSED_LEN: usize = 33;
pub const ECDSA_PUBKEY_UNCOMPRESSED_LEN: usize = 65;
pub const ECDSA_PRIVKEY_LEN: usize = 32;

lazy_static! {
    static ref ECDSA_CURVE_LOCK: Mutex<()> = Mutex::new(());
}

#[doc(hidden)]
pub struct EcdsaCurveLock {
    curve: &'static sys::ecdsa_curve,
    _lock: MutexGuard<'static, ()>,
}

impl CurveLock for EcdsaCurveLock {}

impl EcdsaCurveLock {
    pub(crate) unsafe fn as_ptr(&self) -> *const sys::ecdsa_curve {
        self.curve
    }
}

impl CurveInfoLock for EcdsaCurveInfoLock {
    type CurveLock = EcdsaCurveLock;
    #[inline]
    unsafe fn curve(&self) -> &EcdsaCurveLock {
        &self.lock
    }
}

impl ops::Deref for EcdsaCurveLock {
    type Target = sys::ecdsa_curve;
    fn deref(&self) -> &Self::Target {
        self.curve
    }
}

#[doc(hidden)]
pub struct EcdsaCurveInfoLock {
    info: &'static sys::curve_info,
    lock: EcdsaCurveLock,
}

impl ops::Deref for EcdsaCurveInfoLock {
    type Target = sys::curve_info;
    fn deref(&self) -> &Self::Target {
        self.info
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
    fn read_public_key(pub_key: &[u8]) -> Option<sys::curve_point> {
        let key_len = pub_key.len();
        if key_len < 1 {
            return None;
        }
        let expected_key_len = match pub_key[0] {
            0x02 | 0x03 => ECDSA_PUBKEY_COMPRESSED_LEN,
            0x04 => ECDSA_PUBKEY_UNCOMPRESSED_LEN,
            _ => {
                return None;
            }
        };
        if key_len != expected_key_len {
            return None;
        }
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
        is_canonical: Option<IsCanonicalFn>,
    ) -> Option<([u8; SIG_LEN], u8)> {
        let mut sig = [0; SIG_LEN];
        let mut by = 0;
        let res = unsafe {
            let curve = Self::curve_lock();
            sys::ecdsa_sign_digest(
                curve.as_ptr(),
                priv_key.as_ptr(),
                digest.as_ptr(),
                sig.as_mut_ptr(),
                &mut by,
                curve.is_canonical_fn(is_canonical),
            )
        };
        if res == 0 {
            Some((sig, by))
        } else {
            None
        }
    }
    fn sign(
        priv_key: &[u8; ECDSA_PRIVKEY_LEN],
        hasher_type: sys::HasherType,
        data: &[u8],
        is_canonical: Option<IsCanonicalFn>,
    ) -> Option<([u8; SIG_LEN], u8)> {
        let mut sig = [0; SIG_LEN];
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
                curve.is_canonical_fn(is_canonical),
            )
        };
        if res == 0 {
            Some((sig, by))
        } else {
            None
        }
    }
    fn verify_digest(
        pub_key: &[u8; ECDSA_PUBKEY_COMPRESSED_LEN],
        sig: &[u8; SIG_LEN],
        digest: &[u8; DIGEST_LEN],
    ) -> bool {
        let res = unsafe {
            let curve = Self::curve_lock();
            sys::ecdsa_verify_digest(
                curve.as_ptr(),
                pub_key.as_ptr(),
                sig.as_ptr(),
                digest.as_ptr(),
            )
        };
        res == 0
    }
    fn verify(
        pub_key: &[u8; ECDSA_PUBKEY_COMPRESSED_LEN],
        hasher_type: sys::HasherType,
        sig: &[u8; SIG_LEN],
        data: &[u8],
    ) -> bool {
        let res = unsafe {
            let curve = Self::curve_lock();
            sys::ecdsa_verify(
                curve.as_ptr(),
                hasher_type,
                pub_key.as_ptr(),
                sig.as_ptr(),
                data.as_ptr(),
                data.len() as u32,
            )
        };
        res == 0
    }
    fn recover_pub_from_sig(
        sig: &[u8; SIG_LEN],
        digest: &[u8; DIGEST_LEN],
        recid: u8,
    ) -> Option<[u8; ECDSA_PUBKEY_UNCOMPRESSED_LEN]> {
        let mut out = [0; ECDSA_PUBKEY_UNCOMPRESSED_LEN];
        let res = unsafe {
            let curve = Self::curve_lock();
            sys::ecdsa_recover_pub_from_sig(
                curve.as_ptr(),
                out.as_mut_ptr(),
                sig.as_ptr(),
                digest.as_ptr(),
                recid as i32,
            )
        };
        if res == 0 {
            Some(out)
        } else {
            None
        }
    }
}

impl<T> EcdsaCurveExt for T where T: EcdsaCurve {}

macro_rules! ecdsa_curve {
    ($name:ident, $curve:path, $info:path, $name_ptr:path) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name;
        impl EcdsaCurve for $name {
            #[inline]
            unsafe fn curve_lock() -> EcdsaCurveLock {
                EcdsaCurveLock {
                    curve: &$curve,
                    _lock: ECDSA_CURVE_LOCK.lock().unwrap(),
                }
            }
        }
        impl Curve for $name {
            type PublicKey = EcdsaPublicKey<Self>;
            type PrivateKey = EcdsaPrivateKey<Self>;
            type CurveInfoLock = EcdsaCurveInfoLock;
            #[inline]
            unsafe fn curve_info_lock() -> EcdsaCurveInfoLock {
                EcdsaCurveInfoLock {
                    info: &$info,
                    lock: Self::curve_lock(),
                }
            }
            #[inline]
            unsafe fn name_ptr() -> *const c_char {
                $name_ptr.as_ptr()
            }
        }
    };
}
ecdsa_curve!(
    Secp256k1,
    sys::secp256k1,
    sys::secp256k1_info,
    sys::SECP256K1_NAME
);
ecdsa_curve!(
    Nist256p1,
    sys::nist256p1,
    sys::nist256p1_info,
    sys::NIST256P1_NAME
);

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
        is_canonical: Option<IsCanonicalFn>,
    ) -> Option<RecoverableSignature<C>> {
        C::sign(&self.bytes, H::hasher_type(), data.as_ref(), is_canonical)
            .map(|(sig, by)| RecoverableSignature::new(Signature::from_bytes(sig), by))
    }
    pub fn sign_digest(
        &self,
        digest: &Digest,
        is_canonical: Option<IsCanonicalFn>,
    ) -> Option<RecoverableSignature<C>> {
        C::sign_digest(&self.bytes, digest.as_bytes(), is_canonical)
            .map(|(sig, by)| RecoverableSignature::new(Signature::from_bytes(sig), by))
    }
}

impl<C: EcdsaCurve> PrivateKey for EcdsaPrivateKey<C> {
    type SerializedSize = U32;
    #[inline]
    fn from_bytes_unchecked(bytes: [u8; HDNODE_PRIVKEY_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
    #[inline]
    fn to_bytes(self) -> [u8; HDNODE_PRIVKEY_LEN] {
        self.bytes
    }
    #[inline]
    fn serialize(&self) -> GenericArray<u8, Self::SerializedSize> {
        self.bytes.into()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EcdsaPublicKey<C: EcdsaCurve> {
    bytes: [u8; ECDSA_PUBKEY_COMPRESSED_LEN],
    curve: PhantomData<C>,
}

impl<C: EcdsaCurve> EcdsaPublicKey<C> {
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        C::read_public_key(slice).map(|point| {
            let mut out = [0; ECDSA_PUBKEY_COMPRESSED_LEN];
            unsafe {
                sys::compress_coords(&point, out.as_mut_ptr());
                Self::from_bytes_unchecked(out)
            }
        })
    }
    #[inline]
    pub unsafe fn from_bytes_unchecked(bytes: [u8; ECDSA_PUBKEY_COMPRESSED_LEN]) -> Self {
        Self {
            bytes,
            curve: PhantomData,
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
    pub fn verify_digest(&self, signature: &Signature<C>, digest: &Digest) -> bool {
        C::verify_digest(&self.bytes, &signature.serialize(), digest.as_bytes())
    }
    pub fn verify<H: HashingAlgorithm, D: AsRef<[u8]>>(
        &self,
        signature: &Signature<C>,
        data: D,
    ) -> bool {
        C::verify(
            &self.bytes,
            H::hasher_type(),
            &signature.serialize(),
            data.as_ref(),
        )
    }
}

impl<C: EcdsaCurve> PublicKey for EcdsaPublicKey<C> {
    type SerializedSize = U33;
    type UncompressedSize = U65;
    #[inline]
    fn from_bytes_unchecked(bytes: [u8; HDNODE_PUBKEY_LEN]) -> Self {
        unsafe { Self::from_bytes_unchecked(bytes) }
    }
    #[inline]
    fn to_bytes(self) -> [u8; HDNODE_PUBKEY_LEN] {
        self.bytes
    }
    fn serialize(&self) -> GenericArray<u8, Self::SerializedSize> {
        GenericArray::clone_from_slice(&self.serialize())
    }
    fn serialize_uncompressed(&self) -> GenericArray<u8, Self::UncompressedSize> {
        GenericArray::clone_from_slice(&self.serialize_uncompressed())
    }
}

impl<C: EcdsaCurve> fmt::Debug for EcdsaPublicKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaPublicKey")
            .field("bytes", &hex::encode(self.serialize()))
            .field("curve", &core::any::type_name::<C>())
            .finish()
    }
}

impl<C: EcdsaCurve> Signature<C> {
    pub fn serialize_der(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 << 7);
        unsafe {
            let len = sys::ecdsa_sig_to_der(self.bytes.as_ptr(), out.as_mut_ptr());
            out.set_len(len as usize);
        }
        out
    }
    pub fn from_der(der: &[u8]) -> Option<Self> {
        let mut out = [0; SIG_LEN];
        let res =
            unsafe { sys::ecdsa_sig_from_der(der.as_ptr(), der.len() as u64, out.as_mut_ptr()) };
        if res == 0 {
            Some(Self::from_bytes(out))
        } else {
            None
        }
    }
}

impl<C: EcdsaCurve> RecoverableSignature<C> {
    pub fn recover_public_key(&self, digest: &Digest) -> Option<EcdsaPublicKey<C>> {
        C::recover_pub_from_sig(
            self.signature().serialize(),
            digest.as_bytes(),
            self.recovery_byte(),
        )
        .and_then(|bytes| EcdsaPublicKey::from_slice(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::*;

    #[test]
    fn curve_name() {
        assert_eq!("secp256k1", Secp256k1::name());
        assert_eq!("nist256p1", Nist256p1::name());
    }

    fn public_key_test_vector<C: EcdsaCurve>(priv_key_hex: &str, x_hex: &str, y_hex: &str) {
        let priv_key =
            EcdsaPrivateKey::<C>::from_slice(&hex::decode(priv_key_hex).unwrap()).unwrap();
        let pub_key = priv_key.public_key();
        assert!(pub_key.is_valid());
        let pub_key = pub_key.serialize_uncompressed();
        assert_eq!(pub_key[1..33], hex::decode(x_hex).unwrap());
        assert_eq!(pub_key[33..], hex::decode(y_hex).unwrap());
    }

    #[test]
    fn secp256k1_public_key_test_vectors() {
        public_key_test_vector::<Secp256k1>(
            "AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522",
            "34F9460F0E4F08393D192B3C5133A6BA099AA0AD9FD54EBCCFACDFA239FF49C6",
            "0B71EA9BD730FD8923F6D25A7A91E7DD7728A960686CB5A901BB419E0F2CA232",
        );
        public_key_test_vector::<Secp256k1>(
            "7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3",
            "D74BF844B0862475103D96A611CF2D898447E288D34B360BC885CB8CE7C00575",
            "131C670D414C4546B88AC3FF664611B1C38CEB1C21D76369D7A7A0969D61D97D",
        );
        public_key_test_vector::<Secp256k1>(
            "6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D",
            "E8AECC370AEDD953483719A116711963CE201AC3EB21D3F3257BB48668C6A72F",
            "C25CAF2F0EBA1DDB2F0F3F47866299EF907867B7D27E95B3873BF98397B24EE1",
        );
        public_key_test_vector::<Secp256k1>(
            "376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC",
            "14890E61FCD4B0BD92E5B36C81372CA6FED471EF3AA60A3E415EE4FE987DABA1",
            "297B858D9F752AB42D3BCA67EE0EB6DCD1C2B7B0DBE23397E66ADC272263F982",
        );
        public_key_test_vector::<Secp256k1>(
            "1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9",
            "F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3",
            "F449A8376906482A84ED01479BD18882B919C140D638307F0C0934BA12590BDE",
        );
    }

    #[test]
    fn secp256k1_public_key_from_slice() {
        let public_key_compressed =
            hex::decode("02F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3")
                .unwrap();
        let public_key_uncompressed = hex::decode("04F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3F449A8376906482A84ED01479BD18882B919C140D638307F0C0934BA12590BDE").unwrap();
        let public_key1 = EcdsaPublicKey::<Secp256k1>::from_slice(&public_key_compressed).unwrap();
        let public_key2 =
            EcdsaPublicKey::<Secp256k1>::from_slice(&public_key_uncompressed).unwrap();
        assert_eq!(public_key1.serialize(), public_key2.serialize());
        assert_eq!(
            public_key1.serialize_uncompressed(),
            public_key2.serialize_uncompressed()
        );
    }

    #[test]
    fn secp256k1_public_key_trait() {
        let public_key_compressed =
            hex::decode("02F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3")
                .unwrap();
        let public_key_uncompressed = hex::decode("04F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3F449A8376906482A84ED01479BD18882B919C140D638307F0C0934BA12590BDE").unwrap();
        let public_key = EcdsaPublicKey::<Secp256k1>::from_slice(&public_key_compressed).unwrap();
        assert_eq!(
            PublicKey::serialize(&public_key).to_vec(),
            public_key_compressed
        );
        assert_eq!(
            PublicKey::serialize_uncompressed(&public_key).to_vec(),
            public_key_uncompressed
        );
    }

    #[test]
    fn nist256p1_public_key_test_vectors() {
        public_key_test_vector::<Nist256p1>(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        )
    }

    fn signature_test_vector<C: EcdsaCurve>(
        priv_key_hex: &str,
        message: &[u8],
        r_hex: &str,
        s_hex: &str,
    ) {
        let priv_key =
            EcdsaPrivateKey::<C>::from_slice(&hex::decode(priv_key_hex).unwrap()).unwrap();
        let digest = digest::<Sha2, _>(message.as_ref());
        let signature = priv_key.sign_digest(&digest, None).unwrap();
        let sig = signature.serialize();
        assert_eq!(sig[..32], hex::decode(r_hex).unwrap());
        assert_eq!(sig[32..], hex::decode(s_hex).unwrap());

        let signature2 = priv_key.sign::<Sha2, _>(message.as_ref(), None).unwrap();
        assert_eq!(signature.serialize(), signature2.serialize());

        let der = signature.serialize_der();
        assert!(der.len() > 0);
        let signature3 = Signature::<C>::from_der(&der).unwrap();
        assert_eq!(signature.serialize(), signature3.serialize());

        let pub_key = priv_key.public_key();
        assert!(pub_key.verify::<Sha2, _>(&signature, message));
        assert!(pub_key.verify_digest(&signature, &digest));

        let pub_key2 = signature.recover_public_key(&digest).unwrap();
        assert_eq!(pub_key.serialize(), pub_key2.serialize());
    }

    #[test]
    fn nist256p1_signature_test_vectors() {
        signature_test_vector::<Nist256p1>(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
            b"test",
            "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
            "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
        )
    }

    lazy_static! {
        static ref COUNTER: Mutex<u8> = Mutex::new(0);
    }

    fn test_is_canonical<C: EcdsaCurve>(_sig: RecoverableSignature<C>) -> bool {
        let mut counter = COUNTER.lock().unwrap();
        *counter += 1;
        if *counter < 5 {
            false
        } else {
            true
        }
    }

    #[test]
    fn nist256p1_signature_test_is_canonical() {
        let priv_key = EcdsaPrivateKey::<Nist256p1>::from_slice(
            &hex::decode("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
                .unwrap(),
        )
        .unwrap();
        let _ = priv_key
            .sign::<Sha2, _>(b"test", Some(Box::new(test_is_canonical)))
            .unwrap();
        assert_eq!(*COUNTER.lock().unwrap(), 5);
    }

    #[test]
    fn ecdsa_multi_thread() {
        let mut children = Vec::new();
        for _ in 0..10 {
            children.push(std::thread::spawn(|| {
                secp256k1_public_key_test_vectors();
                nist256p1_public_key_test_vectors();
                nist256p1_signature_test_vectors();
            }))
        }
        for child in children {
            child.join().unwrap();
        }
    }
}
