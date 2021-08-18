use super::Secp256k1;
use crate::curve::CurveLock;
use crate::signature::{RecoverableSignature, Signature, SIG_LEN};
use std::sync::Mutex;

pub type IsCanonicalFn = Box<dyn Fn(RecoverableSignature<Secp256k1>) -> bool + Send + Sync>;

lazy_static! {
    static ref ECDSA_IS_CANONICAL_FN: Mutex<Option<IsCanonicalFn>> = Mutex::new(None);
}

type RawCanonicalFn = unsafe extern "C" fn(u8, *mut u8) -> i32;

pub(crate) extern "C" fn is_canonical(by: u8, sig_ptr: *mut u8) -> i32 {
    let callback = ECDSA_IS_CANONICAL_FN.lock().unwrap();
    if let Some(ref cb) = callback.as_ref() {
        let sig = unsafe {
            Signature::from_slice(core::slice::from_raw_parts(sig_ptr, SIG_LEN)).unwrap()
        };
        let signature = RecoverableSignature::new(sig, by);
        if cb(signature) {
            1
        } else {
            0
        }
    } else {
        1
    }
}

pub(crate) trait CanonicalFnLock {
    #[doc(hidden)]
    fn is_canonical_fn(&self, func: Option<IsCanonicalFn>) -> Option<RawCanonicalFn> {
        if func.is_some() {
            let mut canon_func = ECDSA_IS_CANONICAL_FN.lock().unwrap();
            *canon_func = func;
            Some(is_canonical)
        } else {
            None
        }
    }
}

impl<T> CanonicalFnLock for T where T: CurveLock {}

pub fn is_canonical_ethereum(sig: RecoverableSignature<Secp256k1>) -> bool {
    return (sig.recovery_byte() & 2) == 0;
}

pub fn is_canonical_eos(sig: RecoverableSignature<Secp256k1>) -> bool {
    let signature = sig.serialize();
    return (signature[0] & 0x80) == 0
        && !(signature[0] == 0 && (signature[1] & 0x80) == 0)
        && (signature[32] & 0x80) == 0
        && !(signature[32] == 0 && (signature[33] & 0x80) == 0);
}
