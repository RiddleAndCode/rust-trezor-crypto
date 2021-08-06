use crate::ecdsa::{EcdsaCurveLock, RecoverableSignature, Signature, ECDSA_SIG_LEN};
use std::sync::Mutex;

pub type IsCanonicalFn = Box<dyn Fn(&RecoverableSignature) -> bool + Send + Sync>;

lazy_static! {
    static ref ECDSA_IS_CANONICAL_FN: Mutex<Option<IsCanonicalFn>> = Mutex::new(None);
}

impl EcdsaCurveLock {
    pub(crate) fn set_is_canonical_func(&self, func: Option<IsCanonicalFn>) {
        let mut canon_func = ECDSA_IS_CANONICAL_FN.lock().unwrap();
        *canon_func = func;
    }

    pub(crate) extern "C" fn is_canonical(by: u8, sig_ptr: *mut u8) -> i32 {
        let callback = ECDSA_IS_CANONICAL_FN.lock().unwrap();
        if let Some(ref cb) = callback.as_ref() {
            let sig = unsafe {
                Signature::from_slice(core::slice::from_raw_parts(sig_ptr, ECDSA_SIG_LEN)).unwrap()
            };
            let signature = RecoverableSignature::new(sig, by);
            if cb(&signature) {
                1
            } else {
                0
            }
        } else {
            1
        }
    }
}

pub fn is_canonical_ethereum(sig: &RecoverableSignature) -> bool {
    return (sig.recovery_byte() & 2) == 0;
}

pub fn is_canonical_eos(sig: &RecoverableSignature) -> bool {
    let signature = sig.serialize();
    return (signature[0] & 0x80) == 0
        && !(signature[0] == 0 && (signature[1] & 0x80) == 0)
        && (signature[32] & 0x80) == 0
        && !(signature[32] == 0 && (signature[33] & 0x80) == 0);
}
