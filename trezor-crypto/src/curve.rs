use crate::hd_node::{HDNODE_PRIVKEY_LEN, HDNODE_PUBKEY_LEN};
use std::ffi::CStr;
use std::os::raw::c_char;

#[doc(hidden)]
pub trait CurveLock {}

#[doc(hidden)]
pub trait CurveInfoLock {
    type CurveLock: CurveLock;
    unsafe fn curve(&self) -> &Self::CurveLock;
}

pub trait PublicKey: Sized {
    #[doc(hidden)]
    fn from_bytes_unchecked(bytes: [u8; HDNODE_PUBKEY_LEN]) -> Self;
    #[doc(hidden)]
    fn to_bytes(self) -> [u8; HDNODE_PUBKEY_LEN];
}

pub trait PrivateKey: Sized {
    #[doc(hidden)]
    fn from_bytes_unchecked(bytes: [u8; HDNODE_PRIVKEY_LEN]) -> Self;
    #[doc(hidden)]
    fn to_bytes(self) -> [u8; HDNODE_PRIVKEY_LEN];
}

pub trait Curve {
    type PublicKey: PublicKey;
    type PrivateKey: PrivateKey;
    #[doc(hidden)]
    type CurveInfoLock: CurveInfoLock;
    #[doc(hidden)]
    unsafe fn curve_info_lock() -> Self::CurveInfoLock;
    #[doc(hidden)]
    unsafe fn name_ptr() -> *const c_char;
    #[doc(hidden)]
    unsafe fn name_c_str() -> &'static CStr {
        CStr::from_ptr(Self::name_ptr())
    }
    fn name() -> &'static str {
        unsafe { Self::name_c_str() }.to_str().unwrap()
    }
}
