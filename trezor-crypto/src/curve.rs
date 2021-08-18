use std::ffi::CStr;
use std::os::raw::c_char;

pub trait Curve {
    #[doc(hidden)]
    type CurveInfoLock;
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
