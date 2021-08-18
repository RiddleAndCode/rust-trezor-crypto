use std::ffi::CStr;
use std::os::raw::c_char;

pub trait Curve {
    type CurveInfoLock;
    unsafe fn curve_info_lock() -> Self::CurveInfoLock;
    unsafe fn name_ptr() -> *const c_char;
    unsafe fn name_c_str() -> &'static CStr {
        CStr::from_ptr(Self::name_ptr())
    }
}
