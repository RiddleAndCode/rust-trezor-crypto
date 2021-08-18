use core::marker::PhantomData;

pub const SIG_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature<C> {
    pub(crate) bytes: [u8; SIG_LEN],
    _curve: PhantomData<C>,
}

impl<C> Signature<C> {
    #[inline]
    pub fn from_bytes(bytes: [u8; SIG_LEN]) -> Self {
        Self {
            bytes,
            _curve: PhantomData,
        }
    }
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == SIG_LEN {
            let mut bytes = [0; SIG_LEN];
            bytes.copy_from_slice(slice);
            Some(Self::from_bytes(bytes))
        } else {
            None
        }
    }
    pub fn serialize(&self) -> &[u8; SIG_LEN] {
        &self.bytes
    }
    #[inline]
    pub(crate) fn cast<U>(self) -> Signature<U> {
        Signature::from_bytes(self.bytes)
    }
}
