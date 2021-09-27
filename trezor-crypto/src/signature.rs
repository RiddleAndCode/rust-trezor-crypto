use core::marker::PhantomData;
use std::ops;

pub const SIG_LEN: usize = 64;

#[derive(Clone, Debug)]
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
    pub fn cast<U>(self) -> Signature<U> {
        Signature::from_bytes(self.bytes)
    }
}

impl<C, D> PartialEq<Signature<D>> for Signature<C> {
    fn eq(&self, other: &Signature<D>) -> bool {
        self.bytes == other.bytes
    }
}

impl<C> Eq for Signature<C> {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoverableSignature<C> {
    signature: Signature<C>,
    recovery_byte: u8,
}

impl<C> RecoverableSignature<C> {
    #[inline]
    pub fn new(signature: Signature<C>, recovery_byte: u8) -> Self {
        Self {
            signature,
            recovery_byte,
        }
    }
    #[inline]
    pub fn signature(&self) -> &Signature<C> {
        &self.signature
    }
    #[inline]
    pub fn recovery_byte(&self) -> u8 {
        self.recovery_byte
    }
    #[inline]
    pub fn cast<U>(self) -> RecoverableSignature<U> {
        RecoverableSignature::new(self.signature.cast(), self.recovery_byte)
    }
}

impl<C> ops::Deref for RecoverableSignature<C> {
    type Target = Signature<C>;
    fn deref(&self) -> &Signature<C> {
        self.signature()
    }
}
