use super::curve::{EcdsaCurve, EcdsaCurveInfoLock, EcdsaPrivateKey, EcdsaPublicKey};
use std::marker::PhantomData;
use std::ops;

struct HDNodeRef<'a> {
    hd_node: &'a sys::HDNode,
    lock: EcdsaCurveInfoLock,
}

impl<'a> HDNodeRef<'a> {
    #[inline]
    fn curve_info(&self) -> &EcdsaCurveInfoLock {
        &self.lock
    }
    #[inline]
    fn as_ptr(&self) -> *const sys::HDNode {
        self.hd_node
    }
}

impl<'a> ops::Deref for HDNodeRef<'a> {
    type Target = sys::HDNode;
    fn deref(&self) -> &Self::Target {
        self.hd_node
    }
}

struct HDNodeMutRef<'a> {
    hd_node: &'a mut sys::HDNode,
    lock: EcdsaCurveInfoLock,
}

impl<'a> HDNodeMutRef<'a> {
    #[inline]
    fn curve_info(&self) -> &EcdsaCurveInfoLock {
        &self.lock
    }
    #[inline]
    fn as_ptr(&mut self) -> *mut sys::HDNode {
        self.hd_node
    }
}

impl<'a> ops::Deref for HDNodeMutRef<'a> {
    type Target = sys::HDNode;
    fn deref(&self) -> &Self::Target {
        self.hd_node
    }
}

impl<'a> ops::DerefMut for HDNodeMutRef<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.hd_node
    }
}

pub struct HDNode<C: EcdsaCurve> {
    hd_node: sys::HDNode,
    curve: PhantomData<C>,
}

impl<C: EcdsaCurve> HDNode<C> {
    pub fn from_seed(seed: &[u8]) -> Option<Self> {
        let mut this: Self;
        let res = unsafe {
            this = std::mem::zeroed();
            let mut hd_node = this.borrow_mut();
            sys::hdnode_from_seed(
                seed.as_ptr(),
                seed.len() as i32,
                C::name_ptr(),
                hd_node.as_ptr(),
            )
        };
        if res == 1 {
            this.fill_public_key();
            Some(this)
        } else {
            None
        }
    }
    #[inline]
    pub fn depth(&self) -> u32 {
        self.hd_node.depth
    }
    #[inline]
    pub fn child_num(&self) -> u32 {
        self.hd_node.child_num
    }
    #[inline]
    pub fn chain_code(&self) -> [u8; 32] {
        self.hd_node.chain_code
    }
    #[inline]
    pub fn private_key_extension(&self) -> [u8; 32] {
        self.hd_node.private_key_extension
    }
    pub fn private_key(&self) -> EcdsaPrivateKey<C> {
        EcdsaPrivateKey::from_bytes(self.hd_node.private_key)
    }
    fn fill_public_key(&mut self) {
        unsafe {
            let mut hd_node = self.borrow_mut();
            sys::hdnode_fill_public_key(hd_node.as_ptr())
        }
    }
    pub fn public_key(&self) -> EcdsaPublicKey<C> {
        unsafe { EcdsaPublicKey::from_bytes_unchecked(self.hd_node.public_key) }
    }
    unsafe fn borrow(&self) -> HDNodeRef {
        HDNodeRef {
            hd_node: &self.hd_node,
            lock: C::curve_info_lock(),
        }
    }
    unsafe fn borrow_mut(&mut self) -> HDNodeMutRef {
        HDNodeMutRef {
            hd_node: &mut self.hd_node,
            lock: C::curve_info_lock(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdsa::Secp256k1;

    #[test]
    fn from_seed() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let hd_node = HDNode::<Secp256k1>::from_seed(&seed).unwrap();
        assert_eq!(
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
            hex::encode(hd_node.chain_code())
        );
        assert_eq!(
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
            hex::encode(hd_node.public_key().serialize())
        );
    }
}
