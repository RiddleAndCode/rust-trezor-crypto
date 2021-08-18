use crate::curve::{Curve, CurveInfoLock, PrivateKey, PublicKey};
use crate::ecdsa::canonical::{CanonicalFnLock, IsCanonicalFn};
use crate::hasher::{Digest, HashingAlgorithm};
use crate::signature::{RecoverableSignature, Signature, SIG_LEN};
use derivation_path::{ChildIndex, DerivationPath};
use std::marker::PhantomData;
use std::ops;

pub(crate) const HDNODE_PRIVKEY_LEN: usize = 32;
pub(crate) const HDNODE_PUBKEY_LEN: usize = 33;

struct HDNodeRef<'a, C: Curve> {
    hd_node: &'a sys::HDNode,
    lock: C::CurveInfoLock,
}

impl<'a, C: Curve> HDNodeRef<'a, C> {
    #[inline]
    fn curve_info(&self) -> &C::CurveInfoLock {
        &self.lock
    }
    #[inline]
    fn as_ptr(&self) -> *const sys::HDNode {
        self.hd_node
    }
}

impl<'a, C: Curve> ops::Deref for HDNodeRef<'a, C> {
    type Target = sys::HDNode;
    fn deref(&self) -> &Self::Target {
        self.hd_node
    }
}

struct HDNodeMutRef<'a, C: Curve> {
    hd_node: &'a mut sys::HDNode,
    lock: C::CurveInfoLock,
}

impl<'a, C: Curve> HDNodeMutRef<'a, C> {
    #[inline]
    fn curve_info(&self) -> &C::CurveInfoLock {
        &self.lock
    }
    #[inline]
    fn as_ptr(&mut self) -> *mut sys::HDNode {
        self.hd_node
    }
}

impl<'a, C: Curve> ops::Deref for HDNodeMutRef<'a, C> {
    type Target = sys::HDNode;
    fn deref(&self) -> &Self::Target {
        self.hd_node
    }
}

impl<'a, C: Curve> ops::DerefMut for HDNodeMutRef<'a, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.hd_node
    }
}

pub struct HDNode<C: Curve> {
    hd_node: sys::HDNode,
    curve: PhantomData<C>,
}

impl<C: Curve> HDNode<C> {
    #[inline]
    pub fn depth(&self) -> u8 {
        self.hd_node.depth as u8
    }

    #[inline]
    pub fn child_index(&self) -> ChildIndex {
        ChildIndex::from_bits(self.hd_node.child_num)
    }

    #[inline]
    pub fn chain_code(&self) -> [u8; 32] {
        self.hd_node.chain_code
    }

    #[inline]
    pub fn public_key(&self) -> C::PublicKey {
        C::PublicKey::from_bytes_unchecked(self.hd_node.public_key)
    }

    unsafe fn borrow(&self) -> HDNodeRef<C> {
        HDNodeRef {
            hd_node: &self.hd_node,
            lock: C::curve_info_lock(),
        }
    }

    unsafe fn borrow_mut(&mut self) -> HDNodeMutRef<C> {
        HDNodeMutRef {
            hd_node: &mut self.hd_node,
            lock: C::curve_info_lock(),
        }
    }
}

impl<C: Curve> Clone for HDNode<C> {
    fn clone(&self) -> Self {
        Self {
            hd_node: self.hd_node.clone(),
            curve: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct ExtendedPrivateKey<C: Curve>(HDNode<C>);

impl<C: Curve> ExtendedPrivateKey<C> {
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

    pub fn extend_public_key(&self) -> ExtendedPublicKey<C> {
        let mut inner = self.0.clone();
        inner.hd_node.private_key.fill(0);
        ExtendedPublicKey(inner)
    }

    #[inline]
    pub fn private_key_extension(&self) -> [u8; 32] {
        self.hd_node.private_key_extension
    }

    fn fill_public_key(&mut self) {
        unsafe {
            let mut hd_node = self.borrow_mut();
            sys::hdnode_fill_public_key(hd_node.as_ptr())
        }
    }

    pub fn derive_next(&mut self, index: ChildIndex) {
        unsafe {
            let mut hd_node = self.borrow_mut();
            sys::hdnode_private_ckd(hd_node.as_ptr(), index.to_bits());
        }
        self.fill_public_key();
    }

    pub fn derive(&mut self, path: &DerivationPath) {
        for index in path {
            self.derive_next(*index);
        }
    }

    #[inline]
    pub fn private_key(&self) -> C::PrivateKey {
        C::PrivateKey::from_bytes_unchecked(self.hd_node.private_key)
    }

    pub fn sign<H: HashingAlgorithm, D: AsRef<[u8]>>(
        &self,
        data: D,
        is_canonical: Option<IsCanonicalFn>,
    ) -> Option<RecoverableSignature<C>> {
        let data = data.as_ref();
        let hasher_type = H::hasher_type();
        let mut sig = [0; SIG_LEN];
        let mut by = 0;
        let res = unsafe {
            let hd_node = self.borrow();
            let curve_lock = hd_node.curve_info().curve();
            sys::hdnode_sign(
                hd_node.as_ptr() as *mut sys::HDNode,
                data.as_ptr(),
                data.len() as u32,
                hasher_type,
                sig.as_mut_ptr(),
                &mut by,
                curve_lock.is_canonical_fn(is_canonical),
            )
        };
        if res == 0 {
            Some(RecoverableSignature::new(Signature::from_bytes(sig), by))
        } else {
            None
        }
    }
    pub fn sign_digest(
        &self,
        digest: &Digest,
        is_canonical: Option<IsCanonicalFn>,
    ) -> Option<RecoverableSignature<C>> {
        let mut sig = [0; SIG_LEN];
        let mut by = 0;
        let res = unsafe {
            let hd_node = self.borrow();
            let curve_lock = hd_node.curve_info().curve();
            sys::hdnode_sign_digest(
                hd_node.as_ptr() as *mut sys::HDNode,
                digest.as_ref().as_ptr(),
                sig.as_mut_ptr(),
                &mut by,
                curve_lock.is_canonical_fn(is_canonical),
            )
        };
        if res == 0 {
            Some(RecoverableSignature::new(Signature::from_bytes(sig), by))
        } else {
            None
        }
    }
}

impl<C: Curve> ops::Deref for ExtendedPrivateKey<C> {
    type Target = HDNode<C>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C: Curve> ops::DerefMut for ExtendedPrivateKey<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Clone)]
pub struct ExtendedPublicKey<C: Curve>(HDNode<C>);

impl<C: Curve> ExtendedPublicKey<C> {
    pub fn derive_next(&mut self, index: ChildIndex) {
        unsafe {
            let mut hd_node = self.borrow_mut();
            sys::hdnode_public_ckd(hd_node.as_ptr(), index.to_bits());
        }
    }

    pub fn derive(&mut self, path: &DerivationPath) {
        for index in path {
            self.derive_next(*index);
        }
    }
}

impl<C: Curve> ops::Deref for ExtendedPublicKey<C> {
    type Target = HDNode<C>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C: Curve> ops::DerefMut for ExtendedPublicKey<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdsa::Secp256k1;

    #[test]
    fn derive_next() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let mut hd_node = ExtendedPrivateKey::<Secp256k1>::from_seed(&seed).unwrap();
        assert_eq!(
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
            hex::encode(hd_node.chain_code())
        );
        assert_eq!(
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
            hex::encode(hd_node.public_key().serialize())
        );
        hd_node.derive_next(ChildIndex::Hardened(0));
        assert_eq!(
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
            hex::encode(hd_node.chain_code())
        );
        assert_eq!(
            "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
            hex::encode(hd_node.public_key().serialize())
        );
    }

    #[test]
    fn derive() {
        let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let mut hd_node = ExtendedPrivateKey::<Secp256k1>::from_seed(&seed).unwrap();
        assert_eq!(
            "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
            hex::encode(hd_node.chain_code())
        );
        assert_eq!(
            "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
            hex::encode(hd_node.public_key().serialize())
        );
        hd_node.derive(&"m/0/2147483647'/1/2147483646'/2".parse().unwrap());
        assert_eq!(
            "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
            hex::encode(hd_node.chain_code())
        );
        assert_eq!(
            "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
            hex::encode(hd_node.public_key().serialize())
        );
    }
}
