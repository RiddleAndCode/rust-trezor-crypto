use crate::bip39::Mnemonic;
use crate::curve::{Curve, CurveInfoLock, PrivateKey, PublicKey};
use crate::ecdsa::canonical::{CanonicalFnLock, IsCanonicalFn};
use crate::hasher::{Digest, HashingAlgorithm};
use crate::signature::{RecoverableSignature, Signature, SIG_LEN};
use derivation_path::{ChildIndex, DerivationPath};
use std::marker::PhantomData;
use std::{fmt, ops};

pub(crate) const HDNODE_PRIVKEY_LEN: usize = 32;
pub(crate) const HDNODE_PUBKEY_LEN: usize = 33;
pub const CHAIN_CODE_LEN: usize = 32;
pub const PRIV_KEY_EXT_LEN: usize = 32;

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
    /// WARNING: Should only be used for functions that fill the public key
    #[inline]
    unsafe fn as_mut_ptr(&self) -> *mut sys::HDNode {
        self.as_ptr() as *mut sys::HDNode
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
    _lock: C::CurveInfoLock,
}

impl<'a, C: Curve> HDNodeMutRef<'a, C> {
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
    unsafe fn zeroed() -> Self {
        let hd_node = std::mem::zeroed();
        Self {
            hd_node,
            curve: PhantomData,
        }
    }
    #[inline]
    pub fn depth(&self) -> u8 {
        self.hd_node.depth as u8
    }

    #[inline]
    pub fn child_index(&self) -> ChildIndex {
        ChildIndex::from_bits(self.hd_node.child_num)
    }

    #[inline]
    pub fn chain_code(&self) -> [u8; CHAIN_CODE_LEN] {
        self.hd_node.chain_code
    }

    #[inline]
    pub fn public_key(&self) -> C::PublicKey {
        C::PublicKey::from_bytes_unchecked(self.hd_node.public_key)
    }

    #[inline]
    pub fn fingerprint(&self) -> u32 {
        unsafe {
            let hd_node = self.borrow();
            sys::hdnode_fingerprint(hd_node.as_mut_ptr())
        }
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
            _lock: C::curve_info_lock(),
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

pub struct ExtendedPrivateKey<C: Curve>(HDNode<C>);

impl<C: Curve> ExtendedPrivateKey<C> {
    pub fn new(
        private_key: C::PrivateKey,
        chain_code: [u8; CHAIN_CODE_LEN],
        child_index: ChildIndex,
        depth: u8,
    ) -> Option<Self> {
        let private_key_bytes = private_key.to_bytes();
        let (inner, res) = unsafe {
            let mut inner = HDNode::zeroed();
            let mut hd_node = inner.borrow_mut();
            let res = sys::hdnode_from_xprv(
                depth as u32,
                child_index.to_bits(),
                chain_code.as_ptr(),
                private_key_bytes.as_ptr(),
                C::name_ptr(),
                hd_node.as_ptr(),
            );
            (inner, res)
        };
        if res == 1 {
            let mut this = Self(inner);
            this.fill_public_key();
            Some(this)
        } else {
            None
        }
    }

    pub fn from_seed(seed: &[u8]) -> Option<Self> {
        let mut this: Self;
        let res = unsafe {
            this = std::mem::zeroed();
            let mut hd_node = this.borrow_mut();
            if C::is_cardano() {
                sys::hdnode_from_seed_cardano(seed.as_ptr(), seed.len() as i32, hd_node.as_ptr())
            } else {
                sys::hdnode_from_seed(
                    seed.as_ptr(),
                    seed.len() as i32,
                    C::name_ptr(),
                    hd_node.as_ptr(),
                )
            }
        };
        if res == 1 {
            this.fill_public_key();
            Some(this)
        } else {
            None
        }
    }

    pub fn from_mnemonic(mnemonic: &Mnemonic, password: &str) -> Option<Self> {
        let mut this: Self;
        if C::is_cardano() {
            let res = unsafe {
                this = std::mem::zeroed();
                let mut hd_node = this.borrow_mut();
                let pass = password.as_bytes();
                let entropy = mnemonic.entropy_cardano();
                sys::hdnode_from_entropy_cardano_icarus(
                    pass.as_ptr(),
                    pass.len() as i32,
                    entropy.as_ptr(),
                    entropy.len() as i32,
                    hd_node.as_ptr(),
                )
            };
            if res == 1 {
                this.fill_public_key();
                Some(this)
            } else {
                None
            }
        } else {
            Self::from_seed(&mnemonic.seed(password))
        }
    }

    pub fn extend_public_key(&self) -> ExtendedPublicKey<C> {
        let mut inner = self.0.clone();
        inner.hd_node.private_key.fill(0);
        ExtendedPublicKey(inner)
    }

    #[inline]
    pub fn private_key_extension(&self) -> [u8; PRIV_KEY_EXT_LEN] {
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
            if C::is_cardano() {
                sys::hdnode_private_ckd_cardano(hd_node.as_ptr(), index.to_bits());
            } else {
                sys::hdnode_private_ckd(hd_node.as_ptr(), index.to_bits());
            }
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
                hd_node.as_mut_ptr(),
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
                hd_node.as_mut_ptr(),
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

impl<C: Curve> Clone for ExtendedPrivateKey<C> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
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

pub struct ExtendedPublicKey<C: Curve>(HDNode<C>);

impl<C: Curve> ExtendedPublicKey<C> {
    pub fn new(
        public_key: C::PublicKey,
        chain_code: [u8; CHAIN_CODE_LEN],
        child_index: ChildIndex,
        depth: u8,
    ) -> Option<Self> {
        let public_key_bytes = public_key.to_bytes();
        let (inner, res) = unsafe {
            let mut inner = HDNode::zeroed();
            let mut hd_node = inner.borrow_mut();
            let res = sys::hdnode_from_xpub(
                depth as u32,
                child_index.to_bits(),
                chain_code.as_ptr(),
                public_key_bytes.as_ptr(),
                C::name_ptr(),
                hd_node.as_ptr(),
            );
            (inner, res)
        };
        if res == 1 {
            Some(Self(inner))
        } else {
            None
        }
    }

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

impl<C: Curve> Clone for ExtendedPublicKey<C> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
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

impl<C> fmt::Debug for HDNode<C>
where
    C: Curve,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HDNode")
            .field("chain_code", &hex::encode(&self.chain_code()))
            .field("child_index", &self.child_index())
            .field("depth", &self.depth())
            .field("fingerprint", &self.fingerprint())
            .field("public_key", &hex::encode(&self.public_key().serialize()))
            .finish()
    }
}

impl<C> fmt::Debug for ExtendedPublicKey<C>
where
    C: Curve,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ExtendedPublicKey").field(&self.0).finish()
    }
}

impl<C> fmt::Debug for ExtendedPrivateKey<C>
where
    C: Curve,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ExtendedPrivateKey").field(&self.0).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39::Mnemonic;
    use crate::ecdsa::Secp256k1;
    use crate::ed25519::Ed25519Cardano;
    use crate::hasher::Sha2;

    fn dignity_mnemonic() -> Mnemonic {
        Mnemonic::from_phrase("dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic").unwrap()
    }

    #[test]
    fn derive_next() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let mut hd_node = ExtendedPrivateKey::<Secp256k1>::from_seed(&seed).unwrap();
        assert_eq!(hd_node.depth(), 0);
        assert_eq!(hd_node.fingerprint(), 0x3442193e);
        assert_eq!(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
            hex::encode(hd_node.private_key().to_bytes())
        );
        assert_eq!(
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
            hex::encode(hd_node.chain_code())
        );
        assert_eq!(
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
            hex::encode(hd_node.public_key().serialize())
        );
        hd_node.derive_next(ChildIndex::Hardened(0));
        assert_eq!(hd_node.depth(), 1);
        assert_eq!(hd_node.fingerprint(), 0x5c1bd648);
        assert_eq!(
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
            hex::encode(hd_node.private_key().to_bytes())
        );
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
        assert_eq!(hd_node.depth(), 0);
        assert_eq!(hd_node.fingerprint(), 0xbd16bee5);
        assert_eq!(
            "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
            hex::encode(hd_node.private_key().to_bytes())
        );
        assert_eq!(
            "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
            hex::encode(hd_node.chain_code())
        );
        assert_eq!(
            "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
            hex::encode(hd_node.public_key().serialize())
        );
        hd_node.derive(&"m/0/2147483647'/1/2147483646'/2".parse().unwrap());
        assert_eq!(hd_node.depth(), 5);
        assert_eq!(hd_node.fingerprint(), 0x26132fdb);
        assert_eq!(
            "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
            hex::encode(hd_node.private_key().to_bytes())
        );
        assert_eq!(
            "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
            hex::encode(hd_node.chain_code())
        );
        assert_eq!(
            "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
            hex::encode(hd_node.public_key().serialize())
        );
    }

    #[test]
    fn from_xprv() {
        let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let hd_node = ExtendedPrivateKey::<Secp256k1>::from_seed(&seed).unwrap();
        let hd_node2 = ExtendedPrivateKey::<Secp256k1>::new(
            hd_node.private_key(),
            hd_node.chain_code(),
            hd_node.child_index(),
            hd_node.depth(),
        )
        .unwrap();
        assert_eq!(
            hd_node.private_key().to_bytes(),
            hd_node2.private_key().to_bytes()
        );
        assert_eq!(hd_node.public_key(), hd_node2.public_key());
        assert_eq!(hd_node.chain_code(), hd_node2.chain_code());
        assert_eq!(hd_node.depth(), hd_node2.depth());
        assert_eq!(
            hd_node.private_key_extension(),
            hd_node2.private_key_extension()
        );
        assert_eq!(hd_node.child_index(), hd_node2.child_index());
    }

    #[test]
    fn from_xpub() {
        let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let hd_node = ExtendedPrivateKey::<Secp256k1>::from_seed(&seed)
            .unwrap()
            .extend_public_key();
        let hd_node2 = ExtendedPublicKey::<Secp256k1>::new(
            hd_node.public_key(),
            hd_node.chain_code(),
            hd_node.child_index(),
            hd_node.depth(),
        )
        .unwrap();
        assert_eq!(hd_node.public_key(), hd_node2.public_key());
        assert_eq!(hd_node.chain_code(), hd_node2.chain_code());
        assert_eq!(hd_node.depth(), hd_node2.depth());
        assert_eq!(hd_node.child_index(), hd_node2.child_index());
    }

    #[test]
    fn sign() {
        let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let hd_node = ExtendedPrivateKey::<Secp256k1>::from_seed(&seed).unwrap();
        let message = b"hello";
        let signature = hd_node.sign::<Sha2, _>(message, None).unwrap();
        let signature2 = hd_node
            .private_key()
            .sign::<Sha2, _>(message, None)
            .unwrap();
        assert_eq!(signature, signature2);
    }

    #[test]
    fn dignity_secp256k1() {
        let mut hd_node =
            ExtendedPrivateKey::<Secp256k1>::from_mnemonic(&dignity_mnemonic(), "").unwrap();
        hd_node.derive(&"m/1852'/1815'/0'".parse().unwrap());
        assert_eq!(hd_node.depth(), 3);
        assert_eq!(
            &hd_node.chain_code(),
            hex::decode("0d27e09175aed7737fabe8dc833d034f32750e01179dfcf26c74bafada708d38")
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            &hd_node.public_key().serialize(),
            hex::decode("02ee2fdb748f9bc8648372cc79cbe543eed0401528a8ab91966f5135e55aac2d99")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn dignity_cardano() {
        let mut hd_node =
            ExtendedPrivateKey::<Ed25519Cardano>::from_mnemonic(&dignity_mnemonic(), "").unwrap();
        assert_eq!(hd_node.depth(), 0);
        assert_eq!(
            &hd_node.chain_code(),
            hex::decode("350df93ad0ebdbdd42d719badfec2670efe013902bdc05c838774d7118fb9ac8")
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            &hd_node.public_key().serialize(),
            hex::decode("41fe8c524e2e1b4c67ea2b0030f121515085ffa4861e2816dbaaeaf93428eb63")
                .unwrap()
                .as_slice()
        );
        hd_node.derive(&"m/1852'/1815'/0'".parse().unwrap());
        assert_eq!(hd_node.depth(), 3);
        assert_eq!(
            &hd_node.chain_code(),
            hex::decode("415b7d92ecc8539cac4fcc23f2f243a0cfc59125129b9fb297e05bcc8625a51e")
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            &hd_node.public_key().serialize(),
            hex::decode("80609213e0e94b2e49b03996fd57262fed51f34108d6167a69df6938a3435cb3")
                .unwrap()
                .as_slice()
        );
    }
}
