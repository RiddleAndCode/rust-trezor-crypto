use core::{fmt, mem};

pub const DIGEST_LEN: usize = 32;

pub trait HashingAlgorithm {
    #[doc(hidden)]
    fn hasher_type() -> sys::HasherType;
}

trait HashingAlgorithmExt: HashingAlgorithm {
    fn init() -> sys::Hasher {
        let mut hasher;
        unsafe {
            hasher = mem::zeroed();
            sys::hasher_Init(&mut hasher, Self::hasher_type());
        };
        hasher
    }
    fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
        let mut out = [0; DIGEST_LEN];
        unsafe {
            sys::hasher_Raw(
                Self::hasher_type(),
                data.as_ptr(),
                data.len() as u64,
                out.as_mut_ptr(),
            )
        }
        out
    }
}

impl<T> HashingAlgorithmExt for T where T: HashingAlgorithm {}

macro_rules! hashing_algo {
    ($name:ident, $ty:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;
        impl HashingAlgorithm for $name {
            fn hasher_type() -> sys::HasherType {
                $ty
            }
        }
    };
}
hashing_algo!(Blake, sys::HasherType_HASHER_BLAKE);
hashing_algo!(Blake2b, sys::HasherType_HASHER_BLAKE2B);
hashing_algo!(Blake2bPersonal, sys::HasherType_HASHER_BLAKE2B_PERSONAL);
hashing_algo!(BlakeRipemd, sys::HasherType_HASHER_BLAKE_RIPEMD);
hashing_algo!(Blaked, sys::HasherType_HASHER_BLAKED);
hashing_algo!(GroestldTrunc, sys::HasherType_HASHER_GROESTLD_TRUNC);
hashing_algo!(Sha2, sys::HasherType_HASHER_SHA2);
hashing_algo!(Sha2Ripemd, sys::HasherType_HASHER_SHA2_RIPEMD);
hashing_algo!(Sha2d, sys::HasherType_HASHER_SHA2D);
hashing_algo!(Sha3, sys::HasherType_HASHER_SHA3);
hashing_algo!(Sha3k, sys::HasherType_HASHER_SHA3K);
hashing_algo!(NoHash, 0);

pub struct Hasher {
    hasher: sys::Hasher,
}

impl Hasher {
    #[inline]
    fn new(hasher: sys::Hasher) -> Self {
        Self { hasher }
    }
    pub fn init<H: HashingAlgorithm>() -> Self {
        Self::new(H::init())
    }
    pub fn update<D: AsRef<[u8]>>(&mut self, data: D) {
        let data = data.as_ref();
        unsafe { sys::hasher_Update(&mut self.hasher, data.as_ptr(), data.len() as u64) }
    }
    pub fn reset(&mut self) {
        unsafe { sys::hasher_Reset(&mut self.hasher) }
    }
    pub fn finish(&mut self) -> Digest {
        let mut out = [0; DIGEST_LEN];
        unsafe {
            sys::hasher_Final(&mut self.hasher, out.as_mut_ptr());
        }
        Digest::from_bytes(out)
    }
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO add hasher type
        f.debug_struct("Hasher").finish()
    }
}

pub fn digest<H: HashingAlgorithm, D: AsRef<[u8]>>(data: D) -> Digest {
    Digest::from_bytes(H::digest(data.as_ref()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Digest {
    bytes: [u8; DIGEST_LEN],
}

impl Digest {
    #[inline]
    pub fn from_bytes(bytes: [u8; DIGEST_LEN]) -> Self {
        Self { bytes }
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Digest")
            .field(&hex::encode(&self.bytes))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha3_test_vector(input: impl AsRef<[u8]>, expected_hex: impl AsRef<str>) {
        let digest = digest::<Sha3, _>(input);
        assert_eq!(
            hex::encode(digest.as_bytes()),
            expected_hex.as_ref().to_lowercase()
        )
    }

    #[test]
    fn sha3_256_test_vectors() {
        sha3_test_vector(
            b"abc",
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        );
        sha3_test_vector(
            b"",
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        );
        sha3_test_vector(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
        );
        sha3_test_vector(
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"
        );
    }

    #[test]
    fn sha3_256_multi_threaded() {
        let mut children = Vec::new();
        for _ in 0..10 {
            children.push(std::thread::spawn(|| {
                sha3_test_vector(
                    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                    "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
                );
            }))
        }
        for child in children {
            child.join().unwrap();
        }
    }
}
