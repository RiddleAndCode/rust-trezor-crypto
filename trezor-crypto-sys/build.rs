#[cfg(feature = "generate-bindings")]
use std::env;

const BASE_DIR: &str = "trezor-firmware/crypto";
const SRC_LIST: &[&str] = &[
    "bignum",
    "ecdsa",
    "curves",
    "secp256k1",
    "nist256p1",
    "rand",
    "hmac",
    "bip32",
    "bip39",
    "pbkdf2",
    "base58",
    "base32",
    "address",
    "script",
    "ripemd160",
    "sha2",
    "sha3",
    "hasher",
    // "aes/aescrypt",
    // "aes/aeskey",
    // "aes/aestab",
    // "aes/aes_modes",
    // "ed25519-donna/curve25519-donna-32bit",
    // "ed25519-donna/curve25519-donna-helpers",
    // "ed25519-donna/modm-donna-32bit",
    // "ed25519-donna/ed25519-donna-basepoint-table",
    // "ed25519-donna/ed25519-donna-32bit-tables",
    // "ed25519-donna/ed25519-donna-impl-base",
    // "ed25519-donna/ed25519",
    // "ed25519-donna/curve25519-donna-scalarmult-base",
    // "ed25519-donna/ed25519-sha3",
    // "ed25519-donna/ed25519-keccak",
    "monero/base58",
    "monero/serialize",
    "monero/xmr",
    "monero/range_proof",
    "blake256",
    "blake2b",
    "blake2s",
    "chacha_drbg",
    "groestl",
    "chacha20poly1305/chacha20poly1305",
    "chacha20poly1305/chacha_merged",
    "chacha20poly1305/poly1305-donna",
    "chacha20poly1305/rfc7539",
    "rc4",
    "nem",
    "segwit_addr",
    "cash_addr",
    "memzero",
    "shamir",
    "hmac_drbg",
    "rfc6979",
    "slip39",
    "schnorr",
];

#[cfg(feature = "generate-bindings")]
const OPT_HEADERS: &[&str] = &["options"];

const DEFINITIONS: &[(&str, Option<&str>)] = &[
    ("USE_ETHEREUM", Some("1")),
    ("USE_GRAPHENE", Some("1")),
    ("USE_KECCAK", Some("1")),
    ("USE_MONERO", Some("1")),
    ("USE_NEM", Some("1")),
    ("USE_CARDANO", Some("1")),
    ("AES_128", None),
    ("AES_192", None),
];

fn main() {
    println!("cargo:rerun-if-changed={}", BASE_DIR);
    if cfg!(feature = "update-bindings") {
        println!("cargo:rerun-if-changed=generated");
    }

    // let openssl = pkg_config::probe_library("openssl").unwrap();

    let mut builder = cc::Build::new();
    for &file in SRC_LIST {
        builder.file(&format!("{}/{}.c", BASE_DIR, file));
    }
    for &(var, val) in DEFINITIONS {
        builder.define(var, val);
    }
    builder
        .include("./trezor-firmware/crypto")
        .opt_level(3)
        .compile("trezor-crypto");

    #[cfg(feature = "generate-bindings")]
    {
        let mut builder = bindgen::Builder::default();
        for &file in SRC_LIST.into_iter().chain(OPT_HEADERS.into_iter()) {
            let filename = format!("{}/{}.h", BASE_DIR, file);
            if std::path::Path::new(&filename).exists() {
                builder = builder.header(filename);
            }
        }
        for &(var, val) in DEFINITIONS {
            if let Some(val) = val {
                builder = builder.clang_arg(format!("-D{}={}", var, val));
            } else {
                builder = builder.clang_arg(format!("-D{}", var));
            }
        }
        let bindings = builder
            .clang_arg(format!("-I{}", BASE_DIR))
            .generate()
            .expect("unable to generate bindings");

        let out_path = if cfg!(feature = "update-bindings") {
            std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("generated")
        } else {
            std::path::PathBuf::from(env::var("OUT_DIR").unwrap())
        };

        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("couldn't write bindings!");
    }
}
