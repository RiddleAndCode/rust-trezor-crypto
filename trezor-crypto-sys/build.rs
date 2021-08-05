#[cfg(feature = "generate-bindings")]
use std::env;

const BASE_DIR: &str = "trezor-firmware/crypto";
const SRC_LIST: &[&str] = &[
    "bignum.c",
    "ecdsa.c",
    "curves.c",
    "secp256k1.c",
    "nist256p1.c",
    "rand.c",
    "hmac.c",
    "bip32.c",
    "bip39.c",
    "pbkdf2.c",
    "base58.c",
    "base32.c",
    "address.c",
    "script.c",
    "ripemd160.c",
    "sha2.c",
    "sha3.c",
    "hasher.c",
    "aes/aescrypt.c",
    "aes/aeskey.c",
    "aes/aestab.c",
    "aes/aes_modes.c",
    "ed25519-donna/curve25519-donna-32bit.c",
    "ed25519-donna/curve25519-donna-helpers.c",
    "ed25519-donna/modm-donna-32bit.c",
    "ed25519-donna/ed25519-donna-basepoint-table.c",
    "ed25519-donna/ed25519-donna-32bit-tables.c",
    "ed25519-donna/ed25519-donna-impl-base.c",
    "ed25519-donna/ed25519.c",
    "ed25519-donna/curve25519-donna-scalarmult-base.c",
    "ed25519-donna/ed25519-sha3.c",
    "ed25519-donna/ed25519-keccak.c",
    "monero/base58.c",
    "monero/serialize.c",
    "monero/xmr.c",
    "monero/range_proof.c",
    "blake256.c",
    "blake2b.c",
    "blake2s.c",
    "chacha_drbg.c",
    "groestl.c",
    "chacha20poly1305/chacha20poly1305.c",
    "chacha20poly1305/chacha_merged.c",
    "chacha20poly1305/poly1305-donna.c",
    "chacha20poly1305/rfc7539.c",
    "rc4.c",
    "nem.c",
    "segwit_addr.c",
    "cash_addr.c",
    "memzero.c",
    "shamir.c",
    "hmac_drbg.c",
    "rfc6979.c",
    "slip39.c",
    "schnorr.c",
];
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
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed={}", BASE_DIR);
    if cfg!(feature = "update-bindings") {
        println!("cargo:rerun-if-changed=generated");
    }

    let mut builder = cc::Build::new();
    for &file in SRC_LIST {
        builder.file(&format!("{}/{}", BASE_DIR, file));
    }
    for &(var, val) in DEFINITIONS {
        builder.define(var, val);
    }
    builder
        .include("./trezor-firmware/crypto")
        .flag("-std=gnu99")
        .opt_level(3)
        .compile("trezor-crypto");

    #[cfg(feature = "generate-bindings")]
    {
        let mut builder = bindgen::Builder::default();
        for &(var, val) in DEFINITIONS {
            if let Some(val) = val {
                builder = builder.clang_arg(format!("-D{}={}", var, val));
            } else {
                builder = builder.clang_arg(format!("-D{}", var));
            }
        }
        let bindings = builder
            .clang_arg("-std=gnu99")
            .clang_arg(format!("-I{}", BASE_DIR))
            .header("wrapper.h")
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
