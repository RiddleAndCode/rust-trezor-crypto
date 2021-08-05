use crate::*;

fn sha3_test_vector(input: impl AsRef<[u8]>, expected_hex: impl AsRef<str>) {
    let input = input.as_ref();
    let mut output = [0; 32];
    unsafe {
        sha3_256(input.as_ptr(), input.len() as u64, output.as_mut_ptr());
    }
    assert_eq!(hex::encode(&output), expected_hex.as_ref().to_lowercase())
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

fn secp256k1_public_key_test_vector(
    priv_key_hex: impl AsRef<str>,
    x_hex: impl AsRef<str>,
    y_hex: impl AsRef<str>,
) {
    let priv_key = hex::decode(priv_key_hex.as_ref()).unwrap();
    let mut pub_key = [0; 65];
    unsafe {
        ecdsa_get_public_key65(&secp256k1, priv_key.as_ptr(), pub_key.as_mut_ptr());
    }
    assert_eq!(hex::encode(&pub_key[1..33]), x_hex.as_ref().to_lowercase());
    assert_eq!(hex::encode(&pub_key[33..]), y_hex.as_ref().to_lowercase());
}

#[test]
fn secp256k1_public_key_test_vectors() {
    secp256k1_public_key_test_vector(
        "AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522",
        "34F9460F0E4F08393D192B3C5133A6BA099AA0AD9FD54EBCCFACDFA239FF49C6",
        "0B71EA9BD730FD8923F6D25A7A91E7DD7728A960686CB5A901BB419E0F2CA232",
    );
    secp256k1_public_key_test_vector(
        "7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3",
        "D74BF844B0862475103D96A611CF2D898447E288D34B360BC885CB8CE7C00575",
        "131C670D414C4546B88AC3FF664611B1C38CEB1C21D76369D7A7A0969D61D97D",
    );
    secp256k1_public_key_test_vector(
        "6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D",
        "E8AECC370AEDD953483719A116711963CE201AC3EB21D3F3257BB48668C6A72F",
        "C25CAF2F0EBA1DDB2F0F3F47866299EF907867B7D27E95B3873BF98397B24EE1",
    );
    secp256k1_public_key_test_vector(
        "376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC",
        "14890E61FCD4B0BD92E5B36C81372CA6FED471EF3AA60A3E415EE4FE987DABA1",
        "297B858D9F752AB42D3BCA67EE0EB6DCD1C2B7B0DBE23397E66ADC272263F982",
    );
    secp256k1_public_key_test_vector(
        "1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9",
        "F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3",
        "F449A8376906482A84ED01479BD18882B919C140D638307F0C0934BA12590BDE",
    );
}
