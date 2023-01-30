// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module sui::ecdsa_r1_tests {
    use sui::ecdsa_r1;
    
    #[test]
    fun test_ecrecover_pubkey() {
        // test case generated against https://github.com/MystenLabs/fastcrypto/blob/1553672a0c130af3fedc1ed5b317cad911313578/fastcrypto/src/tests/secp256r1_recoverable_tests.rs
        let hashed_msg = x"315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";

        let sig = x"63943a01af84b202f80f17b0f567d0ab2e8b8c8b0c971e4b253706d0f4be91204d69c018c5ca4bb8b8587772467e2e32cc71c067336709862145246a5e778d2700";
        let pubkey_bytes = x"0227322b3a891a0a280d6bc1fb2cbb23d28f54906fd6407f5f741f6def5762609a";

        let pubkey = ecdsa_r1::ecrecover(&sig, &hashed_msg);
        assert!(pubkey == pubkey_bytes, 0);
    }

    #[test]
    #[expected_failure(abort_code = ecdsa_r1::EInvalidSignature)]
    fun test_ecrecover_pubkey_invalid_sig() {
        let hashed_msg = x"315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";
        // incorrect length sig
        let sig = x"63943a01af84b202f80f17b0f567d0ab2e8b8c8b0c971e4b253706d0f4be91204d69c018c5ca4bb8b8587772467e2e32cc71c067336709862145246a5e778d27";
        ecdsa_r1::ecrecover(&sig, &hashed_msg);
    }

    #[test]
    fun test_secp256r1_verify_fails_with_recoverable_sig() {
        let hashed_msg = x"315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";
        let pk = x"0227322b3a891a0a280d6bc1fb2cbb23d28f54906fd6407f5f741f6def5762609a";
        // signature is a 65-byte recoverable one with recovery id 0
        let sig = x"63943a01af84b202f80f17b0f567d0ab2e8b8c8b0c971e4b253706d0f4be91204d69c018c5ca4bb8b8587772467e2e32cc71c067336709862145246a5e778d2700";
        let verify = ecdsa_r1::secp256r1_verify(&sig, &pk, &hashed_msg);
        assert!(verify == false, 0);
        
        // signature is a 65-byte recoverable one with recovery id 1
        let sig_1 = x"63943a01af84b202f80f17b0f567d0ab2e8b8c8b0c971e4b253706d0f4be91204d69c018c5ca4bb8b8587772467e2e32cc71c067336709862145246a5e778d2701";
        let verify_1 = ecdsa_r1::secp256r1_verify(&sig_1, &pk, &hashed_msg);
        assert!(verify_1 == false, 0);
    }

    #[test]
    fun test_secp256r1_verify_success_with_nonrecoverable_sig() {
        // test generated with https://github.com/MystenLabs/fastcrypto/blob/1553672a0c130af3fedc1ed5b317cad911313578/fastcrypto/src/tests/secp256r1_tests.rs
        let hashed_msg = x"315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";
        let pk = x"0227322b3a891a0a280d6bc1fb2cbb23d28f54906fd6407f5f741f6def5762609a";
        // signature is a 64-byte nonrecoverable one without recovery id
        let sig = x"63943a01af84b202f80f17b0f567d0ab2e8b8c8b0c971e4b253706d0f4be91204d69c018c5ca4bb8b8587772467e2e32cc71c067336709862145246a5e778d27";
        let verify = ecdsa_r1::secp256r1_verify(&sig, &pk, &hashed_msg);
        assert!(verify == true, 0)
    }

    #[test]
    fun test_secp256r1_invalid_public_key_length() {
        let hashed_msg = x"315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";
        // public key has wrong length
        let pk = x"0227322b3a891a0a280d6bc1fb2cbb23d28f54906fd6407f5f741f6def5762609a00";
        let sig = x"9c7a72ff1e7db1646b9f9443cb1a3563aa3a6344e4e513efb96258c7676ac4895953629d409a832472b710a028285dfec4733a2c1bb0a2749e465a18292b8bd601";
        
        let verify = ecdsa_r1::secp256r1_verify(&sig, &pk, &hashed_msg);
        assert!(verify == false, 0)
    }
}
