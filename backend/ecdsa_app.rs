use candid::Principal;
use ic_cdk::management_canister::{
    ecdsa_public_key, sign_with_ecdsa, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs,
    SignWithEcdsaArgs,
};

use crate::codec::{decode_hex, encode_hex};

// Local dfx threshold ECDSA key name.
const ECDSA_KEY_NAME: &str = "dfx_test_key";
const ECDSA_DOMAIN: &[u8] = b"rustshow-eth-ecdsa-v1";

#[ic_cdk::update]
async fn ecdsa_public_key_for_caller_hex() -> Result<String, String> {
    let caller = ic_cdk::api::msg_caller();
    let args = EcdsaPublicKeyArgs {
        canister_id: Some(ic_cdk::api::canister_self()),
        derivation_path: caller_derivation_path(caller),
        key_id: key_id(),
    };

    let result = ecdsa_public_key(&args)
        .await
        .map_err(|err| format!("ecdsa_public_key call failed: {err}"))?;
    Ok(encode_hex(&result.public_key))
}

#[ic_cdk::update]
async fn ecdsa_sign_hash_hex_for_caller(message_hash_hex: String) -> Result<String, String> {
    let message_hash = decode_hex(&message_hash_hex)?;
    if message_hash.len() != 32 {
        return Err("message_hash must be exactly 32 bytes".to_string());
    }

    let caller = ic_cdk::api::msg_caller();
    let args = SignWithEcdsaArgs {
        message_hash,
        derivation_path: caller_derivation_path(caller),
        key_id: key_id(),
    };

    let result = sign_with_ecdsa(&args)
        .await
        .map_err(|err| format!("sign_with_ecdsa call failed: {err}"))?;
    Ok(encode_hex(&result.signature))
}

#[ic_cdk::update(name = "ecdsaPublicKeyExample")]
async fn ecdsa_public_key_example(key_name: String) -> Result<String, String> {
    let caller = ic_cdk::api::msg_caller();
    let args = EcdsaPublicKeyArgs {
        canister_id: Some(ic_cdk::api::canister_self()),
        derivation_path: vec![caller.as_slice().to_vec()],
        key_id: key_id_with_name(&normalize_ecdsa_key_name(&key_name)),
    };

    let result = ecdsa_public_key(&args)
        .await
        .map_err(|err| format!("ecdsa_public_key call failed: {err}"))?;
    Ok(encode_hex(&result.public_key))
}

#[ic_cdk::update(name = "ecdsaSignMessageHashExample")]
async fn ecdsa_sign_message_hash_example(
    message_hash: Vec<u8>,
    key_name: String,
) -> Result<String, String> {
    if message_hash.len() != 32 {
        return Err("messageHash must be exactly 32 bytes".to_string());
    }

    let caller = ic_cdk::api::msg_caller();
    let args = SignWithEcdsaArgs {
        message_hash,
        derivation_path: vec![caller.as_slice().to_vec()],
        key_id: key_id_with_name(&normalize_ecdsa_key_name(&key_name)),
    };

    let result = sign_with_ecdsa(&args)
        .await
        .map_err(|err| format!("sign_with_ecdsa call failed: {err}"))?;
    Ok(encode_hex(&result.signature))
}

fn caller_derivation_path(caller: Principal) -> Vec<Vec<u8>> {
    vec![ECDSA_DOMAIN.to_vec(), caller.as_slice().to_vec()]
}

fn key_id() -> EcdsaKeyId {
    key_id_with_name(ECDSA_KEY_NAME)
}

fn key_id_with_name(name: &str) -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: name.to_string(),
    }
}

fn normalize_ecdsa_key_name(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        ECDSA_KEY_NAME.to_string()
    } else {
        trimmed.to_string()
    }
}
