use ic_cdk::management_canister::{
    vetkd_derive_key, vetkd_public_key, VetKDCurve, VetKDDeriveKeyArgs, VetKDKeyId,
    VetKDPublicKeyArgs,
};

use crate::codec::{decode_hex, encode_hex};

const VETKEYS_KEY_NAME: &str = "test_key_1";
const IBE_CONTEXT: &[u8] = b"rustshow-ibe-v1";

#[ic_cdk::update]
async fn ibe_public_key_hex() -> Result<String, String> {
    let args = VetKDPublicKeyArgs {
        canister_id: Some(ic_cdk::api::canister_self()),
        context: IBE_CONTEXT.to_vec(),
        key_id: key_id(),
    };
    let result = vetkd_public_key(&args)
        .await
        .map_err(|err| format!("vetkd_public_key call failed: {err}"))?;
    Ok(encode_hex(&result.public_key))
}

#[ic_cdk::update]
async fn ibe_decryption_key_for_caller_hex(
    transport_public_key_hex: String,
) -> Result<String, String> {
    let caller = ic_cdk::api::msg_caller();
    let args = VetKDDeriveKeyArgs {
        input: caller.as_slice().to_vec(),
        context: IBE_CONTEXT.to_vec(),
        transport_public_key: decode_hex(&transport_public_key_hex)?,
        key_id: key_id(),
    };
    let result = vetkd_derive_key(&args)
        .await
        .map_err(|err| format!("vetkd_derive_key call failed: {err}"))?;
    Ok(encode_hex(&result.encrypted_key))
}

#[ic_cdk::update(name = "vetkdPublicKeyExample")]
async fn vetkd_public_key_example(
    key_name: String,
    context_label: String,
) -> Result<String, String> {
    let args = VetKDPublicKeyArgs {
        canister_id: Some(ic_cdk::api::canister_self()),
        context: context_bytes(&context_label),
        key_id: key_id_with_name(&normalize_vetkd_key_name(&key_name)),
    };
    let result = vetkd_public_key(&args)
        .await
        .map_err(|err| format!("vetkd_public_key call failed: {err}"))?;
    Ok(encode_hex(&result.public_key))
}

#[ic_cdk::update(name = "vetkdDeriveKeyExample")]
async fn vetkd_derive_key_example(
    transport_public_key: Vec<u8>,
    key_name: String,
    context_label: String,
) -> Result<String, String> {
    if transport_public_key.is_empty() {
        return Err("transportPublicKey must not be empty".to_string());
    }

    let caller = ic_cdk::api::msg_caller();
    let args = VetKDDeriveKeyArgs {
        input: caller.as_slice().to_vec(),
        context: context_bytes(&context_label),
        transport_public_key,
        key_id: key_id_with_name(&normalize_vetkd_key_name(&key_name)),
    };
    let result = vetkd_derive_key(&args)
        .await
        .map_err(|err| format!("vetkd_derive_key call failed: {err}"))?;
    Ok(encode_hex(&result.encrypted_key))
}

#[ic_cdk::query(name = "vetkdCallerInputHex")]
fn vetkd_caller_input_hex() -> String {
    let caller = ic_cdk::api::msg_caller();
    encode_hex(caller.as_slice())
}

fn key_id() -> VetKDKeyId {
    key_id_with_name(VETKEYS_KEY_NAME)
}

fn key_id_with_name(name: &str) -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: name.to_string(),
    }
}

fn normalize_vetkd_key_name(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        VETKEYS_KEY_NAME.to_string()
    } else {
        trimmed.to_string()
    }
}

fn context_bytes(label: &str) -> Vec<u8> {
    label.as_bytes().to_vec()
}
