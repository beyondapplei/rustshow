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

fn key_id() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: VETKEYS_KEY_NAME.to_string(),
    }
}
