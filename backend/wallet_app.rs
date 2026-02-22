use candid::{CandidType, Nat, Principal};
use ic_cdk::management_canister::{ecdsa_public_key, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs};

use crate::codec::encode_hex;

#[derive(CandidType, serde::Deserialize, Clone, Debug)]
#[allow(non_snake_case)]
pub struct WalletNetworkInfo {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub primarySymbol: String,
    pub supportsSend: bool,
    pub supportsBalance: bool,
    pub defaultRpcUrl: Option<String>,
}

#[derive(CandidType, serde::Deserialize, Clone, Debug)]
#[allow(non_snake_case)]
pub struct WalletBalanceItem {
    pub symbol: String,
    pub name: String,
    pub network: String,
    pub decimals: Nat,
    pub amount: Nat,
    pub available: bool,
    pub address: String,
    pub error: Option<String>,
    pub tokenAddress: Option<String>,
    pub ledgerPrincipalText: Option<String>,
}

#[derive(CandidType, serde::Deserialize, Clone, Debug)]
#[allow(non_snake_case)]
pub struct WalletOverviewOut {
    pub callerPrincipalText: String,
    pub selectedNetwork: String,
    pub primarySymbol: String,
    pub primaryAmount: Nat,
    pub primaryAvailable: bool,
    pub evmAddress: Option<String>,
    pub evmPublicKeyHex: Option<String>,
    pub balances: Vec<WalletBalanceItem>,
}

pub type WalletOverviewResult = Result<WalletOverviewOut, String>;

const LOCAL_ECDSA_KEY_NAME: &str = "dfx_test_key";
const IC_ECDSA_KEY_NAME: &str = "test_key_1";

#[ic_cdk::query(name = "wallet_networks")]
fn wallet_networks() -> Vec<WalletNetworkInfo> {
    vec![
        wallet_network("eth", "evm", "Ethereum", "ETH", Some("https://ethereum-rpc.publicnode.com")),
        wallet_network(
            "sepolia",
            "evm",
            "Sepolia",
            "ETH",
            Some("https://ethereum-sepolia-rpc.publicnode.com"),
        ),
        wallet_network("base", "evm", "Base", "ETH", Some("https://base-rpc.publicnode.com")),
        wallet_network("sol", "ed25519", "Solana", "SOL", Some("https://solana-rpc.publicnode.com")),
        wallet_network(
            "sol_testnet",
            "ed25519",
            "Solana Testnet",
            "SOL",
            Some("https://solana-testnet-rpc.publicnode.com"),
        ),
        wallet_network("apt", "ed25519", "Aptos", "APT", None),
        wallet_network("sui", "ed25519", "Sui", "SUI", None),
        wallet_network("btc", "utxo", "Bitcoin", "BTC", None),
        wallet_network("ckb", "cell", "Nervos CKB", "CKB", None),
        wallet_network("icp", "icp", "Internet Computer", "ICP", None),
    ]
}

#[ic_cdk::update(name = "wallet_overview")]
async fn wallet_overview(
    network: String,
    _rpc_url: Option<String>,
    _erc20_token_address: Option<String>,
) -> WalletOverviewResult {
    let normalized = normalize_wallet_network(&network);
    let chain = wallet_networks()
        .into_iter()
        .find(|item| item.id == normalized)
        .ok_or_else(|| format!("unsupported wallet network: {network}"))?;

    let caller = ic_cdk::api::msg_caller();

    let (evm_address, evm_public_key_hex) = if is_evm_wallet_network(&normalized) {
        let public_key = read_evm_public_key_for_caller_with_fallback(caller)
            .await
            .map_err(|err| format!("wallet ecdsa public key failed: {err}"))?;
        (None, Some(encode_hex(&public_key)))
    } else {
        (None, None)
    };

    Ok(WalletOverviewOut {
        callerPrincipalText: caller.to_text(),
        selectedNetwork: normalized,
        primarySymbol: chain.primarySymbol,
        primaryAmount: Nat::from(0u8),
        primaryAvailable: false,
        evmAddress: evm_address,
        evmPublicKeyHex: evm_public_key_hex,
        balances: Vec::new(),
    })
}

fn wallet_network(
    id: &str,
    kind: &str,
    name: &str,
    primary_symbol: &str,
    default_rpc_url: Option<&str>,
) -> WalletNetworkInfo {
    WalletNetworkInfo {
        id: id.to_string(),
        kind: kind.to_string(),
        name: name.to_string(),
        primarySymbol: primary_symbol.to_string(),
        supportsSend: false,
        supportsBalance: false,
        defaultRpcUrl: default_rpc_url.map(ToString::to_string),
    }
}

fn normalize_wallet_network(raw: &str) -> String {
    let n = raw.trim().to_ascii_lowercase();
    match n.as_str() {
        "" | "icp" | "ic" | "internet_computer" | "internet-computer" => "icp".to_string(),
        "eth" | "ethereum" | "mainnet" => "eth".to_string(),
        "sepolia" | "eth-sepolia" | "ethereum-sepolia" => "sepolia".to_string(),
        "sol" | "solana" => "sol".to_string(),
        "sol_testnet" | "solana_testnet" | "solana-testnet" | "sol-testnet" => {
            "sol_testnet".to_string()
        }
        "aptos" => "apt".to_string(),
        "bitcoin" => "btc".to_string(),
        "nervos" | "nervos_ckb" => "ckb".to_string(),
        _ => n,
    }
}

fn is_evm_wallet_network(id: &str) -> bool {
    matches!(id, "eth" | "sepolia" | "base")
}

async fn read_evm_public_key_for_caller_with_fallback(caller: Principal) -> Result<Vec<u8>, String> {
    let local_try = read_evm_public_key_for_caller(caller, LOCAL_ECDSA_KEY_NAME).await;
    match local_try {
        Ok(bytes) => Ok(bytes),
        Err(local_err) => {
            let ic_try = read_evm_public_key_for_caller(caller, IC_ECDSA_KEY_NAME).await;
            match ic_try {
                Ok(bytes) => Ok(bytes),
                Err(ic_err) => Err(format!(
                    "tried '{LOCAL_ECDSA_KEY_NAME}' and '{IC_ECDSA_KEY_NAME}' ({local_err}; {ic_err})"
                )),
            }
        }
    }
}

async fn read_evm_public_key_for_caller(caller: Principal, key_name: &str) -> Result<Vec<u8>, String> {
    let args = EcdsaPublicKeyArgs {
        canister_id: Some(ic_cdk::api::canister_self()),
        derivation_path: vec![caller.as_slice().to_vec()],
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: key_name.to_string(),
        },
    };

    let result = ecdsa_public_key(&args)
        .await
        .map_err(|err| format!("ecdsa_public_key call failed: {err}"))?;
    Ok(result.public_key)
}
