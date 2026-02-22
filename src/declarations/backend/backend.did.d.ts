import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export type Result = { 'Ok' : string } |
  { 'Err' : string };
export interface WalletBalanceItem {
  'decimals' : bigint,
  'ledgerPrincipalText' : [] | [string],
  'tokenAddress' : [] | [string],
  'name' : string,
  'network' : string,
  'error' : [] | [string],
  'available' : boolean,
  'address' : string,
  'amount' : bigint,
  'symbol' : string,
}
export interface WalletNetworkInfo {
  'id' : string,
  'kind' : string,
  'name' : string,
  'defaultRpcUrl' : [] | [string],
  'primarySymbol' : string,
  'supportsBalance' : boolean,
  'supportsSend' : boolean,
}
export interface WalletOverviewOut {
  'evmPublicKeyHex' : [] | [string],
  'primaryAvailable' : boolean,
  'primaryAmount' : bigint,
  'callerPrincipalText' : string,
  'primarySymbol' : string,
  'selectedNetwork' : string,
  'evmAddress' : [] | [string],
  'balances' : Array<WalletBalanceItem>,
}
export type WalletOverviewResult = { 'Ok' : WalletOverviewOut } |
  { 'Err' : string };
export interface _SERVICE {
  'ecdsaPublicKeyExample' : ActorMethod<[string], Result>,
  'ecdsaSignMessageHashExample' : ActorMethod<
    [Uint8Array | number[], string],
    Result
  >,
  'ecdsa_public_key_for_caller_hex' : ActorMethod<[], Result>,
  'ecdsa_sign_hash_hex_for_caller' : ActorMethod<[string], Result>,
  'ibe_decryption_key_for_caller_hex' : ActorMethod<[string], Result>,
  'ibe_public_key_hex' : ActorMethod<[], Result>,
  'vetkdCallerInputHex' : ActorMethod<[], string>,
  'vetkdDeriveKeyExample' : ActorMethod<
    [Uint8Array | number[], string, string],
    Result
  >,
  'vetkdPublicKeyExample' : ActorMethod<[string, string], Result>,
  'wallet_networks' : ActorMethod<[], Array<WalletNetworkInfo>>,
  'wallet_overview' : ActorMethod<
    [string, [] | [string], [] | [string]],
    WalletOverviewResult
  >,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
