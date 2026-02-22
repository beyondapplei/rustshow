import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export type Result = { 'Ok' : string } |
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
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
