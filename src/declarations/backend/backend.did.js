export const idlFactory = ({ IDL }) => {
  const Result = IDL.Variant({ 'Ok' : IDL.Text, 'Err' : IDL.Text });
  return IDL.Service({
    'ecdsaPublicKeyExample' : IDL.Func([IDL.Text], [Result], []),
    'ecdsaSignMessageHashExample' : IDL.Func(
        [IDL.Vec(IDL.Nat8), IDL.Text],
        [Result],
        [],
      ),
    'ecdsa_public_key_for_caller_hex' : IDL.Func([], [Result], []),
    'ecdsa_sign_hash_hex_for_caller' : IDL.Func([IDL.Text], [Result], []),
    'ibe_decryption_key_for_caller_hex' : IDL.Func([IDL.Text], [Result], []),
    'ibe_public_key_hex' : IDL.Func([], [Result], []),
    'vetkdCallerInputHex' : IDL.Func([], [IDL.Text], ['query']),
    'vetkdDeriveKeyExample' : IDL.Func(
        [IDL.Vec(IDL.Nat8), IDL.Text, IDL.Text],
        [Result],
        [],
      ),
    'vetkdPublicKeyExample' : IDL.Func([IDL.Text, IDL.Text], [Result], []),
  });
};
export const init = ({ IDL }) => { return []; };
