export const idlFactory = ({ IDL }) => {
  const Result = IDL.Variant({ 'Ok' : IDL.Text, 'Err' : IDL.Text });
  const WalletNetworkInfo = IDL.Record({
    'id' : IDL.Text,
    'kind' : IDL.Text,
    'name' : IDL.Text,
    'defaultRpcUrl' : IDL.Opt(IDL.Text),
    'primarySymbol' : IDL.Text,
    'supportsBalance' : IDL.Bool,
    'supportsSend' : IDL.Bool,
  });
  const WalletBalanceItem = IDL.Record({
    'decimals' : IDL.Nat,
    'ledgerPrincipalText' : IDL.Opt(IDL.Text),
    'tokenAddress' : IDL.Opt(IDL.Text),
    'name' : IDL.Text,
    'network' : IDL.Text,
    'error' : IDL.Opt(IDL.Text),
    'available' : IDL.Bool,
    'address' : IDL.Text,
    'amount' : IDL.Nat,
    'symbol' : IDL.Text,
  });
  const WalletOverviewOut = IDL.Record({
    'evmPublicKeyHex' : IDL.Opt(IDL.Text),
    'primaryAvailable' : IDL.Bool,
    'primaryAmount' : IDL.Nat,
    'callerPrincipalText' : IDL.Text,
    'primarySymbol' : IDL.Text,
    'selectedNetwork' : IDL.Text,
    'evmAddress' : IDL.Opt(IDL.Text),
    'balances' : IDL.Vec(WalletBalanceItem),
  });
  const WalletOverviewResult = IDL.Variant({
    'Ok' : WalletOverviewOut,
    'Err' : IDL.Text,
  });
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
    'wallet_networks' : IDL.Func([], [IDL.Vec(WalletNetworkInfo)], ['query']),
    'wallet_overview' : IDL.Func(
        [IDL.Text, IDL.Opt(IDL.Text), IDL.Opt(IDL.Text)],
        [WalletOverviewResult],
        [],
      ),
  });
};
export const init = ({ IDL }) => { return []; };
