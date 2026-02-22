export const idlFactory = ({ IDL }) => {
  const Result = IDL.Variant({ 'Ok' : IDL.Text, 'Err' : IDL.Text });
  return IDL.Service({
    'ibe_decryption_key_for_caller_hex' : IDL.Func([IDL.Text], [Result], []),
    'ibe_public_key_hex' : IDL.Func([], [Result], []),
  });
};
export const init = ({ IDL }) => { return []; };
