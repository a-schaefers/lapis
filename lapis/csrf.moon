-- csrf protection

import encode_base64, encode_with_secret, decode_with_secret from require "lapis.util.encoding"

config = require"lapis.config".get!
cookie_name = "#{config.session_name}_token"

-- luaossl is optional so it doesn't have to be installed for apps running in
-- OpenResty, which bundles resty.random. resty.random calls into the OpenSSL
-- that nginx is linked with, so it's only used inside of a real nginx process.
-- (The fake ngx of a simulated request has no ngx.config)
random_bytes = do
  has_luaossl, openssl_rand = pcall require, "openssl.rand"

  if has_luaossl
    openssl_rand.bytes
  elseif ngx and ngx.config and pcall -> require "resty.random"
    resty_random = require "resty.random"
    (n) ->
      bytes = resty_random.bytes n, true
      assert bytes, "lapis.csrf: resty.random failed to generate random bytes"
      bytes
  else
    luaossl_err = openssl_rand
    ->
      error "lapis.csrf: generating a token requires luaossl (or resty.random in OpenResty), but luaossl failed to load: #{luaossl_err}"

generate_token = (req, data) ->
  key = req.cookies[cookie_name]

  unless key
    key = encode_base64 random_bytes 32
    req.cookies[cookie_name] = key

  token = {
    k: key
    d: data
  }

  encode_with_secret token

validate_token = (req, callback) ->
  token = req.params.csrf_token
  return nil, "missing csrf token" unless token

  expected_key = req.cookies[cookie_name]
  return nil, "csrf: missing token cookie" unless expected_key

  obj, err = decode_with_secret token
  unless obj
    return nil, "csrf: #{err}"

  if obj.k != expected_key
    return nil, "csrf: token mismatch"

  if callback
    pass, err = callback obj.d
    unless pass
      return nil, "csrf: #{err or "failed check"}"

  true

assert_token = (...) ->
  import assert_error from require "lapis.application"
  assert_error validate_token ...

{ :generate_token, :validate_token, :assert_token }

