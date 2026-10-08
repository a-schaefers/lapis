
local encode_base64, decode_base64, hmac_sha1

config = require"lapis.config".get!

-- luaossl is optional so it doesn't have to be installed for apps running in
-- OpenResty, where lua-resty-openssl can be used instead. Both libraries
-- provide new(key, digest_type) to create an hmac. With neither installed,
-- calculating an hmac raises an error that includes why luaossl failed to load
new_hmac = do
  has_luaossl, openssl_hmac = pcall require, "openssl.hmac"

  if has_luaossl
    openssl_hmac.new
  elseif pcall -> require "resty.openssl.hmac"
    require("resty.openssl.hmac").new
  else
    luaossl_err = openssl_hmac
    (secret, digest_type) ->
      error "lapis.util.encoding: hmac_#{digest_type} requires luaossl or lua-resty-openssl, but luaossl failed to load: #{luaossl_err}"

hmac_for = (digest_type) ->
  (secret, str) ->
    hmac = assert new_hmac secret, digest_type
    assert hmac\final str

if ngx
  {:encode_base64, :decode_base64, :hmac_sha1} = ngx
else
  mime = require "mime"
  { :b64, :unb64 } = mime
  encode_base64 = (...) -> (b64 ...)
  decode_base64 = (...) -> (unb64 ...)

  hmac_sha1 = hmac_for "sha1"

---Generate HMAC-SHA256 hash
---@param secret string Secret key for HMAC
---@param str string String to hash
---@return string hash Binary HMAC-SHA256 digest
hmac_sha256 = hmac_for "sha256"

default_hmac = switch config.hmac_digest
  when "sha256"
    hmac_sha256
  else
    hmac_sha1

---@package
---Set the default HMAC function
set_hmac = (fn) -> default_hmac = fn

---Encode object with secret signature
---@param object any Object to encode as JSON
---@param secret? string Secret key for signature (default: config.secret)
---@param sep? string Separator between message and signature (default: ".")
---@return string encoded Base64 encoded JSON with HMAC signature
encode_with_secret = (object, secret=config.secret, sep=".") ->
  json = require "cjson"

  msg = encode_base64 json.encode object
  signature = encode_base64 default_hmac secret, msg
  msg .. sep .. signature

---Decode object with secret signature verification
---@param msg_and_sig string Base64 encoded message with signature
---@param secret? string Secret key for verification (default: config.secret)
---@param sep? string Separator pattern between message and signature (default: "%.")
---@return any|nil object Decoded object on success, nil on failure
---@return string|nil error Error message if decoding fails
decode_with_secret = (msg_and_sig, secret=config.secret, sep="%.") ->
  json = require "cjson"

  msg, sig = msg_and_sig\match "^(.*)#{sep}(.*)$"
  return nil, "invalid format" unless msg

  sig = decode_base64 sig

  unless sig == default_hmac(secret, msg)
    return nil, "invalid signature"

  json.decode decode_base64 msg

{ :encode_base64, :decode_base64, :hmac_sha1, :hmac_sha256, :encode_with_secret, :decode_with_secret, :set_hmac }
