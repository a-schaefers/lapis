local encode_base64, decode_base64, hmac_sha1
local config = require("lapis.config").get()
local new_hmac
do
  local has_luaossl, openssl_hmac = pcall(require, "openssl.hmac")
  if has_luaossl then
    new_hmac = openssl_hmac.new
  elseif pcall(function()
    return require("resty.openssl.hmac")
  end) then
    new_hmac = require("resty.openssl.hmac").new
  else
    local luaossl_err = openssl_hmac
    new_hmac = function(secret, digest_type)
      return error("lapis.util.encoding: hmac_" .. tostring(digest_type) .. " requires luaossl or lua-resty-openssl, but luaossl failed to load: " .. tostring(luaossl_err))
    end
  end
end
local hmac_for
hmac_for = function(digest_type)
  return function(secret, str)
    local hmac = assert(new_hmac(secret, digest_type))
    return assert(hmac:final(str))
  end
end
if ngx then
  do
    local _obj_0 = ngx
    encode_base64, decode_base64, hmac_sha1 = _obj_0.encode_base64, _obj_0.decode_base64, _obj_0.hmac_sha1
  end
else
  local mime = require("mime")
  local b64, unb64
  b64, unb64 = mime.b64, mime.unb64
  encode_base64 = function(...)
    return (b64(...))
  end
  decode_base64 = function(...)
    return (unb64(...))
  end
  hmac_sha1 = hmac_for("sha1")
end
local hmac_sha256 = hmac_for("sha256")
local default_hmac
local _exp_0 = config.hmac_digest
if "sha256" == _exp_0 then
  default_hmac = hmac_sha256
else
  default_hmac = hmac_sha1
end
local set_hmac
set_hmac = function(fn)
  default_hmac = fn
end
local encode_with_secret
encode_with_secret = function(object, secret, sep)
  if secret == nil then
    secret = config.secret
  end
  if sep == nil then
    sep = "."
  end
  local json = require("cjson")
  local msg = encode_base64(json.encode(object))
  local signature = encode_base64(default_hmac(secret, msg))
  return msg .. sep .. signature
end
local decode_with_secret
decode_with_secret = function(msg_and_sig, secret, sep)
  if secret == nil then
    secret = config.secret
  end
  if sep == nil then
    sep = "%."
  end
  local json = require("cjson")
  local msg, sig = msg_and_sig:match("^(.*)" .. tostring(sep) .. "(.*)$")
  if not (msg) then
    return nil, "invalid format"
  end
  sig = decode_base64(sig)
  if not (sig == default_hmac(secret, msg)) then
    return nil, "invalid signature"
  end
  return json.decode(decode_base64(msg))
end
return {
  encode_base64 = encode_base64,
  decode_base64 = decode_base64,
  hmac_sha1 = hmac_sha1,
  hmac_sha256 = hmac_sha256,
  encode_with_secret = encode_with_secret,
  decode_with_secret = decode_with_secret,
  set_hmac = set_hmac
}
