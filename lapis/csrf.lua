local encode_base64, encode_with_secret, decode_with_secret
do
  local _obj_0 = require("lapis.util.encoding")
  encode_base64, encode_with_secret, decode_with_secret = _obj_0.encode_base64, _obj_0.encode_with_secret, _obj_0.decode_with_secret
end
local config = require("lapis.config").get()
local cookie_name = tostring(config.session_name) .. "_token"
local random_bytes
do
  local has_luaossl, openssl_rand = pcall(require, "openssl.rand")
  if has_luaossl then
    random_bytes = openssl_rand.bytes
  elseif ngx and ngx.config and pcall(function()
    return require("resty.random")
  end) then
    local resty_random = require("resty.random")
    random_bytes = function(n)
      local bytes = resty_random.bytes(n, true)
      assert(bytes, "lapis.csrf: resty.random failed to generate random bytes")
      return bytes
    end
  else
    local luaossl_err = openssl_rand
    random_bytes = function()
      return error("lapis.csrf: generating a token requires luaossl (or resty.random in OpenResty), but luaossl failed to load: " .. tostring(luaossl_err))
    end
  end
end
local generate_token
generate_token = function(req, data)
  local key = req.cookies[cookie_name]
  if not (key) then
    key = encode_base64(random_bytes(32))
    req.cookies[cookie_name] = key
  end
  local token = {
    k = key,
    d = data
  }
  return encode_with_secret(token)
end
local validate_token
validate_token = function(req, callback)
  local token = req.params.csrf_token
  if not (token) then
    return nil, "missing csrf token"
  end
  local expected_key = req.cookies[cookie_name]
  if not (expected_key) then
    return nil, "csrf: missing token cookie"
  end
  local obj, err = decode_with_secret(token)
  if not (obj) then
    return nil, "csrf: " .. tostring(err)
  end
  if obj.k ~= expected_key then
    return nil, "csrf: token mismatch"
  end
  if callback then
    local pass
    pass, err = callback(obj.d)
    if not (pass) then
      return nil, "csrf: " .. tostring(err or "failed check")
    end
  end
  return true
end
local assert_token
assert_token = function(...)
  local assert_error
  assert_error = require("lapis.application").assert_error
  return assert_error(validate_token(...))
end
return {
  generate_token = generate_token,
  validate_token = validate_token,
  assert_token = assert_token
}
