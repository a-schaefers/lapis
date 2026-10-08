encoding = require "lapis.util.encoding"
ngx_stack = require "lapis.spec.stack"
import require_with_stubs from require "spec.helpers"

to_hex = (str) -> (str\gsub ".", (c) -> string.format "%02x", c\byte!)

-- stands in for luaossl's openssl.hmac and lua-resty-openssl's
-- resty.openssl.hmac, which share the same interface
fake_hmac = (name) -> {
  new: (secret, digest_type) -> {
    final: (str) => "#{name}:#{digest_type}:#{secret}:#{str}"
  }
}

describe "lapis.util.encoding", ->
  config = require"lapis.config".get!

  before_each ->
    config.secret = "the-secret"

  it "should encode message", ->
    encoded = encoding.encode_with_secret { color: "red" }
    input = encoding.decode_with_secret encoded
    assert.same input, { color: "red" }

  it "should encode message", ->
    encoded = encoding.encode_with_secret { color: "red" }
    input = encoding.decode_with_secret encoded
    assert.same input, { color: "red" }

  it "should not decode with incorrect secret", ->
    encoded = encoding.encode_with_secret { color: "red" }
    config.secret = "not-the-secret"
    assert.same { encoding.decode_with_secret encoded }, {nil, "invalid signature"}


  it "should fail on invalid string", ->
    assert.same {encoding.decode_with_secret "hello"},
      {nil, "invalid format"}

    assert.same {encoding.decode_with_secret "hello.world"},
      {nil, "invalid signature"}

  -- RFC 2202 and RFC 4231 test case 2
  it "calculates hmac_sha1", ->
    assert.same "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
      to_hex encoding.hmac_sha1 "Jefe", "what do ya want for nothing?"

  it "calculates hmac_sha256", ->
    assert.same "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
      to_hex encoding.hmac_sha256 "Jefe", "what do ya want for nothing?"

  describe "hmac backend", ->
    it "uses luaossl when it's installed", ->
      e = require_with_stubs "lapis.util.encoding", {
        "openssl.hmac": fake_hmac "luaossl"
        "resty.openssl.hmac": fake_hmac "resty"
      }

      assert.same "luaossl:sha1:key:msg", e.hmac_sha1 "key", "msg"
      assert.same "luaossl:sha256:key:msg", e.hmac_sha256 "key", "msg"

    it "falls back to lua-resty-openssl", ->
      e = require_with_stubs "lapis.util.encoding", {
        "openssl.hmac": false
        "resty.openssl.hmac": fake_hmac "resty"
      }

      assert.same "resty:sha1:key:msg", e.hmac_sha1 "key", "msg"
      assert.same "resty:sha256:key:msg", e.hmac_sha256 "key", "msg"

    it "loads without a backend and fails when an hmac is calculated", ->
      e = require_with_stubs "lapis.util.encoding", {
        "openssl.hmac": false
        "resty.openssl.hmac": false
      }

      for fn_name in *{"hmac_sha1", "hmac_sha256"}
        ok, err = pcall e[fn_name], "key", "msg"
        assert.same false, ok
        assert.truthy err\find "#{fn_name} requires luaossl or lua-resty-openssl", 1, true
        -- includes the reason luaossl couldn't be loaded
        assert.truthy err\find "luaossl failed to load: module 'openssl.hmac' not found (stubbed by spec)", 1, true

      assert.has_error -> e.encode_with_secret { color: "red" }

    describe "with nginx", ->
      before_each ->
        mime = require "mime"
        ngx_stack.push {
          config: {}
          encode_base64: (str) -> (mime.b64 str)
          decode_base64: (str) -> (mime.unb64 str)
          hmac_sha1: (secret, str) -> "ngx:sha1:#{secret}:#{str}"
        }

      after_each ->
        ngx_stack.pop!

      it "signs with ngx.hmac_sha1 without a backend", ->
        e = require_with_stubs "lapis.util.encoding", {
          "openssl.hmac": false
          "resty.openssl.hmac": false
        }

        assert.same "ngx:sha1:key:msg", e.hmac_sha1 "key", "msg"
        assert.same { color: "red" }, e.decode_with_secret e.encode_with_secret { color: "red" }
        assert.has_error -> e.hmac_sha256 "key", "msg"

      it "signs with lua-resty-openssl when hmac_digest is sha256", ->
        prev_digest = config.hmac_digest
        config.hmac_digest = "sha256"
        finally -> config.hmac_digest = prev_digest

        e = require_with_stubs "lapis.util.encoding", {
          "openssl.hmac": false
          "resty.openssl.hmac": fake_hmac "resty"
        }

        assert.same "ngx:sha1:key:msg", e.hmac_sha1 "key", "msg"
        assert.same "resty:sha256:key:msg", e.hmac_sha256 "key", "msg"

        msg, signature = e.encode_with_secret({ color: "red" })\match "^(.*)%.(.*)$"
        assert.same "resty:sha256:the-secret:#{msg}", e.decode_base64 signature
