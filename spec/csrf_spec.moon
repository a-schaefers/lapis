csrf = require "lapis.csrf"
import encode_base64, encode_with_secret, decode_with_secret from require "lapis.util.encoding"
ngx_stack = require "lapis.spec.stack"
import require_with_stubs from require "spec.helpers"

describe "lapis.csrf", ->
  config = require"lapis.config".get!

  before_each ->
    config.secret = "the-secret"

  describe "generate_token", ->
    it "generates fresh token", ->
      r = {
        cookies: {}
      }
      t = csrf.generate_token r
      assert.truthy t
      assert.truthy r.cookies.lapis_session_token

      out = decode_with_secret t
      assert.same {
        k: r.cookies.lapis_session_token
      }, out

    it "generates fresh token with payload", ->
      r = {
        cookies: {}
      }
      t = csrf.generate_token r, {
        color: "blue"
      }
      assert.truthy t
      assert.truthy t
      assert.truthy r.cookies.lapis_session_token

      out = decode_with_secret t
      assert.same {
        d: {
          color: "blue"
        }
        k: r.cookies["lapis_session_token"]
      }, out

    it "re-uses token stored in cookie", ->
      r = {
        cookies: {
          lapis_session_token: "hello world"
        }
      }
      t = csrf.generate_token r

      assert.truthy t
      assert.same "hello world", r.cookies.lapis_session_token

      assert.same {
        k: "hello world"
      }, decode_with_secret t

    it "re-uses token stored in cookie with payload", ->
      r = {
        cookies: {
          lapis_session_token: "hello world"
        }
      }
      t = csrf.generate_token r, {
        color: "blue"
      }

      assert.truthy t
      assert.same "hello world", r.cookies.lapis_session_token

      assert.same {
        d: {
          color: "blue"
        }
        k: "hello world"
      }, decode_with_secret t


  describe "validate_token", ->
    it "fails validation when param is missing", ->
      assert.same {
        nil, "missing csrf token"
      }, {
        csrf.validate_token {
          cookies: {
            lapis_session_token: "blahblah"
          }
          params: { }
        }
      }

    it "fails validation when cookie isn't set", ->
      assert.same {
        nil
        "csrf: missing token cookie"
      },{
        csrf.validate_token {
          cookies: { }
          params: {
            csrf_token: "testtoeknthing"
          }
        }
      }

    it "fails validation for invalid signed token", ->
      r = { cookies: {} }
      token = csrf.generate_token r

      assert.same {
        nil
        "csrf: invalid format"
      },{
        csrf.validate_token {
          cookies: r.cookies
          params: {
            csrf_token: "this is wrong"
          }
        }
      }

    it "fails validation for cookie mismatch", ->
      r = { cookies: {} }
      token = csrf.generate_token r

      assert.same {
        nil
        "csrf: token mismatch"
      },{
        csrf.validate_token {
          cookies: {
            lapis_session_token: "random bytes"
          }
          params: {
            csrf_token: token
          }
        }
      }

    it "validates token", ->
      r = { cookies: {} }
      token = csrf.generate_token r, {
        color: "blue"
      }

      assert csrf.validate_token {
        cookies: r.cookies
        params: {
          csrf_token: token
        }
      }

    it "fails validation when token callback fails", ->
      r = { cookies: {} }
      token = csrf.generate_token r, { number: 5 }

      assert.same {
        nil
        "csrf: is not right"
      },{
        csrf.validate_token {
          cookies: r.cookies
          params: {
            csrf_token: token
          }
        }, (d) ->
          assert.same {
            number: 5
          }, d
          nil, "is not right"
      }

      -- with no error messag
      assert.same {
        nil
        "csrf: failed check"
      },{
        csrf.validate_token {
          cookies: r.cookies
          params: {
            csrf_token: token
          }
        }, (d) -> nil
      }

    it "valides token with callback", ->
      r = { cookies: {} }
      token = csrf.generate_token r, { number: 5 }

      assert csrf.validate_token {
        cookies: r.cookies
        params: {
          csrf_token: token
        }
      }, (d) -> d.number == 5

  describe "random bytes backend", ->
    -- stands in for luaossl's openssl.rand and OpenResty's resty.random
    fake_rand = (char, log) -> {
      bytes: (n, strong) ->
        table.insert log, { :n, :strong } if log
        string.rep char, n
    }

    generate_key = (c) ->
      r = { cookies: {} }
      assert c.generate_token r
      r.cookies.lapis_session_token

    it "uses luaossl when it's installed", ->
      ngx_stack.push { config: {} }
      finally -> ngx_stack.pop!

      c = require_with_stubs "lapis.csrf", {
        "openssl.rand": fake_rand "a"
        "resty.random": fake_rand "b"
      }

      assert.same encode_base64(string.rep "a", 32), generate_key c

    it "falls back to resty.random with nginx", ->
      ngx_stack.push { config: {} }
      finally -> ngx_stack.pop!

      calls = {}
      c = require_with_stubs "lapis.csrf", {
        "openssl.rand": false
        "resty.random": fake_rand "b", calls
      }

      assert.same encode_base64(string.rep "b", 32), generate_key c
      -- asks for cryptographically strong bytes
      assert.same {{ n: 32, strong: true }}, calls

    it "fails when resty.random can't generate bytes", ->
      ngx_stack.push { config: {} }
      finally -> ngx_stack.pop!

      c = require_with_stubs "lapis.csrf", {
        "openssl.rand": false
        "resty.random": { bytes: -> nil }
      }

      ok, err = pcall generate_key, c
      assert.same false, ok
      assert.truthy err\find "resty.random failed to generate random bytes", 1, true

    describe "without nginx", ->
      assert_no_backend = ->
        c = require_with_stubs "lapis.csrf", {
          "openssl.rand": false
          "resty.random": fake_rand "b"
        }

        ok, err = pcall generate_key, c
        assert.same false, ok
        assert.truthy err\find "generating a token requires luaossl (or resty.random in OpenResty)", 1, true
        -- includes the reason luaossl couldn't be loaded
        assert.truthy err\find "luaossl failed to load: module 'openssl.rand' not found (stubbed by spec)", 1, true

      it "fails to generate a token without luaossl", ->
        assert_no_backend!

      it "doesn't use resty.random in a simulated request", ->
        -- the fake ngx of a simulated request has no ngx.config
        ngx_stack.push { _lapis_simulate: true }
        finally -> ngx_stack.pop!
        assert_no_backend!

    it "validates tokens without a backend", ->
      c = require_with_stubs "lapis.csrf", {
        "openssl.rand": false
        "resty.random": false
      }

      r = { cookies: {} }
      token = csrf.generate_token r

      assert c.validate_token {
        cookies: r.cookies
        params: { csrf_token: token }
      }
