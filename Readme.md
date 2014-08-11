[![Build Status](https://travis-ci.org/guyht/notp.svg)](https://travis-ci.org/guyht/notp)

# Node One Time Password library
 Simple to use, fast, and with zero dependencies.  The Node One Time Password library is fully compliant with [HOTP](http://tools.ietf.org/html/rfc4226) (counter based one time passwords) and [TOTP](http://tools.ietf.org/html/rfc6238) (time based one time passwords).  It can be used in conjunction with the [Google Authenticator](http://code.google.com/p/google-authenticator/) which has free apps for iOS, Android and BlackBerry.

# Installation

```
npm install notp
```

# Usage

```javascript
var notp = require('notp');

//.... some initial login code, that receives the user details and TOTP / HOTP token

var key = 'secret key for user... could be stored in DB';
var token = 'user supplied one time use token';

// Check TOTP is correct (HOTP if hotp pass type)
var login = notp.totp.verify(token, key);

// invalid token if login is null
if (!login) {
    return console.log('Token invalid');
}

// valid token
console.log('Token valid, sync value is %s', login.delta);
```

## Google Authenticator

[Google authenticator](https://code.google.com/p/google-authenticator/) requires that keys be base32 encoded before being used. This includes manual entry into the app as well as preparing a QR code URI.

To base32 encode a utf8 key you can use the `thirty-two` module.

```javascript
var base32 = require('thirty-two');

var key = 'secret key for the user';

// encoded will be the secret key, base32 encoded
var encoded = base32.encode(key);

// Google authenticator doesn't like equal signs
var encodedForGoogle = encoded.toString().replace(/=/g,'');

// to create a URI for a qr code (change totp to hotp is using hotp)
var uri = 'otpauth://totp/somelabel?secret=' + encodedForGoogle;
```

Note: If your label has spaces or other invalid uri characters you will need to encode it accordingly using `encodeURIComponent` More details about the uri key format can be found on the [google auth wiki](https://code.google.com/p/google-authenticator/wiki/KeyUriFormat)

# API
##hotp.verify(token, key, opt)

Check a counter based one time password for validity.

Returns null if token is not valid for given key and options.

Returns an object `{delta: #}` if the token is valid. `delta` is the count skew between client and server.

### opt
**window**
> The allowable margin for the counter. The function will check `window` codes in the future against the provided token.
> i.e. if `window = 100` and `counter = 5` all tokens between 5 and 105 will be checked against the supplied token
> Default - 50

**counter**
> Counter value. This should be stored by the application on a per user basis. It is up to the application to track and increment this value as needed. It is also up to the application to increment this value if there is a skew between the client and server (`delta`)

##totp.verify(token, key, opt)

Check a time based one time password for validity

Returns null if token is not valid for given key and options.

Returns an object `{delta: #}` if the token is valid. `delta` is the count skew between client and server.

### opt
**window**
> The allowable margin for the counter. The function will check `window` codes in the future against the provided token.
> i.e. if `window = 5` and `counter = 1000` all tokens between 995 and 1005 will be checked against the supplied token
> Default - 6

**time**
> The time step of the counter. This must be the same for every request and is used to calculate C.
> Default - 30

##hotp.gen(key, opt)

Return a counter based one time password

### opt
**counter**
> Counter value. This should be stored by the application, must be user specific, and be incremented for each request.

##totp.gen(key, opt)

Return a time based one time password

### opt
**time**
> The time step of the counter. This must be the same for every request and is used to calculate C.
> Default - 30

# Migrating from 1.x to 2.x

## Removed
The `encBase32` and `decBase32` methods have been removed. If you wish to encode/decode base32 you should install a module to do so. We recommend the `thirty-two` npm module.

## Changed

All of the APIs have been changed to return values directly instead of using callbacks. This reflects the fact that the functions are actually synchronous and perform no I/O.

Some of the required arguments to the functions have also been removed from the `args` parameter and are passed as separate function parameters. See the above API docs for details.

* `notp.checkHOTP(args, err, cb)` -> `notp.hotp.verify(token, key, opt)`
* `notp.checkTOTP(args, err, cb)` -> `notp.totp.verify(token, key, opt)`
* `notp.getHOTP(args, err, cb)` -> `notp.gotp.gen(key, opt)`
* `notp.getTOTP(args, err, cb)` -> `notp.totp.gen(key, opt)`

## Args

The argument names have also changed to better describe the purpose of the argument.

* `K` -> no longer in args/opt but passed directly as a function argument
* `P` -> no longer in args/opt but passed directly as a function argument
* `W` -> `window`
* `C` -> `counter`
* `T` -> `time`

