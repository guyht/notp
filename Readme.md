# Node One Time Password library
 Simple to use, fast, and with zero dependencies.  The Node One Time Password library is fully compliant with [HOTP](http://tools.ietf.org/html/rfc4226) (counter based one time passwords) and [TOTP](http://tools.ietf.org/html/rfc6238) (time based one time passwords).  It was designed to be used in conjunction with the [Google Authenticator](http://code.google.com/p/google-authenticator/) which has free apps for iOS, Android and BlackBerry.

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

// to create a URI for a qr code (change totp to hotp is using hotp)
var uri = 'otpauth://totp/somelabel?secret=' + encoded';
```

Note: If your label has spaces or other invalid uri characters you will need to encode it accordingly using `encodeURIComponent` More details about the uri key format can be found on the [google auth wiki](https://code.google.com/p/google-authenticator/wiki/KeyUriFormat)

# API
##hotp.verify(token, key, opt)

    Check a One Time Password based on a counter.

    First argument of callback is true if password check is successful,
    or false if check fails.

    Second argument is the time step difference between the client and
    the server.  This argument is only passed if the password check is
    successful.

    Arguments:


    opt
      window - The allowable margin for the counter.  The function will check
          W codes in the future against the provided passcode.  Note,
          it is the calling applications responsibility to keep track of
          W and increment it for each password check, and also to adjust
          it accordingly in the case where the client and server become
          out of sync (second argument returns non zero).
          E.g. if W = 100, and C = 5, this function will check the psscode
          against all One Time Passcodes between 5 and 105.

         Default - 50

      counter - Counter value.  This should be stored by the application, must
         be user specific, and be incremented for each request.


**Example**

```javascript
var key = 'USER SPECIFIC KEY', // Should be ASCII string
var token = 'USER SUPPLIED PASSCODE'

var res = notp.hotp.verify(token, key, opt);

// not valid
if (!res) {
    return console.log('invalid');
}

console.log('valid, counter is out of sync by %d steps', res.delta);
```

##totp.verify(token, key, opt)


    Check a One Time Password based on a timer.

    First argument of callback is true if password check is successful,
    or false if check fails.

    Second argument is the time step difference between the client and
    the server.  This argument is only passed if the password check is
    successful.

    Arguments:

    opt
     window - The allowable margin for the counter.  The function will check
         W codes either side of the provided counter.  Note,
         it is the calling applications responsibility to keep track of
         W and increment it for each password check, and also to adjust
         it accordingly in the case where the client and server become
         out of sync (second argument returns non zero).
         E.g. if W = 5, and C = 1000, this function will check the psscode
         against all One Time Passcodes between 995 and 1005.

         Default - 6

     time - The time step of the counter.  This must be the same for
         every request and is used to calculat C.

         Default - 30


**Example**

```javascript
var key = 'USER SPECIFIC KEY', // Should be ASCII string
var token = 'USER SUPPLIED PASSCODE'

var res = notp.totp.verify(token, key, opt);

// not valid
if (!res) {
    return console.log('invalid');
}

console.log('valid, counter is out of sync by %d steps', res.delta);
```

##hotp.gen(key, opt)

    Generate a counter based One Time Password

    First argument of callback is the value of the One Time Password

    Arguments:

    opt
     counter - Counter value.  This should be stored by the application, must
         be user specific, and be incremented for each request.

**Example**

```javascript
var token = notp.hotp.gen(key, {
    counter : 5 // COUNTER VALUE
});
```

##totp.gen(key, opt)

    Generate a time based One Time Password

    First argument of callback is the value of the One Time Password

    Arguments:

    opt
     time - The time step of the counter.  This must be the same for
         every request and is used to calculate C.

         Default - 30

**Example**

```javascript
var token = notp.totp.gen(key);
```

## License

(The MIT License)

Copyright (c) 2011 Guy Halford-Thompson &lt;guy@cach.me&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

