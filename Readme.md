# Node One Time Password library
 Simple to use, fast, and with zero dependencies.  The Node One Time Password library is fully compliant with [HOTP](http://tools.ietf.org/html/rfc4226) (counter based one time passwords) and [TOTP](http://tools.ietf.org/html/rfc6238) (time based one time passwords).  It was designed to be used in conjunction with the [Google Authenticator](http://code.google.com/p/google-authenticator/) which has free apps for iOS, Android and BlackBerry.

# Installation

```
npm install notp
```

# Usage

IMPORTANT: The NOTP library accepts ASCII strings as keys, but the Google Authenticator app uses base32 encoded strings.  If you wish to use this library in conjunction with the Google Authenticator app, then you need to convert the keys to base32 before entering them into the Google Authenticator app.

```javascript
var notp = require('notp');

var args = {};

//.... some initial login code, that receives the TOTP / HTOP
// token from the user
args.K = 'TOTP key for user... could be stored in DB';
args.P = 'User supplied TOTP value';

// Check TOTP is correct
var login = notp.checkTOTP(args);

// invalid token
if (!login) {
    return console.log('Token invalid');
}

// valid token
console.log('Token valid, sync value is %s', login.delta);
```

# API
##notp.checkHOTP(args)

    Check a One Time Password based on a counter.

    First argument of callback is true if password check is successful,
    or false if check fails.

    Second argument is the time step difference between the client and
    the server.  This argument is only passed if the password check is
    successful.

    Arguments:

    args
      K - Key for the one time password.  This should be unique and secret for
          every user as it is the seed used to calculate the HMAC

      P - Passcode to validate.

      W - The allowable margin for the counter.  The function will check
          W codes in the future against the provided passcode.  Note,
          it is the calling applications responsibility to keep track of
          W and increment it for each password check, and also to adjust
          it accordingly in the case where the client and server become
          out of sync (second argument returns non zero).
          E.g. if W = 100, and C = 5, this function will check the psscode
          against all One Time Passcodes between 5 and 105.

         Default - 50

      C - Counter value.  This should be stored by the application, must
         be user specific, and be incremented for each request.


**Example**

```javascript
var opt = {
    K : 'USER SPECIFIC KEY', // Should be ASCII string
    P : 'USER SUPPLIED PASSCODE'
};

var res = notp.checkHOTP(opt);

// not valid
if (!res) {
    return console.log('invalid');
}

console.log('valid, counter is out of sync by %d steps', res.delta);
```

##notp.checkTOTP(args, err, cb)


    Check a One Time Password based on a timer.

    First argument of callback is true if password check is successful,
    or false if check fails.

    Second argument is the time step difference between the client and
    the server.  This argument is only passed if the password check is
    successful.

    Arguments:

    args
     K - Key for the one time password.  This should be unique and secret for
         every user as it is the seed used to calculate the HMAC

     P - Passcode to validate.

     W - The allowable margin for the counter.  The function will check
         W codes either side of the provided counter.  Note,
         it is the calling applications responsibility to keep track of
         W and increment it for each password check, and also to adjust
         it accordingly in the case where the client and server become
         out of sync (second argument returns non zero).
         E.g. if W = 5, and C = 1000, this function will check the psscode
         against all One Time Passcodes between 995 and 1005.

         Default - 6

     T - The time step of the counter.  This must be the same for
         every request and is used to calculat C.

         Default - 30


**Example**

```javascript
var opt = {
    K : 'USER SPECIFIC KEY', // Should be ASCII string
    P : 'USER SUPPLIED PASSCODE'
};

var res = notp.checkTOTP(opt);

// not valid
if (!res) {
    return console.log('invalid');
}

console.log('valid, counter is out of sync by %d steps', res.delta);
```

##notp.getHOTP(args, err, cb)

    Generate a counter based One Time Password

    First argument of callback is the value of the One Time Password

    Arguments:

    args
     K - Key for the one time password.  This should be unique and secret for
         every user as it is the seed used to calculate the HMAC

     C - Counter value.  This should be stored by the application, must
         be user specific, and be incremented for each request.

**Example**

```javascript
var token = notp.getHOTP({
    K : 'USER SPECIFIC KEY', // Should be ASCII string
    C : 5 // COUNTER VALUE
});
```

##notp.getTOTP(args, err, cb)

    Generate a time based One Time Password

    First argument of callback is the value of the One Time Password

    Arguments:

    args
     K - Key for the one time password.  This should be unique and secret for
         every user as it is the seed used to calculate the HMAC

     T - The time step of the counter.  This must be the same for
         every request and is used to calculat C.

         Default - 30

**Example**

```javascript
var token = notp.getTOTP({
    K : 'USER SPECIFIC KEY' // Should be ASCII string
});
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

