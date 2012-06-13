
var notp = require('../index'),
    t2 = require('thirty-two'),
    K = '12345678901234567890',
	b32 = t2.encode(K);

console.log('Getting current counter value for K = 12345678901234567890');
console.log('This has a base32 value of ' + b32);
console.log('The base32 value should be entered in the Google Authenticator App');
console.log('');
console.log('Open the following URL for a QR code.  Google Authenticator can read this QR code using your phone\'s camera:');
console.log('http://qrcode.kaywa.com/img.php?s=8&d=' + encodeURIComponent('otpauth://totp/notp@example.com?secret=' + b32));

console.log('The current TOTP value is ' + notp.totp.gen(K, {}));

