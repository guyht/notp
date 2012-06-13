
var notp = require('../index'),
    t2 = require('thirty-two'),
    K = '12345678901234567890',
	b32 = t2.encode(K);

console.log('Click on this link to gennerate a QR code, and use Google Authenticator on your phone to read it:');
console.log('http://qrcode.kaywa.com/img.php?s=8&d=' + encodeURIComponent('otpauth://totp/notp@example.com?secret=' + b32));
verify();

function verify() {
    ask('Enter a code to verify', function(code) {
        if(notp.totp.verify(code, K, {})) {
            console.log('Success!!!');
        }
        console.log(notp.totp.verify(code, K, {}));
        verify();
    });
}



function ask(question, callback) {
    var stdin = process.stdin, stdout = process.stdout;

    stdin.resume();
    stdout.write(question + ": ");

    stdin.once('data', function(data) {
        data = data.toString().trim();
        callback(data);
    });
}
