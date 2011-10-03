
var notp = require('../lib/notp'),
	args = {
		K : '12345678901234567890'
	},
	b32 = notp.encBase32(args.K);

console.log('Getting current counter value for K = 12345678901234567890');
console.log('This has a base32 value of ' + b32);
console.log('The base32 value should be entered in the Google Authenticator App');
console.log('');

notp.getTOTP(args,
	function(err) { console.log(err); },
	function(code) {
		console.log('The current TOTP value is ' + code);
	}
);

