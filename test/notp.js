
var notp = require('..');

/*
 * Test HOTP.  Uses test values from RFC 4226
 *
 *
 *    The following test data uses the ASCII string
 *    "12345678901234567890" for the secret:
 *
 * Secret = 0x3132333435363738393031323334353637383930
 *
 * Table 1 details for each count, the intermediate HMAC value.
 *
 * Count    Hexadecimal HMAC-SHA-1(secret, count)
 * 0        cc93cf18508d94934c64b65d8ba7667fb7cde4b0
 * 1        75a48a19d4cbe100644e8ac1397eea747a2d33ab
 * 2        0bacb7fa082fef30782211938bc1c5e70416ff44
 * 3        66c28227d03a2d5529262ff016a1e6ef76557ece
 * 4        a904c900a64b35909874b33e61c5938a8e15ed1c
 * 5        a37e783d7b7233c083d4f62926c7a25f238d0316
 * 6        bc9cd28561042c83f219324d3c607256c03272ae
 * 7        a4fb960c0bc06e1eabb804e5b397cdc4b45596fa
 * 8        1b3c89f65e6c9e883012052823443f048b4332db
 * 9        1637409809a679dc698207310c8c7fc07290d9e5
 *
 * Table 2 details for each count the truncated values (both in
 * hexadecimal and decimal) and then the HOTP value.
 *
 *                   Truncated
 * Count    Hexadecimal    Decimal        HOTP
 * 0        4c93cf18       1284755224     755224
 * 1        41397eea       1094287082     287082
 * 2         82fef30        137359152     359152
 * 3        66ef7655       1726969429     969429
 * 4        61c5938a       1640338314     338314
 * 5        33c083d4        868254676     254676
 * 6        7256c032       1918287922     287922
 * 7         4e5b397         82162583     162583
 * 8        2823443f        673399871     399871
 * 9        2679dc69        645520489     520489
 *
 *
 * see http://tools.ietf.org/html/rfc4226
 */
exports.testHOTP = function(beforeExit, assert) {
	var args = {
		W : 0,
		K : '12345678901234567890'
	};
	var HOTP = ['755224', '287082','359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];

	// Check for failure
	args.C = 0;
	args.P = 'WILLNOTPASS';
	assert.ok(!notp.checkHOTP(args), 'Should not pass');

	// Check for passes
	for(i=0;i<HOTP.length;i++) {
		args.C = i;
		args.P = HOTP[i];
		var res = notp.checkHOTP(args);

		assert.ok(res, 'Should pass');
		assert.eql(res.delta, 0, 'Should be in sync');
	}
};


/*
 * Test TOTP using test vectors from TOTP RFC.
 *
 * see http://tools.ietf.org/id/draft-mraihi-totp-timebased-06.txt
 */
exports.testTOTP = function(beforeExit, assert) {
	var args = {
		W : 0,
		K : '12345678901234567890'
	};

	// Check for failure
	args.T = 0;
	args.P = 'WILLNOTPASS';
	assert.ok(!notp.checkTOTP(args), 'Should not pass');

	// Check for test vector at 59s
	args._t = 59*1000;
	args.P = '287082';
	var res = notp.checkTOTP(args);
	assert.ok(res, 'Should pass');
	assert.eql(res.delta, 0, 'Should be in sync');

	// Check for test vector at 1234567890
	args._t = 1234567890*1000;
	args.P = '005924';
	var res = notp.checkTOTP(args);
	assert.ok(res, 'Should pass');
	assert.eql(res.delta, 0, 'Should be in sync');

	// Check for test vector at 1111111109
	args._t = 1111111109*1000;
	args.P = '081804';
	var res = notp.checkTOTP(args);
	assert.ok(res, 'Should pass');
	assert.eql(res.delta, 0, 'Should be in sync');

	// Check for test vector at 2000000000
	args._t = 2000000000*1000;
	args.P = '279037';
	notp.checkTOTP(args,
		function(ret, w) {
			assert.eql(ret, true, 'Should pass');
			assert.eql(w, 0, 'Should be in sync');
			n++;
		}
	);
};


/*
 * Check for codes that are out of sync
 * We are going to use a value of C = 1 and test against
 * a code for C = 9
 */
exports.testHOTPOutOfSync = function(beforeExit, assert) {

	var args = {
		K : '12345678901234567890',
		P : '520489',
		C : 1
	};

	// Check that the test should fail for W < 8
	args.W = 7;
	assert.ok(!notp.checkHOTP(args), 'Should not pass for value of W < 8');

	// Check that the test should pass for W >= 9
	args.W = 8;
	assert.ok(notp.checkHOTP(args), 'Should pass for value of W >= 9');
};


/*
 * Check for codes that are out of sync
 * We are going to use a value of T = 1999999909 (91s behind 2000000000)
 */
exports.testTOTPOutOfSync = function(beforeExit, assert) {

	var args = {
		K : '12345678901234567890',
		P : '279037',
		_t : 1999999909*1000
	};

	// Check that the test should fail for W < 2
	args.W = 2;
	assert.ok(!notp.checkTOTP(args), 'Should not pass for value of W < 3');

	// Check that the test should pass for W >= 3
	args.W = 3;
	assert.ok(notp.checkTOTP(args), 'Should pass for value of W >= 3');
};


/*
 * Test getHOTP function.  Uses same test values as for checkHOTP
 */
exports.testGetHOTP = function(beforeExit, assert) {
	var args = {
		W : 0,
		K : '12345678901234567890'
	};

	var HOTP = ['755224', '287082','359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];

	// Check for passes
	for(i=0;i<HOTP.length;i++) {
		args.C = i;
		assert.eql(notp.getHOTP(args), HOTP[i], 'HTOP value should be correct');
	}
};


/*
 * Test getTOTP function. Uses same test values as for checkTOTP
 */
exports.testGetTOTP = function(beforeExit, assert) {
	var args = {
		W : 0,
		K : '12345678901234567890'
	};

	// Check for test vector at 59s
	args._t = 59*1000;
	assert.eql(notp.getTOTP(args), '287082', 'TOTP values should match');

	// Check for test vector at 1234567890
	args._t = 1234567890*1000;
	assert.eql(notp.getTOTP(args), '005924', 'TOTP values should match');

	// Check for test vector at 1111111109
	args._t = 1111111109*1000;
	assert.eql(notp.getTOTP(args), '081804', 'TOTP values should match');

	// Check for test vector at 2000000000
	args._t = 2000000000*1000;
	assert.eql(notp.getTOTP(args), '279037', 'TOTP values should match');
};

