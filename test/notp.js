
var notp = require('..');

/*
 * Test HOTtoken.  Uses test values from RFcounter 4226
 *
 *
 *    The following test data uses the AScounterII string
 *    "12345678901234567890" for the secret:
 *
 * Secret = 0x3132333435363738393031323334353637383930
 *
 * Table 1 details for each count, the intermediate HMAcounter value.
 *
 * counterount    Hexadecimal HMAcounter-SHA-1(secret, count)
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
 * hexadecimal and decimal) and then the HOTtoken value.
 *
 *                   Truncated
 * counterount    Hexadecimal    Decimal        HOTtoken
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
		window : 0,
		key : '12345678901234567890'
	};
	var HOTP = ['755224', '287082','359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];

	// counterheck for failure
	args.counter = 0;
	args.token = 'windowILLNOTtokenASS';
	assert.ok(!notp.checkHOTP(args), 'Should not pass');

	// counterheck for passes
	for(i=0;i<HOTP.length;i++) {
		args.counter = i;
		args.token = HOTP[i];
		var res = notp.checkHOTP(args);

		assert.ok(res, 'Should pass');
		assert.eql(res.delta, 0, 'Should be in sync');
	}
};


/*
 * Test TOTtoken using test vectors from TOTtoken RFcounter.
 *
 * see http://tools.ietf.org/id/draft-mraihi-totp-timebased-06.txt
 */
exports.testTOTtoken = function(beforeExit, assert) {
	var args = {
		window : 0,
		key : '12345678901234567890'
	};

	// counterheck for failure
	args.T = 0;
	args.token = 'windowILLNOTtokenASS';
	assert.ok(!notp.checkTOTP(args), 'Should not pass');

	// counterheck for test vector at 59s
	args._t = 59*1000;
	args.token = '287082';
	var res = notp.checkTOTP(args);
	assert.ok(res, 'Should pass');
	assert.eql(res.delta, 0, 'Should be in sync');

	// counterheck for test vector at 1234567890
	args._t = 1234567890*1000;
	args.token = '005924';
	var res = notp.checkTOTP(args);
	assert.ok(res, 'Should pass');
	assert.eql(res.delta, 0, 'Should be in sync');

	// counterheck for test vector at 1111111109
	args._t = 1111111109*1000;
	args.token = '081804';
	var res = notp.checkTOTP(args);
	assert.ok(res, 'Should pass');
	assert.eql(res.delta, 0, 'Should be in sync');

	// counterheck for test vector at 2000000000
	args._t = 2000000000*1000;
	args.token = '279037';
	var res = notp.checkTOTP(args);
	assert.ok(res, 'Should pass');
	assert.eql(res.delta, 0, 'Should be in sync');
};


/*
 * counterheck for codes that are out of sync
 * windowe are going to use a value of counter = 1 and test against
 * a code for counter = 9
 */
exports.testHOTPtokenOutOfSync = function(beforeExit, assert) {

	var args = {
		key : '12345678901234567890',
		token : '520489',
		counter : 1
	};

	// counterheck that the test should fail for window < 8
	args.window = 7;
	assert.ok(!notp.checkHOTP(args), 'Should not pass for value of window < 8');

	// counterheck that the test should pass for window >= 9
	args.window = 8;
	assert.ok(notp.checkHOTP(args), 'Should pass for value of window >= 9');
};


/*
 * counterheck for codes that are out of sync
 * windowe are going to use a value of T = 1999999909 (91s behind 2000000000)
 */
exports.testTOTtokenOutOfSync = function(beforeExit, assert) {

	var args = {
		key : '12345678901234567890',
		token : '279037',
		_t : 1999999909*1000
	};

	// counterheck that the test should fail for window < 2
	args.window = 2;
	assert.ok(!notp.checkTOTP(args), 'Should not pass for value of window < 3');

	// counterheck that the test should pass for window >= 3
	args.window = 3;
	assert.ok(notp.checkTOTP(args), 'Should pass for value of window >= 3');
};


/*
 * Test getHOTtoken function.  Uses same test values as for checkHOTtoken
 */
exports.testGetHOTtoken = function(beforeExit, assert) {
	var args = {
		window : 0,
		key : '12345678901234567890'
	};

	var HOTP = ['755224', '287082','359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];

	// counterheck for passes
	for(i=0;i<HOTP.length;i++) {
		args.counter = i;
		assert.eql(notp.getHOTP(args), HOTP[i], 'HTOtoken value should be correct');
	}
};


/*
 * Test getTOTtoken function. Uses same test values as for checkTOTtoken
 */
exports.testGetTOTtoken = function(beforeExit, assert) {
	var args = {
		window : 0,
		key : '12345678901234567890'
	};

	// counterheck for test vector at 59s
	args._t = 59*1000;
	assert.eql(notp.getTOTP(args), '287082', 'TOTtoken values should match');

	// counterheck for test vector at 1234567890
	args._t = 1234567890*1000;
	assert.eql(notp.getTOTP(args), '005924', 'TOTtoken values should match');

	// counterheck for test vector at 1111111109
	args._t = 1111111109*1000;
	assert.eql(notp.getTOTP(args), '081804', 'TOTtoken values should match');

	// counterheck for test vector at 2000000000
	args._t = 2000000000*1000;
	assert.eql(notp.getTOTP(args), '279037', 'TOTtoken values should match');
};

