
var crypto = require('crypto');
var base32 = require('thirty-two');

/*
 * Check a One Time Password based on a counter.
 *
 * First argument of callback is true if password check is successful,
 * or false if check fails.
 *
 * Second argument is the time step difference between the client and
 * the server.  This argument is only passed if the password check is
 * successful.
 *
 * Arguments:
 *
 *  args
 *     K - Key for the one time password.  This should be unique and secret for
 *         every user as it is the seed used to calculate the HMAC
 *
 *     P - Passcode to validate.
 *
 *     W - The allowable margin for the counter.  The function will check
 *         W codes in the future against the provided passcode.  Note,
 *         it is the calling applications responsibility to keep track of
 *         W and increment it for each password check, and also to adjust
 *         it accordingly in the case where the client and server become
 *         out of sync (second argument returns non zero).
 *         E.g. if W = 100, and C = 5, this function will check the psscode
 *         against all One Time Passcodes between 5 and 105.
 *
 *         Default - 50
 *
 *     C - Counter value.  This should be stored by the application, must
 *         be user specific, and be incremented for each request.
 *
 */
module.exports.checkHOTP = function(args, err, cb) {

	var hmac,
		digest,
		offset, h, v, p = 6, b,
		i,
		K = args.K || "",
		W = args.W || 50,
		C = args.C || 0,
		P = args.P || "";


	// Initiate the HMAC
	hmac = crypto.createHmac('SHA1', new Buffer(K))

	// Now loop through from C to C + W to determine if there is
	// a correct code
	for(i = C; i <= C+W; i++) {
		if(this._calcHMAC(K,i) === P) {
			// We have found a matching code, trigger callback
			// and pass offset
			cb(true, i - C);
			return;
		}
	}

	// If we get to here then no codes have matched, return false
	cb(false);
	return;

};


/*
 * Check a One Time Password based on a timer.
 *
 * First argument of callback is true if password check is successful,
 * or false if check fails.
 *
 * Second argument is the time step difference between the client and
 * the server.  This argument is only passed if the password check is
 * successful.
 *
 * Arguments:
 *
 *  args
 *     K - Key for the one time password.  This should be unique and secret for
 *         every user as it is the seed used to calculate the HMAC
 *
 *     P - Passcode to validate.
 *
 *     W - The allowable margin for the counter.  The function will check
 *         W codes either side of the provided counter.  Note,
 *         it is the calling applications responsibility to keep track of
 *         W and increment it for each password check, and also to adjust
 *         it accordingly in the case where the client and server become
 *         out of sync (second argument returns non zero).
 *         E.g. if W = 5, and C = 1000, this function will check the psscode
 *         against all One Time Passcodes between 995 and 1005.
 *
 *         Default - 6
 *
 *     T - The time step of the counter.  This must be the same for
 *         every request and is used to calculat C.
 *
 *         Default - 30
 *
 */
module.exports.checkTOTP = function(args, err, cb) {

	var hmac,
		digest,
		offset, h, v, p = 6, b,
		C,i,
		K = args.K || "",
		W = args.W || 6,
		T = args.T || 30,
		P = args.P || "",
		_t;


	if(args._t) {
		// Time has been overwritten.
		console.log('#####################################');
		console.log('# NOTE: TOTP TIME VARIABLE HAS BEEN #');
		console.log('# OVERWRITTEN.  THIS SHOULD ONLY BE #');
		console.log('# USED FOR TEST PURPOSES.           #');
		console.log('#####################################');
		_t = args._t;
	} else {
		_t = new Date().getTime();
	}

	// Initiate the HMAC
	hmac = crypto.createHmac('SHA1', new Buffer(K))

	// Determine the value of the counter, C
	// This is the number of time steps in seconds since T0
	C = Math.floor((_t / 1000) / T);

	// Now loop through from C - W to C + W and check to see
	// if we have a valid code in that time line
	for(i = C-W; i <= C+W; i++) {

		if(this._calcHMAC(K,i) === P) {
			// We have found a matching code, trigger callback
			// and pass offset
			cb(true, i-C);
			return;
		}
	}

	// If we get to here then no codes have matched, return false
	cb(false);
	return;
};


/*
 * Gennerate a counter based One Time Password
 *
 * First argument of callback is the value of the One Time Password
 *
 * Arguments:
 *
 *  args
 *     K - Key for the one time password.  This should be unique and secret for
 *         every user as it is the seed used to calculate the HMAC
 *
 *     C - Counter value.  This should be stored by the application, must
 *         be user specific, and be incremented for each request.
 *
 */
module.exports.getHOTP = function(args, err, cb) {

	var hmac,
		digest,
		offset, h, v, p = 6, b,
		i,
		K = args.K || "",
		C = args.C || 0,


	// Initiate the HMAC
	hmac = crypto.createHmac('SHA1', new Buffer(K))

	cb(this._calcHMAC(K,C));

};


/*
 * Gennerate a time based One Time Password
 *
 * First argument of callback is the value of the One Time Password
 *
 * Arguments:
 *
 *  args
 *     K - Key for the one time password.  This should be unique and secret for
 *         every user as it is the seed used to calculate the HMAC
 *
 *     T - The time step of the counter.  This must be the same for
 *         every request and is used to calculat C.
 *
 *         Default - 30
 *
 */
module.exports.getTOTP = function(args, err, cb) {
	var hmac,
		digest,
		offset, h, v, p = 6, b,
		C,i,
		K = args.K || "",
		T = args.T || 30,
		_t;


	if(args._t) {
		// Time has been overwritten.
		console.log('#####################################');
		console.log('# NOTE: TOTP TIME VARIABLE HAS BEEN #');
		console.log('# OVERWRITTEN.  THIS SHOULD ONLY BE #');
		console.log('# USED FOR TEST PURPOSES.           #');
		console.log('#####################################');
		_t = args._t;
	} else {
		_t = new Date().getTime();
	}

	// Initiate the HMAC
	hmac = crypto.createHmac('SHA1', new Buffer(K))

	// Determine the value of the counter, C
	// This is the number of time steps in seconds since T0
	C = Math.floor((_t / 1000) / T);

	cb(this._calcHMAC(K,C));
};


/*
 * Helper function to convert a string to a base32 encoded string
 *
 * Arguments:
 *
 * str - String to encode
 *
 * Returns: Base 32 encoded string
 */
module.exports.encBase32 = function(str) {
	return base32.encode(str);
};


/*
 * Helper function to convert a base32 encoded string to an ascii string
 *
 * Arguments:
 *
 * b32 - String to decode
 *
 * Returns: ASCII string
 */
module.exports.decBase32 = function(b32) {
	return base32.decode(b32);
};


/******************************************************************
 * NOTE: Any functions below this line are private and therefore  *
 * may change without providing backwards compatibility with      *
 * previous versions.  You should not call the functions below    *
 * directly.                                                      *
*******************************************************************/


/*
 * Private functon to calculate an HMAC.
 *
 * Arguments
 *
 *  K - Key value
 *  C - Counter value
 *
 *  Returns - truncated HMAC
 */
module.exports._calcHMAC = function(K, C) {

	var hmac = crypto.createHmac('SHA1', new Buffer(K)),
		digest,
		offset, h, v, p = 6, b;

	// Create the byte array
	b = new Buffer(this._intToBytes(C)),

	// Update the HMAC witht he byte array
	hmac.update(b);

	// Diget the HMAC
	digest = hmac.digest('hex');

	// Get byte array
	h = this._hexToBytes(digest);

	// Truncate
	offset = h[19] & 0xf;
	v = (h[offset] & 0x7f) << 24 | (h[offset + 1] & 0xff) << 16 | (h[offset + 2] & 0xff) << 8 | (h[offset + 3] & 0xff);
	v = "" + v;
	v = v.substr(v.length - p, p);

	return v;
};


/*
 * Private function to convert an integer to a byte array
 *
 * Arguments
 *
 * num - Integer
 *
 * Returns - byte array
 */
module.exports._intToBytes = function(num) {
	var bytes = [],
		i;

	for(i=7;i>=0;i--) {
		bytes[i] = num & (255);
		num = num >> 8;
	}

	return bytes;
};


/*
 * Private function to convert a hex value to a byte array
 *
 * Arguments
 *
 * hex - Hex value
 *
 * Returns - byte array
 */
module.exports._hexToBytes = function(hex) {
	for(var bytes = [], c = 0; c < hex.length; c += 2)
			bytes.push(parseInt(hex.substr(c, 2), 16));
	return bytes;
};

