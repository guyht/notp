
var crypto = require('crypto');

/**
 * Check a One Time Password based on a counter.
 *
 * @return {Object} null if failure, { delta: # } on success
 * delta is the time step difference between the client and the server
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
module.exports.checkHOTP = function(args) {

	var W = args.W || 50;
	var C = args.C || 0;
	var P = args.P || '';

	// Now loop through from C to C + W to determine if there is
	// a correct code
	for(i = C; i <= C+W; ++i) {
		args.C = i;
		if(this.getHOTP(args) === P) {
			// We have found a matching code, trigger callback
			// and pass offset
			return { delta: i - C };
		}
	}

	// If we get to here then no codes have matched, return false
	return false;
};


/**
 * Check a One Time Password based on a timer.
 *
 * @return {Object} null if failure, { delta: # } on success
 * delta is the time step difference between the client and the server
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
module.exports.checkTOTP = function(args) {

	var T = args.T || 30;
	var _t = new Date().getTime();

	// Time has been overwritten.
	if(args._t) {
		console.log('#####################################');
		console.log('# NOTE: TOTP TIME VARIABLE HAS BEEN #');
		console.log('# OVERWRITTEN.  THIS SHOULD ONLY BE #');
		console.log('# USED FOR TEST PURPOSES.           #');
		console.log('#####################################');
		_t = args._t;
	}

	// Determine the value of the counter, C
	// This is the number of time steps in seconds since T0
	args.C = Math.floor((_t / 1000) / T);

	return module.exports.checkHOTP(args);
};


/**
 * Generate a counter based One Time Password
 *
 * @return {String} the one time password
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
module.exports.getHOTP = function(args) {
	var key = args.K || '';
	var counter = args.C || 0;

	var p = 6;

	// Create the byte array
	var b = new Buffer(intToBytes(counter));

	var hmac = crypto.createHmac('SHA1', new Buffer(key));

	// Update the HMAC witht he byte array
	var digest = hmac.update(b).digest('hex');

	// Get byte array
	var h = hexToBytes(digest);

	// Truncate
	var offset = h[19] & 0xf;
	var v = (h[offset] & 0x7f) << 24 |
		(h[offset + 1] & 0xff) << 16 |
		(h[offset + 2] & 0xff) << 8  |
		(h[offset + 3] & 0xff);

	v = v + '';

	return v.substr(v.length - p, p);
};


/**
 * Generate a time based One Time Password
 *
 * @return {String} the one time password
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
module.exports.getTOTP = function(args) {
	var K = args.K || '';
	var T = args.T || 30;
	var _t = new Date().getTime();;

	// Time has been overwritten.
	if(args._t) {
		console.log('#####################################');
		console.log('# NOTE: TOTP TIME VARIABLE HAS BEEN #');
		console.log('# OVERWRITTEN.  THIS SHOULD ONLY BE #');
		console.log('# USED FOR TEST PURPOSES.           #');
		console.log('#####################################');
		_t = args._t;
	}

	// Determine the value of the counter, C
	// This is the number of time steps in seconds since T0
	args.C = Math.floor((_t / 1000) / T);

	return this.getHOTP(args);
};

/**
 * convert an integer to a byte array
 * @param {Integer} num
 * @return {Array} bytes
 */
var intToBytes = function(num) {
	var bytes = [];

	for(var i=7 ; i>=0 ; --i) {
		bytes[i] = num & (255);
		num = num >> 8;
	}

	return bytes;
};


/**
 * convert a hex value to a byte array
 * @param {String} hex string of hex to convert to a byte array
 * @return {Array} bytes
 */
var hexToBytes = function(hex) {
	var bytes = [];
	for(var c = 0; c < hex.length; c += 2) {
		bytes.push(parseInt(hex.substr(c, 2), 16));
	}
	return bytes;
};

