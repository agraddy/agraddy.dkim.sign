var mod = {};

var parse = require('agraddy.parse.email');
var crypto = require('crypto');
var fs = require('fs');

var WRAP_AT = 65;
var CRLF = '\r\n';
var TAB = ' ';

mod = function(eml, options, private_key_file_location) {
	var body = eml.slice(eml.indexOf('\r\n\r\n') + 4).replace(/(\r?\n)*$/, '\r\n');
	var output = '';
	var temp = '';
	var i;
	var private_key = fs.readFileSync(private_key_file_location);
	var headers = '';
	var email = parse(eml);

	output = 'DKIM-Signature: ';
	if(options.v) {
		output += 'v=' + options.v + ';';
	} else {
		output += 'v=1;';
	}
	if(options.a) {
		output += checkFolding(output, 'a=' + options.a + ';');
	} else {
		output += checkFolding(output, 'a=rsa-sha256;');
	}
	if(options.q) {
		output += checkFolding(output, 'q=' + options.q + ';');
	} else {
		output += checkFolding(output, 'q=dns/txt;');
	}
	if(options.c) {
		output += checkFolding(output, 'c=' + options.c + ';');
	} else {
		output += checkFolding(output, 'c=simple/simple;');
	}
	output += checkFolding(output, 's=' + options.s + ';');
	output += checkFolding(output, 'd=' + options.d + ';');
	temp = 'h=';
	for(i = 0; i < options.h.length; i++) {
		if(i == 0) {
			temp += options.h[i].toLowerCase();
		} else {
			temp += ':' + options.h[i].toLowerCase();
		}
	}
	temp += ';';
	output += checkFolding(output, temp);

	if(options.i) {
		output += checkFolding(output, 'i=' + options.i + ';');
	}

	output += CRLF;
	temp = TAB + 'bh=';
	temp += crypto.createHash('sha256').update(body).digest('base64');
	temp += ';';
	output += checkFolding(output, temp, 65);

	headers = getHeaders(output + CRLF + TAB + 'b=', options.h, email.extraRawHeaders);

	output += CRLF;
	temp = TAB + 'b=';
	temp += crypto.createSign('RSA-SHA256').update(headers).sign(private_key, 'base64');
	console.log(temp);
	output += checkFolding(output, temp, 73);

	output += CRLF;

	return output;
}

function checkFolding(base, item, hard) {
	var temp;
	var output;
	var wrap_at = WRAP_AT;
	if(hard) {
		wrap_at = hard;
		temp = item;
		output = '';

		if(temp.length <= wrap_at) {
			output = temp;
			return output;
		} else {
			while(temp.length > wrap_at) {
				output += temp.slice(0, wrap_at) + CRLF;
				temp = TAB + temp.slice(wrap_at);
			}
			output += temp;
			return output;
		}
	} else {
		temp = base.split(CRLF).pop() + ' ' + item;
		if(temp.length > wrap_at) {
			return CRLF + TAB + item;
		} else {
			return ' ' + item;
		}
	}
}

function getHeaders(signature, items, raw) {
	var already_matched = [];
	var output = '';
	var found = false;
	var i;
	var j;

	raw.reverse();

	for(i = 0; i < items.length; i++) {
		found = false;
		for(j = 0; j < raw.length; j++) {
			if(already_matched.indexOf(j) == -1 && items[i].toLowerCase() == raw[j].toLowerCase()) {
				found = true;
				output += raw[j] + ':' + raw[j-1] + CRLF;
				already_matched.push(j);
				break;
			}
		}
		if(!found) {
			output += items[i] + ':' + CRLF;
		}
	}

	output += signature;

	return output;
}

module.exports = mod;
