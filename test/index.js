var path = require('path');
process.chdir(path.dirname(__filename));
var tap = require('agraddy.test.tap')(__filename);
var fs = require('fs');

var mod = require('../');

var expected = '';

// From DKIM RFC: https://tools.ietf.org/html/rfc6376#appendix-A
// The example email seems to have an extra space that shouldn't be there between the two sentences:
// This From The RFC: We lost the game.  Are you hungry yet?
// Should Be This: We lost the game. Are you hungry yet?
// Simple does not remove any spacing.
// 
// The RFC results for b= was: AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHutKVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV4bmp/YzhwvcubU4=;
// I could not figure out how they reached that result (I'm guessing it might be a spacing issue)



// Based on the go-dkim tests (the RFC example seems to have issues):
// https://github.com/toorop/go-dkim/blob/master/dkim_test.go

actual = mod(fs.readFileSync('./fixtures/message.eml').toString(), {d: 'tmail.io', s: 'test', h: ['From', 'Date', 'MIME-Version', 'Received', 'Received']}, './fixtures/private_key.pem');
expected = '';
expected += 'DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=simple/simple;\r\n';
expected += ' s=test; d=tmail.io; h=from:date:mime-version:received:received;\r\n';
expected += ' bh=ZrMyJ01ZlWHPSzskR7A+4CeBDAd0m8CPny4m15ablao=;\r\n';
expected += ' b=nzkqVMlEBL+6m/1AtlFzGV2tHjvfNwFmz9kUDNqphBNSvguv/8KAdqsVheBudJBDHNPrjr\r\n';
expected += ' +N57+atXBQX/jng2WAlI5wpQb1TlxLfm8b7SyS1Z7WwSOI0MqaLMhIss4QEVsevaTF1d/1Wc\r\n';
expected += ' FzOPxn66nnn+CRKaz553tjIn1GeFQ=\r\n';
//console.log(JSON.stringify(actual));
//console.log(JSON.stringify(expected));
tap.assert.equal(actual, expected, 'simple/simple');





