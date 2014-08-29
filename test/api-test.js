var assert = require('assert');
var ms = require('../');

var key = require('fs').readFileSync(__dirname + '/keys/key.pem');

describe('md5sha1', function() {
  it('should sign/verify data', function() {
    var right = new Buffer(36);
    var wrong = new Buffer(36);
    for (var i = 0; i < right.length; i++) {
      right[i] = (3 + i * 11) & 0xff;
      wrong[i] = (3 + i * 17) & 0xff;
    }

    var s = ms.sign(right, key);
    assert(ms.verify(right, s, key));
    assert(!ms.verify(wrong, s, key));
  });
});
