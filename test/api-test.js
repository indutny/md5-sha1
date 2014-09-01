var assert = require('assert');
var ms = require('../');
var crypto = require('crypto');

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

  it('should digest', function() {
    var d = new ms.Digest();
    var out = new Buffer(36);
    d.update(new Buffer('hello world')).digest(out);

    var md5 = crypto.createHash('md5').update('hello world').digest('hex');
    var sha1 = crypto.createHash('sha1').update('hello world').digest('hex');
    assert.equal(out.toString('hex'), md5 + sha1);
  });
});
