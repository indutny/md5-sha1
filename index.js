var binding = require('bindings')('md5sha1');

exports.sign = binding.sign;
exports.verify = binding.verify;
exports.Digest = binding.Digest;
