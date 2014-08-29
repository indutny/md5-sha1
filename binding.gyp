{
  "targets": [{
    "target_name": "md5sha1",
    "include_dirs": [
      "src",
      "<(node_root_dir)/deps/openssl/openssl/include",
      "<!(node -e \"require('nan')\")",
    ],
    "sources": [
      "src/md5sha1.cc",
    ],
  }],
}
