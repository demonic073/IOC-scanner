{
  "targets": [
    {
      "target_name": "native",
      "sources": ["src/native.cc"],
      "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"]
    }
  ]
}
