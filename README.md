
# WebAssembly AES Encrypt Sample

```
emcc -o wasm.js aes.c -s NO_EXIT_RUNTIME=1 -s "EXPORTED_FUNCTIONS=['_aes_128_encrypt', '_aes_256_encrypt', '_aes_128_decrypt', '_aes_256_decrypt']" -O2
```
