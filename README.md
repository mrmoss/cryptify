# Cryptify
Simple zero-dependency, cross-platform, command-line encryption/decryption tool.

Uses AES-512 in CBC mode with PKCS7 padding.

Building is really slow because everything is statically linked. If you want to speed up building, manually compile all the CryptoPP .cpp files in include/cryptopp into .o files and then change all instances of `.cpp` to `.o` on the line starting with `CRYPTOPP_SRC=`.

Pre-compiled binaries are included, but feel free to rebuild them if you don't trust my builds...I won't take any offense...I wouldn't trust any binary from me either...

### Build
```
make
```

### Cross-compile for Windows
```
make WINDOWS=1
```

### Encrypt
```
./cryptify e plain.ext cipher.ext
```

### Decrypt
```
./cryptify d cipher.ext new-plain.ext
```
