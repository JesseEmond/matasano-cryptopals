# Matasano - [Cryptopals](http://cryptopals.com/)

[![Build Status](https://travis-ci.org/JesseEmond/matasano-cryptopals.svg?branch=unittests)](https://travis-ci.org/JesseEmond/matasano-cryptopals)

*Note: most links below are just links to files within this repo for your
convenience.*
## Set 1: Basics
- [x] [1](src/01.py). Convert hex to base64

  Trivial introduction to hex parsing to get you going. I
  [implemented b64decode](src/mybase64.py) out of curiosity.

- [x] [2](src/02.py). Fixed XOR

  Introduction to XOR between strings. Implementation in [xor.py](src/xor.py).

- [x] [3](src/03.py). Single-byte XOR cipher

  Ahh. Crypto! To break it, loop through all 256 possible bytes to find which
  of the keys produces the decrypted text that looks the most like English.

  [frequency.py](src/frequency.py) has code to score how much a string looks
  like English (testing how close to a certain distribution our data is).

  [xor.py](src/xor.py) has code to encrypt/decrypt using a single-byte XOR
  cipher.

- [x] [4](src/04.py). Detect single-character XOR

  Very similar to challenge #3. Break all ciphertexts, pick the one with the
  best "English score".

- [x] [5](src/05.py). Implement repeating-key XOR

  Simply cycle the key when XOR-ing with the plaintext.

- [x] [6](src/06.py). Break repeating-key XOR

  Interesting! Breaking it amounts to breaking a single-byte XOR cipher for the
  1st character of every repeated key, then for the 2nd, the 3rd, etc.

  Guessing the keysize is done by picking the keysize that minimizes the
  normalized [hamming distance](src/distance.py) (`distance / keysize`) between
  "blocks" of the repeated key. This is because we can expect 2 different blocks
  encrypted with the right keysize to have similar bit patterns (e.g. matching
  characters), so minimizing the normalized hamming distance gives us the
  keysize that produces the most similar blocks. We need to normalize because
  e.g. a keysize of 4 would have 2 times as many bits as a keysize of 2.

- [x] [7](src/07.py). AES in ECB mode

  Intro to using the pycrypto API. [aes.py](src/aes.py) has the code that
  handles AES encryption/decryption.

- [x] [8](src/08.py). Detect AES in ECB mode

  ECB mode encrypts the blocks independently. This means that two identical
  blocks of plaintext at different positions will produce the same ciphertext
  block. All that we need to do is find the ciphertext that has the most (or
  any, really) duplicate ciphertext blocks, which is very unlikely with 16 bytes
  of random data.
