# Matasano - [Cryptopals](http://cryptopals.com/)

[![Build Status](https://travis-ci.org/JesseEmond/matasano-cryptopals.svg?branch=unittests)](https://travis-ci.org/JesseEmond/matasano-cryptopals)

*Note: most links below are just links to files within this repo for your
convenience.*
## Set 1: Basics
- [x] [1. Convert hex to base64](src/01.py)

  Trivial introduction to hex parsing to get you going. I
  [implemented b64decode](src/mybase64.py) out of curiosity.

- [x] [2. Fixed XOR](src/02.py)

  Introduction to XOR between strings. Implementation in [xor.py](src/xor.py).

- [x] [3. Single-byte XOR cipher](src/03.py)

  Ahh. Crypto! To break it, loop through all 256 possible bytes to find which
  of the keys produces the decrypted text that looks the most like English.

  [frequency.py](src/frequency.py) has code to score how much a string looks
  like English (testing how close to a certain distribution our data is).

  [xor.py](src/xor.py) has code to encrypt/decrypt using a single-byte XOR
  cipher.

- [x] [4. Detect single-character XOR](src/04.py)

  Very similar to challenge #3. Break all ciphertexts, pick the one with the
  best "English score".

- [x] [5. Implement repeating-key XOR](src/05.py)

  Simply cycle the key when XOR-ing with the plaintext.

- [x] [6. Break repeating-key XOR](src/06.py)

  Interesting! Breaking it amounts to breaking a single-byte XOR cipher for the
  1st character of every repeated key, then for the 2nd, the 3rd, etc.

  Guessing the keysize is done by picking the keysize that minimizes the
  normalized [hamming distance](src/distance.py) (`distance / keysize`) between
  "blocks" of the repeated key. This is because we can expect 2 different blocks
  encrypted with the right keysize to have similar bit patterns (e.g. matching
  characters), so minimizing the normalized hamming distance gives us the
  keysize that produces the most similar blocks. We need to normalize because
  e.g. a keysize of 4 would have 2 times as many bits as a keysize of 2.

- [x] [7. AES in ECB mode](src/07.py)

  Intro to using the pycrypto API. [aes.py](src/aes.py) has the code that
  handles AES encryption/decryption.

- [x] [8. Detect AES in ECB mode](src/08.py)

  ECB mode encrypts the blocks independently. This means that two identical
  blocks of plaintext at different positions will produce the same ciphertext
  block. All that we need to do is find the ciphertext that has the most (or
  any, really) duplicate ciphertext blocks, which is very unlikely with 16 bytes
  of otherwise random data.

## Set 2: Block crypto

- [x] [9. Implement PKCS#7 padding](src/09.py)

  We pad the plaintext so that it has a length that is a multiple of the
  blocksize (e.g. 16). If it already is, we add a full block of padding. The
  padding byte to use is equal to the length of the padding.

  Examples:

  ```
  pad('0123456789') = '0123456789' + '666666'
  pad('') = '\x10' * 16
  ```

- [x] [10. Implement CBC mode](src/.py)

  [Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29)'s
  image on the matter is enough of a description to implement this. Basically,
  every encrypted block is XORed with the previous block (or the IV if this is
  the first block). The result is that 2 identical plaintext blocks will no
  longer automatically encrypt to the same ciphertext block (compared to ECB).

- [x] [11. An ECB/CBC detection oracle](src/.py)

  When using ECB, two identical plaintext blocks will encrypt to the same
  ciphertext block.
    
  Therefore, a block that contains duplicate plaintext blocks will contain
  duplicate ciphertext blocks once encrypted.

  Our oracle checks if the ciphertext contains duplicate blocks. If it does, we
  consider the ciphertext to be encrypted using ECB. Otherwise, we consider that
  it used CBC.

- [x] [12. Byte-at-a-time ECB decryption (Simple)](src/.py)

  Detecting the blocksize is relatively easy. We start by noting
  `len(ciphertext)`. We continue adding prefix bytes until we notice a change in
  `len(ciphertext)`. When that happens, it means that we have crossed a block
  boundary and we know the blocksize to be `len(after) - len(start)`.

  Using the ECB property that we exploited earlier (identical plaintext blocks
  encrypt to identical ciphertext blocks), we can bruteforce individual bytes
  at the end of blocks.

  For example, assume that we want to bruteforce the (unknown) plaintext:
  `hello this is a test`.

  At first, we want to isolate the first character (`h`, but we don't know that
  yet) at the end of a block, through a prefix of `A`s. Like this:

  ```
  AAAAAAAAAAAAAAAh
  ```

  We get the encrypted result of this (call this `C0`). We can try all
  possible bytes that could follow our prefix, like the following:

  ```
  AAAAAAAAAAAAAAAa
  AAAAAAAAAAAAAAAb
  AAAAAAAAAAAAAAAc
  ...
  ```

  Eventually, we will get an encrypted block that will match `C0`, and thus
  we will know the first byte of our plaintext.

  We can bruteforce the second byte (`e`) similarly. We start by getting `C1` by
  encrypting:

  ```
  AAAAAAAAAAAAAAhe
  ```

  Then by trying all possible bytes:

  ```
  AAAAAAAAAAAAAAha
  AAAAAAAAAAAAAAhb
  AAAAAAAAAAAAAAhc
  ...
  ```

  Until we find a block that encrypts to `C1`. And so on, for all bytes in the
  first block.

  For the following blocks, the idea is the same, but a little more thought must
  be put into *where* we get our `Ci` and what should be put as a prefix.

  The block `Ci` is merely the index of the block we already are at with the
  *next* byte that we want to bruteforce. The reason is quite simple: with our
  padding, we will only be pushing that byte at the end of its current block,
  not produce a next block.

  The padding only has to be enough to put the next bruteforced byte at the end
  of a block. When bruteforcing, however, the bytes before the tried byte must
  be the last 15 (blocksize - 1) known bytes, to fit `Ci`.

  This is all clearer through an example:

  ```
  plaintext:    hello this is a (...unknown....)
                |---block 0----||---block 1----|
  bruteforcing: t (unknown yet)

  We will pad with As:
  padded:       AAAAAAAAAAAAAAAhello this is a t(...unknown....)
                |---block 0----||---block 1----||---block 2----|
  Ci = block 1

  Bruteforce tries: ello this is a a
                    ello this is a b
                    ello this is a c
                    ...
  ```

  We repeat the steps up until the point we reach the last block. At this point,
  we will eventually hit the padding.
  
  If the padding happens to be 1 byte, we will successfully find it (this is
  just like bruteforcing the last byte, that just happens to be `0x01`).

  If the padding is anything else, we will first successfully "bruteforce" a
  `0x01` in the plaintext (because we will be padding the plaintext until it is
  only missing a byte, so it will be padded with `0x01`). Then, we will try to
  bruteforce the next byte, but fail. The reason is that the padding will now be
  `[0x02, 0x02]`, while we are trying `[0x01, 0x??]`. Once that happens, we know
  that we have successfully bruteforced the whole plaintext. :tada:

- [x] [13. ECB cut-and-paste](src/.py)

- [x] [14. Byte-at-a-time ECB decryption (Harder)](src/.py)

- [x] [15. PKCS#7 padding validation](src/.py)

- [x] [16. CBC bitflipping attacks](src/.py)

*Pending descriptions.*

## Set 3: Block & stream crypto

*In progress.*
