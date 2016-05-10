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

- [x] [10. Implement CBC mode](src/10.py)

  [Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29)'s
  image on the matter is enough of a description to implement this. Basically,
  every encrypted block is XORed with the previous block (or the IV if this is
  the first block). The result is that 2 identical plaintext blocks will no
  longer automatically encrypt to the same ciphertext block (compared to ECB).

- [x] [11. An ECB/CBC detection oracle](src/11.py)

  When using ECB, two identical plaintext blocks will encrypt to the same
  ciphertext block.
    
  Therefore, a block that contains duplicate plaintext blocks will contain
  duplicate ciphertext blocks once encrypted.

  Our oracle checks if the ciphertext contains duplicate blocks. If it does, we
  consider the ciphertext to be encrypted using ECB. Otherwise, we consider that
  it used CBC.

- [x] [12. Byte-at-a-time ECB decryption (Simple)](src/12.py)

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

  We repeat the steps up until the point where we reach the last block. Then, we
  will eventually hit the padding.
  
  If the padding happens to be 1 byte, we will successfully find it (this is
  just like bruteforcing a normal byte that just happens to be `0x01`).

  If the padding is anything else, we will first successfully "bruteforce" a
  `0x01` in the plaintext (because we will be padding the plaintext until it is
  only missing a byte, so it will be padded with `0x01`). Then, we will try to
  bruteforce the next byte, but fail. The reason is that the padding will now be
  `[0x02, 0x02]`, while we are trying `[0x01, 0x??]`. Once that happens, we know
  that we have successfully bruteforced the whole plaintext. We can remove our
  undesirable bruteforced `0x01` padding and enjoy reading our plaintext. :tada:

- [x] [13. ECB cut-and-paste](src/13.py)

  Using the same exploitable ECB property as before, we craft multiple messages
  and pick-and-choose the parts that we want.

  Blocks A:
  ```
  email=aaaaaaaaaa (A0)
  adminPPPPPPPPPPP (A1) (P is the padding that will be needed as a final block)
  &uid=10&role=use (A2)
  rPPPPPPPPPPPPPPP (A3)
  ```

  Blocks B:
  ```
  email=aaaaaaaaaa (B0)
  aaa&uid=10&role= (B1)
  userPPPPPPPPPPPP (B2)
  ```

  By crafting the ciphertext `B0 + B1 + A1`, we get:
  ```
  email=aaaaaaaaaa (B0)
  aaa&uid=10&role= (B1)
  adminPPPPPPPPPPP (A1)
  ```

  Which grants us admin access to log in.

- [x] [14. Byte-at-a-time ECB decryption (Harder)](src/14.py)

  This attack is the same as the challenge #12, but with some required initial
  work, offsets and padding to apply.

  We first need to find out how long the prefix is. We do this by generating 2
  blocks of fixed data (e.g. `[0xA] * 32`) and gradually increasing the size of
  the fixed data until we find 2 neighbour duplicate blocks in the ciphertext.
  This indicates that we have fully padded the last block of the prefix and that
  we have produced two blocks of our own input after that. To make sure that we
  don't just have identical blocks because the prefix happened to end with our
  fixed value (therefore fooling us into thinking that we have padded 1 more
  byte than we really have), we can try with 2 different fixed values, e.g.
  `[0] * 32` and `[1] * 32`.
  
  Then, one can use the index where the duplicate blocks begin to find where the
  first block after the prefix starts. With that information, we can find the
  amount of padding that was required to pad the prefix to a multiple of
  blocksize through `len(fixed_data) - 2 * blocksize`. The length of the prefix
  is then `index of first of the duplicates - padding length`.

  With the length of the prefix, we just use our algorithm from challenge #12,
  but prefixing our input with some padding to pad the prefix to a blocksize
  multiple. We also need to offset any index in the produced ciphertext by the
  amount of blocks in the prefix.

- [x] [15. PKCS#7 padding validation](src/15.py)

  We get the last byte of the plaintext as `n` and make sure that the last `n`
  bytes of the plaintext are equal to `n`. If it is not the case, raise an
  exception.

- [x] [16. CBC bitflipping attacks](src/16.py)

  Start out by encrypting a normal token for a block of 16 bytes. This will be
  where we will inject our crafted block. Call this encrypted block
  `current_block`.

  We want to inject `target = ";admin=true;abc="`.

  We know that the plaintext block following our input is:
  `next_plain = ";comment2=%20lik"`.

  When decrypting with CBC, the following is done:
  `next_plain = next_block_pre_xor ^ current_block`

  We can calculate `next_block_pre_xor = next_plain ^ current_block`.

  We want `next_block_pre_xor ^ crafter_block` to yield `target`, so we choose:
  `crafter_block = target ^ next_block_pre_xor`.

  Then, all we need is to swap `current_block` with our `crafter_block` to get
  admin access. The decryption of `current_block` will yield scrambled
  plaintext, but it is not a problem since it only modified `comment1`.

## Set 3: Block & stream crypto

*In progress.*
