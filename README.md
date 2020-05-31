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

  We want `next_block_pre_xor ^ crafted_block` to yield `target`, so we choose:
  `crafted_block = target ^ next_block_pre_xor`.

  Then, all we need is to swap `current_block` with our `crafted_block` to get
  admin access. The decryption of `current_block` will yield scrambled
  plaintext, but it is not a problem since it only modifies `comment1`.

## Set 3: Block & stream crypto

- [x] [17. The CBC padding oracle](src/17.py)

  If we have an oracle that tells us if the padding on a ciphertext is valid or
  not, we are able to recover the plaintext.

  Keep in mind that decryption happens like this:
  ```
  block_pre_xor xxxxxxxxxxxxxxxx ^
     prev_block pppppppppppppppp =
      plaintext tttttttttttttttt
  ```

  We can play with the `prev_block` to search for a byte that results in valid
  padding:
  ```
  block_pre_xor xxxxxxxxxxxxxxx? ^
     prev_block pppppppppppppppB = (we bruteforce 'B')
      plaintext ttttttttttttttt1
  ```

  Once we have the `prev_block` byte that gives valid padding, we can deduce
  `pre_xor` byte `?`.

  Once we know the last `N` bytes of the `pre_xor`, we can use that information
  to craft the ending of the padding in just the right way to bruteforce the
  `N+1`th byte (starting from the right).

  With all the `pre_xor` bytes recovered from a block, we can XOR them with
  out real `prev_block` to find the plaintext.

  However, we must keep the following tricky thing in mind:

  The last block (and other plaintext blocks, if we're unlucky) can produce two
  valid `pre_xor` bytes, instead of just one:
  E.g. block `...55555`
  We'll find these 2 valid `pre_xor` bytes:
  - the one that produces `...55551`
  - the one that produces `...55555`

  When this happens, we can just alter the 2nd last byte to produce junk, so
  that *only* the padding ending with a `1` will pass:
  E.g. changing `5` to `4`
  - the `pre_xor` that produces `...55541` passes
  - the `pre_xor` that produces `...55545` **does not**

- [x] [18. Implement CTR, the stream cipher mode](src/18.py)

  There isn't much to say here... We generate a keystream with:
  
  `aes(key, nonce + counter)`
  
  Where `nonce` and `counter` are 64-bits integers encoded in little-endian and
  `counter` is the amount of blocks generated so far.

- [x] [19. Break fixed-nonce CTR mode using substitutions](src/19.py)

  We reuse our `english_test` function and pick the key that has the best
  score. In some cases, we pick a key that is not as good as some others
  because we notice (by analysis of the plaintexts obtained) that the key
  is not the right one.

  As mentioned by the challenge description, this is a bit manual indeed.

- [x] [20. Break fixed-nonce CTR statistically](src/20.py)

  Very similar to the previous challenge, except that we can heavily reuse code
  that we've written before.


- [x] [21. Implement the MT19937 Mersenne Twister RNG](src/21.py)

  This task surprisingly took a little longer than just copying Wikipedia's
  pseudocode. I spent some time wondering why Python's random would yield
  different numbers (and state!) from me, so I investigated.
  
  I compared with C++'s std::mt19937, which yielded the same results as
  me. I couldn't find posts complaining about this specifically so I took a
  look at [CPython's source](https://hg.python.org/cpython/file/3.4/Lib/random.py).
  It turns out that the
  [underlying C module](https://hg.python.org/cpython/file/tip/Modules/_randommodule.c)
  seeds in a different way from what we see on Wikipedia. It assumes that
  the seed could be greater than 32-bits and just uses all of the bits of
  the seed in a different procedure. The result: it ends up with a
  different state from us.
  
  Just to make sure I looked at how `numpy`'s random and it does generate
  the same state as us when seeding. Therefore, the tests for this one use
  values that I extracted with C++'s implementation.

- [x] [22. Crack an MT19937 seed](src/22.py)

  Pretty straightforward. Bruteforce all sensible seeds (a couple of seconds
  in the past) and pick the one that matches.

- [x] [23. Clone an MT19937 RNG from its output](src/23.py)

  The state is directly coming from the next output, so it is really easy to
  recover the next state from a given output.

  Essentially, we need to look at `624` transformations of the state to fully
  recover the MT state:

  ```
  state = [untemper(output) for output in outputs[-624:]]
  ```

  Our `untemper` needs to reverse the right and left shift operations.

  Let's look at a case with 8-bits: `y = 10101010`

  If we're shifting right by 3 bits, we'll do the following:

  ```
  10101010 y
  00010101 y >> 3
  10111111 y ^ y >> 3
  ```
  
  We notice that the first 3 bits of the result will match the first 3 bits of
  the original `y`. Then, those original 3 bits will be used (once shifted) to
  xor with the original `y`. By using the known first 3 bits, we can recover
  the next 3 bits of `y` by doing this:

  ```
  10111111 y ^ y >> 3
  00010100 known_bits >> 3
  10101011 (y ^ y >> 3) ^ (known_bits >> 3)
  ```

  We can then recover the whole `y` this way. The left shift is very similar,
  but we `&` with a constant before xoring.

- [x] [24. Create the MT19937 stream cipher and break it](src/24.py)

  This challenge was very similar to challenge 22. Basically, we bruteforce the
  seed space to find one that gives an expected decryption/token.


## Set 4: Stream crypto and randomness

- [x] [25. Break "random access read/write" AES CTR](src/25.py)

  Here we're doing a terrible mistake: we are reusing our keystream on a
  different plaintext. Solution? We provide `00000000...` and it gets directly
  xored with the keystream (yielding the keystream). We xor that with the
  original ciphertext and we get the secret back!

- [x] [26. CTR bitflipping](src/26.py)

  This one is really straightforward. We know the plaintext, so we can find the
  keystream and use it to encrypt our token the way that we want.

- [x] [27. Recover the key from CBC with IV=Key](src/27.py)

  When we split the obtained ciphertext in 3 blocks:
  ```
  C1, C2, C3
  ```

  We can then produce a ciphertext in the following way:
  ```
  C1, 0, C1
  ```

  and capture the produced plaintext from the error message.

  This means that `P1` is the result of `KEY ^ P3` (since `P3` is unchanged by
  xoring with `0`). We can recover the key through: 
  `P1 ^ P3 = (P3 ^ KEY) ^ P3 = KEY`.

- [x] [28. Implement a SHA-1 keyed MAC](src/28.py)

  Wrote implementation based on Wikipedia's pseudocode (inspired by existing
  implementations).

- [x] [29. Break a SHA-1 keyed MAC using length extension](src/29.py)

  The final SHA-1 hash is just the `h` values directly encoded to bytes (after
  doing the pre-processing of appending the `glue` for a given length and
  processing all the chunks in sequence).

  Thus, if we know that `SHA-1(prefix)` gives a certain digest, we know that
  the `h` states after processing `prefix + glue(len(prefix))` will be
  `digest`. We can inject `glue` after our prefix to know what `h` will be
  at that point, without even knowing `prefix` (apart from its length).

  If we know the length, we just need to initialize a SHA-1 instance to have
  `h = unpacked_digest`, and `msg_len = len(prefix) + len(glue(len(prefix)))`.
  If we `update` that SHA-1, we can then inject whatever we want.

  In practice, since we don't know the length of the password (pseudocode):
  ```
  # Assuming we have 'digest = H(secret + msg)' and don't know 'secret'.
  for secret_len in range(128):  # some upper-bound
    h = unpack(digest)
    prefix_len = secret_len + len(msg)
    prefix_glue = glue(prefix_len)
    msg_len = prefix_len + len(prefix_glue)
    sha = Sha1(h=h, msg_len=msg_len)
    new_mac = sha.update(b';admin=true')
    new_message = msg + prefix_glue + b';admin=true'
    if try_message(new_message, new_mac):
      print("Bingo! ", new_message, " ", new_digest)
  ```

- [x] [30. Break an MD4 keyed MAC using length extension](src/30.py)

  After refactoring the `sha1` implementation to a general `merkle_damgard`
  [structure](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction),
  I then reimplemented `md4` using similar primitives (only implementing
  `process_chunk`). The logic for length-extension attacks could then be made
  generally available in `merkle_damgard`, which I simply used for MD4 and it
  worked out of the box.

- [x] [31. Implement and break HMAC-SHA1 with an artificial timing leak](src/31.py)

  If we're bruteforcing the `ith` byte of the HMAC, we measure, for each byte,
  how long it takes to evaluate a file with `hmac[i] = byte`. We do so `round`
  times to get some distribution. Simply taking the median of each byte times
  and taking the byte with the maximum median seemed sufficient here.

  Note that this takes a _while_ to run, so I added (optional) logic to only
  add a `sleep` for the current byte. This is cheating because in reality each
  sleep adds more noise (that's part of the challenge), but we also want Travis
  to successfully run on it, in reasonable time. :)

- [x] [32. Break HMAC-SHA1 with a slightly less artificial timing leak](src/32.py)

  Took the same implementation and reduced sleep to `0.1ms`. Note that I'm
  still doing this all without going through HTTP, which is EZ mode...
  Attacking this in practice seems difficult. Good experience. :)


## Set 5: Diffie-Hellman and friends

- [x] [33. Implement Diffie-Hellman](src/33.py)

  Pretty easy in python, especially with `pow(a, b, p)`. Noteworthy: to
  implement `modexp`, you can do so with exponentiation-by-squaring, with
  modulos on the way.

- [x] [34. Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection](src/34.py)

  By giving `p` instead of `A` to the server, it ends up computing
  `s = A^b mod p`, which gives:
  ```
  s = A^b mod p
    = p^b mod p
    = 0 mod p
  ```
  So we then know the secret key. The same goes for when we return `p` instead
  of `p`.

- [x] [35. Implement DH with negotiated groups, and break with malicious "g" parameters](src/35.py)

  Three scenarios.

  For `g=1`, we have:
  ```
  s = g^a^b mod p
    = 1^a^b mod p
    = 1 mod p
  ```

  For `g=p`, we have:
  ```
  s = g^a^b mod p
    = p^a^b mod p
    = 0 mod p
  ```
  This is the same as challenge 35. Note that it would be the same for `g=0`.

  For `g=p-1` (note `p-1 mod p = -1 mod p`), we have:
  ```
  s = g^a^b mod p
    = (p-1)^a^b mod p
    = (-1)^a^b mod p
    = { -1 mod p   if a*b is odd
      { 1 mod p    if a*b is even
  ```
  We could already do a lot by just restricting to two possibilities, but we
  can narrow it down by finding if `a` and `b` are individually odd/even:
   - If `A == 1 mod p`, `a` is even. If it is `p-1 mod p`, `a` is odd.
   - If `B == 1 mod p`, `b` is even. If it is `p-1 mod p`, `b` is odd.
  
  Then, `a*b` will be odd iff `a` *and* `b` are odd.

- [ ] [36. Implement Secure Remote Password (SRP)](src/36.py)

*TODO: challenge*