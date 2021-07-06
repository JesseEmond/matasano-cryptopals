# Matasano - [Cryptopals](http://cryptopals.com/)

[![Build Status](https://travis-ci.com/JesseEmond/matasano-cryptopals.svg?branch=unittests)](https://travis-ci.org/JesseEmond/matasano-cryptopals)

*Note: most links below are just links to files within this repo for your
convenience.*

## Set 1: Basics
- [x] [1. Convert hex to base64](src/set_1/01.py)

  Trivial introduction to hex parsing to get you going. I
  [implemented b64decode](src/mybase64.py) out of curiosity.

- [x] [2. Fixed XOR](src/set_1/02.py)

  Introduction to XOR between strings. Implementation in [xor.py](src/xor.py).

- [x] [3. Single-byte XOR cipher](src/set_1/03.py)

  Ahh. Crypto! To break it, loop through all 256 possible bytes to find which
  of the keys produces the decrypted text that looks the most like English.

  [frequency.py](src/frequency.py) has code to score how much a string looks
  like English (testing how close to a certain distribution our data is).

  [xor.py](src/xor.py) has code to encrypt/decrypt using a single-byte XOR
  cipher.

- [x] [4. Detect single-character XOR](src/set_1/04.py)

  Very similar to challenge #3. Break all ciphertexts, pick the one with the
  best "English score".

- [x] [5. Implement repeating-key XOR](src/set_1/05.py)

  Simply cycle the key when XOR-ing with the plaintext.

- [x] [6. Break repeating-key XOR](src/set_1/06.py)

  Interesting! Breaking it amounts to breaking a single-byte XOR cipher for the
  1st character of every repeated key, then for the 2nd, the 3rd, etc.

  Guessing the keysize is done by picking the keysize that minimizes the
  normalized [hamming distance](src/distance.py) (`distance / keysize`) between
  "blocks" of the repeated key. This is because we can expect 2 different blocks
  encrypted with the right keysize to have similar bit patterns (e.g. matching
  characters), so minimizing the normalized hamming distance gives us the
  keysize that produces the most similar blocks. We need to normalize because
  e.g. a keysize of 4 would have 2 times as many bits as a keysize of 2.

- [x] [7. AES in ECB mode](src/set_1/07.py)

  Intro to using the pycrypto API. [aes.py](src/aes.py) has the code that
  handles AES encryption/decryption.

- [x] [8. Detect AES in ECB mode](src/set_1/08.py)

  ECB mode encrypts the blocks independently. This means that two identical
  blocks of plaintext at different positions will produce the same ciphertext
  block. All that we need to do is find the ciphertext that has the most (or
  any, really) duplicate ciphertext blocks, which is very unlikely with 16 bytes
  of otherwise random data.

## Set 2: Block crypto

- [x] [9. Implement PKCS#7 padding](src/set_2/09.py)

  We pad the plaintext so that it has a length that is a multiple of the
  blocksize (e.g. 16). If it already is, we add a full block of padding. The
  padding byte to use is equal to the length of the padding.

  Examples:

  ```
  pad('0123456789') = '0123456789' + '666666'
  pad('') = '\x10' * 16
  ```

- [x] [10. Implement CBC mode](src/set_2/10.py)

  [Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29)'s
  image on the matter is enough of a description to implement this. Basically,
  every encrypted block is XORed with the previous block (or the IV if this is
  the first block). The result is that 2 identical plaintext blocks will no
  longer automatically encrypt to the same ciphertext block (compared to ECB).

- [x] [11. An ECB/CBC detection oracle](src/set_2/11.py)

  When using ECB, two identical plaintext blocks will encrypt to the same
  ciphertext block.
  
  Therefore, a block that contains duplicate plaintext blocks will contain
  duplicate ciphertext blocks once encrypted.

  Our oracle checks if the ciphertext contains duplicate blocks. If it does, we
  consider the ciphertext to be encrypted using ECB. Otherwise, we consider that
  it used CBC.

- [x] [12. Byte-at-a-time ECB decryption (Simple)](src/set_2/12.py)

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

- [x] [13. ECB cut-and-paste](src/set_2/13.py)

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

- [x] [14. Byte-at-a-time ECB decryption (Harder)](src/set_2/14.py)

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

- [x] [15. PKCS#7 padding validation](src/set_2/15.py)

  We get the last byte of the plaintext as `n` and make sure that the last `n`
  bytes of the plaintext are equal to `n`. If it is not the case, raise an
  exception.

- [x] [16. CBC bitflipping attacks](src/set_2/16.py)

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

- [x] [17. The CBC padding oracle](src/set_3/17.py)

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

- [x] [18. Implement CTR, the stream cipher mode](src/set_3/18.py)

  There isn't much to say here... We generate a keystream with:
  
  `aes(key, nonce + counter)`
  
  Where `nonce` and `counter` are 64-bits integers encoded in little-endian and
  `counter` is the amount of blocks generated so far.

- [x] [19. Break fixed-nonce CTR mode using substitutions](src/set_3/19.py)

  We reuse our `english_test` function and pick the key that has the best
  score. In some cases, we pick a key that is not as good as some others
  because we notice (by analysis of the plaintexts obtained) that the key
  is not the right one.

  As mentioned by the challenge description, this is a bit manual indeed.

- [x] [20. Break fixed-nonce CTR statistically](src/set_3/20.py)

  Very similar to the previous challenge, except that we can heavily reuse code
  that we've written before.


- [x] [21. Implement the MT19937 Mersenne Twister RNG](src/set_3/21.py)

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
  values that I extracted with C++'s implementation.¨

- [x] [22. Crack an MT19937 seed](src/set_3/22.py)

  Pretty straightforward. Bruteforce all sensible seeds (a couple of seconds
  in the past) and pick the one that matches.

- [x] [23. Clone an MT19937 RNG from its output](src/set_3/23.py)

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

- [x] [24. Create the MT19937 stream cipher and break it](src/set_3/24.py)

  This challenge was very similar to challenge 22. Basically, we bruteforce the
  seed space to find one that gives an expected decryption/token.


## Set 4: Stream crypto and randomness

- [x] [25. Break "random access read/write" AES CTR](src/set_4/25.py)

  Here we're doing a terrible mistake: we are reusing our keystream on a
  different plaintext. Solution? We provide `00000000...` and it gets directly
  xored with the keystream (yielding the keystream). We xor that with the
  original ciphertext and we get the secret back!

- [x] [26. CTR bitflipping](src/set_4/26.py)

  This one is really straightforward. We know the plaintext, so we can find the
  keystream and use it to encrypt our token the way that we want.

- [x] [27. Recover the key from CBC with IV=Key](src/set_4/27.py)

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

- [x] [28. Implement a SHA-1 keyed MAC](src/set_4/28.py)

  Wrote implementation based on Wikipedia's pseudocode (inspired by existing
  implementations).

- [x] [29. Break a SHA-1 keyed MAC using length extension](src/set_4/29.py)

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
  ```python
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

- [x] [30. Break an MD4 keyed MAC using length extension](src/set_4/30.py)

  After refactoring the `sha1` implementation to a general `merkle_damgard`
  [structure](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction),
  I then reimplemented `md4` using similar primitives (only implementing
  `process_chunk`). The logic for length-extension attacks could then be made
  generally available in `merkle_damgard`, which I simply used for MD4 and it
  worked out of the box.

- [x] [31. Implement and break HMAC-SHA1 with an artificial timing leak](src/set_4/31.py)

  If we're bruteforcing the `ith` byte of the HMAC, we measure, for each byte,
  how long it takes to evaluate a file with `hmac[i] = byte`. We do so `round`
  times to get some distribution. Simply taking the median of each byte times
  and taking the byte with the maximum median seemed sufficient here.

  Note that this takes a _while_ to run, so I added (optional) logic to only
  add a `sleep` for the current byte. This is cheating because in reality each
  sleep adds more noise (that's part of the challenge), but we also want Travis
  to successfully run on it, in reasonable time. :)

- [x] [32. Break HMAC-SHA1 with a slightly less artificial timing leak](src/set_4/32.py)

  Took the same implementation and reduced sleep to `0.1ms`. Note that I'm
  still doing this all without going through HTTP, which is EZ mode...
  Attacking this in practice seems difficult. Good experience. :)


## Set 5: Diffie-Hellman and friends

- [x] [33. Implement Diffie-Hellman](src/set_5/33.py)

  Pretty easy in python, especially with `pow(a, b, p)`. Noteworthy: to
  implement `modexp`, you can do so with exponentiation-by-squaring, with
  modulos on the way.

- [x] [34. Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection](src/set_5/34.py)

  By giving `p` instead of `A` to the server, it ends up computing
  `s = A^b mod p`, which gives:
  ```
  s = A^b mod p
    = p^b mod p
    = 0 mod p
  ```
  So we then know the secret key. The same goes for when we return `p` instead
  of `p`.

- [x] [35. Implement DH with negotiated groups, and break with malicious "g" parameters](src/set_5/35.py)

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

- [x] [36. Implement Secure Remote Password (SRP)](src/set_5/36.py)

  Implement the protocol under [srp.py](src/srp.py).

- [x] [37. Break SRP with a zero key](src/set_5/37.py)

  By passing `A = 0`, the server will then do:

  ```
  s = (A * v^u)^b mod N
    = (0 * v^u)^b mod N
    =         0^b mod N
    =           0 mod N
  ```

  We get the same result by passing `A = cN`, where `c` is an integer.

- [x] [38. Offline dictionary attack on simplified SRP](src/set_5/38.py)

  This challenge gives a bit of clarity into why SRP does `B = kv + g^b mod n`.
  If it didn't, like in the challenge, then we can do an offline brute-force of
  `s`, without knowing the password verifier `v`. We do (pseudocode):

  ```python
  # Known from eaves-dropping an example: salt, A, u, hmac
  # Forced via MITM: b
  for password in dictionary:
    x = H(salt + password)
    v = pow(g, x, n)
    s = pow(A * pow(v, u, n), b, n)
    if hmac(s, salt) == hmac: print("FOUND ", password)
  ```
  
  So why does `B = kv + g^b mod n` help then?

  First, we can't do the same attack because the HMAC that we'll receive is no
  longer computed directly from `g^b mod n` on the client side, it is computed
  on `g^b - kv mod n` (because it assumes that we added it to our `B`).
  
  [This page](http://srp.stanford.edu/ndss.html) has relevant information about
  this attack and the protocol. First, why is it safe to add `kv` to a public
  parameter? We pick `g` such that it is a primitive root of `GF(n)`, which
  means that we can get any integer `a` such that `1 < a < n` via
  `a = g^k mod n` (they're distributed uniformly). In that way, doing
  `g^b + kv mod n` does not leak `kv`, because an eaves-dropper doesn't know
  `g^b`. Alright, but why not something else?
  
  So we want to mix knowledge about the password (`v`) into `B` to protect
  against offline bruteforce, but we have to be careful about it. If we were to
  do e.g. `v * g^b mod n` (multiply), we could also attack it:

  ```python
  x = H(salt + password)
  v = pow(g, x, n)
  # Assuming we sent `B = g^b mod n` instead of `B = v * g^b mod n` during mitm.
  # Client would do: `s = pow(B * invmod(v), a + u * x, n)`.
  # s =     (B / v)^(a+ux) mod n
  #   = (g^b / g^x)^(a+ux) mod n
  #   =   (g^(b-x))^(a+ux) mod n
  #   =   (g^(a+ux))^(b-x) mod n
  #   =       (Av^u)^(b-x) mod n
  s = pow(A * pow(v, u, n), (b - x) % n, n)
  ```

  Note that we pretend that we are doing `v * g^b mod n` instead of
  `kv * g^b mod n`, because otherwise we end up with a tricky term that we don't
  know how to work with (we don't know `a+ux`):
  `(Av^u)^(b-x) * k^(-a - ux) mod n`

  To show that this attack would work if we did `v * g^b mod n`, I also
  implemented that behind a boolean option to confirm that the math made sense.

  If we were to use xor instead, we could do a "partition attack" by eliminating
  possible passwords (if `B = v xor g^b`, then a guess v' is invalid if
  `B > n`). If `g` is not a primitive root of `GF(n)`, we can also do a
  partition attack.

  So modular addition (in the real SRP) appears to be a reasonable choice here.

- [x] [39. Implement RSA](src/set_5/39.py)

  We implement `egcd` and `modinv` in [mod.py](src/mod.py).

  We also implement `is_prime` in [prime.py](src/prime.py) and `random_prime`.

  To implement primality checking for big numbers (think >1024 bits), we
  use a probabilistic method, Miller-Rabin.

  First, probabilistic? It functions by testing for properties that are always
  true for primer numbers, but only sometimes for composite numbers (with a test
  that has a chance to filter out any possible composite number). For
  Miller-Rabin, the probability of tagging a composite number as "probably
  prime" is 1/4 per round. By doing 50 rounds, the probability of having a
  composite number pass all 50 rounds (we call this a "strong pseudoprime") is
  1/4^50, or ~= 10^(-30). To put this in perspective,
  [this link](https://stackoverflow.com/a/4160517) compares that probability to
  the probability of a cosmic ray flipping the 1-bit result of a deterministic
  test. In other words, probabilistic is fine.

  The Miller-Rabin test works by starting from Fermat's little theorem:
  For `n` prime, `a^(n-1) = 1 (mod n)`. We can rewrite `a^(n-1)` as
  `a^(2^s * d)`, where `d` is odd (factor out powers of 2).

  If `n` is prime, `(mod n)` is a field and `x^2 = 1 (mod n)` has only two
  roots: `x = 1 (mod n)` and `x = -1 (mod n)`. To prove that there are only two
  roots, we can use
  [Euclid's lemma](https://en.wikipedia.org/wiki/Euclid%27s_lemma):
  `x^2 - 1 = (x + 1)(x - 1) = 0 (mod n)`. Then it follows that since `n` divides
  `(x + 1)(x - 1)`, it divides one of the factors.

  So, from `a^(n-1) = 1 (mod n)`, if `n` is prime, we can take square roots as
  long as the result is 1, and we should get -1 eventually (or reach `a^d = 1`).

  In other words, a **prime number** will have:

  ```
  a^d = 1 (mod n)
    or 
  a^(2^r * d) = -1 (mod n), for some 0 <= r < s
  ```

  From the contrapositive, we can "witness" that `n` is **composite** if:

  ```
  a^d != 1 (mod n)
    and
  a^(2^r * d) != -1 (mod n), for all 0 <= r < s
  ```

  It turns out that for a random `a`, the probability of `n` being a strong
  pseudoprime is <= `1/4` (see
  [this](http://www.mat.uniroma2.it/~schoof/millerrabinpom.pdf)). We can repeat
  this for multiple random bases `a`.

  As for the RSA implementation, it's under [rsa.py](src/rsa.py).

- [x] [40. Implement an E=3 RSA Broadcast attack](src/set_5/40.py)

  For this challenge, we'll make use of the
  ["Chinese Remainder Theorem"](https://en.wikipedia.org/wiki/Chinese_remainder_theorem).

  As a side-note, I was interested in the origin of the name (i.e. why wasn't it
  named after the person that found the theorem, like we've done for Euler,
  Fermat, and countless others). On
  [mathoverflow](https://mathoverflow.net/q/11951), there is some mention of the
  difficulties in knowing exactly where this problem first appeared, but a good
  name for the theorem might be the
  [Sun Zi Theorem](http://people.math.harvard.edu/~knill/crt/lib/Kangsheng.pdf)
  (this reference also contains interesting history around the problem and its
  origins). One of my favorite quotes while looking this up, from the last
  paragraph of that last reference:

  > Euler, Lagrange and Gauss presented their achievements in indeterminate
  > analysis in the 18th century [...] at that time Europeans considered their
  > results in mathematics unique and very significant. They did not know that
  > they had been completely solved in the East at least several hundred years
  > earlier.

  ... There's something there. :)

  Let's look at the Sun Zi theorem and
  [solution](https://math-physics-problems.wikia.org/wiki/Sun_Zi%27s_Algorithm):

  ```
  From the congruences:
    N = r_1  (mod m_1)
    N = r_2  (mod m_2)
    ...
    N = r_n  (mod m_n)

  where m_1, m_2, ..., m_n mutually coprime.

  From known r_i, m_i (1 <= i <= n), what is N?
  ```

  The solution:

  ```
  Let M = m_1 * m_2 * ... * m_n and M_i = M / m_i
  Note that gcd(M_i, m_i) = 1.
  Note that M_i = 0  (mod m_j) for i != j.

  Let s_1, s_2, ..., s_n be the modular inverses of M_1, M_2, ..., M_n,
  respectively.
  I.e., s_i * M_i = 1  (mod m_i)
  Note that s_i * r_i * M_i = r_i  (mod m_i).

  Since M_i = 0  (mod m_j) for i != j, then r_i * M_i * s_i = 0  (mod m_j).

  Then, the sum \sum_{i=1}^n {r_i * M_i * s_i} satisfies all the initial
  congruences. This is because we'll get 0 terms for indices != i, with only the
  term r_i left for a given modulus m_i.

  Any number equal to the sum (mod M) will be a solution to the system of
  congruences.
  ```

  The code lies under [mod.py](src/mod.py).

  In our case, we have the following examples:
  ```
  plaintext^3 = ciphertext_1  (mod N_1)
  plaintext^3 = ciphertext_2  (mod N_2)
  plaintext^3 = ciphertext_3  (mod N_3)

  With gcd(N_i, N_j) != 1 for i != j. If that were not the case, we could
  trivially factor p, q for one of them and recover d and plaintext this way.
  ```

  With the Sun Zi theorem, we can recover `plaintext^3`, and compute the cube
  root.

  To compute the integer cube root, I found the following links to be super
  helpful to understand how we can apply Newton's Method and prove that the
  number of iterations is `O(lg lg n)`. Note that we could have done a dumb
  algorithm where we do a binary search over `[1, n/2]`, and that would have
  been `O(lg n)` iterations, but it's interesting to see how to do it in a
  smarter way!

  Links: [isqrt](https://www.akalin.com/computing-isqrt)
  [iroot](https://www.akalin.com/computing-iroot)

  The code lies under [roots.py](src/roots.py).

  Note that all of this is not necessary if `m` is small enough to not even wrap
  in the first place (`m**3 < N`, e.g. `bits(m) * e < N`). In that case, we can
  directly take the cube root. To force `m**e` to wrap around `N`, we can add
  static padding to `m` to make it close to `bits(N)`, but then it is vulnerable
  to the attack documented here.


## Set 6: RSA and DSA

- [x] [41. Implement unpadded message recovery oracle](src/set_6/41.py)

  This one is fairly straightforward. We captured `c = p^e mod N` and want to
  recover `p`. By getting the decrypted `c' = (s^e mod N) * c mod N`, we can
  recover `p`:

  ```
  c' = (s^e mod N) * c  mod N
     = s^e * p^e        mod N
     = (s * p)^e        mod N

  p' = decrypt(c')
     = s * p            mod N

  => p = s^(-1) * p'    mod N
  ```

- [x] [42. Bleichenbacher's e=3 RSA Attack](src/set_6/42.py)

  This attack comes from the
  [notes](https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/)
  of Bleichenbacher.

  PKCS v1.5 ([RFC3447](https://tools.ietf.org/html/rfc3447)) encodes a
  particular digest as:

  ```
  00 01 FF ... FF 00 <digest_info>

  digest_info is the following ASN.1 (DER-encoded):
  SEQUENCE {
    SEQUENCE {
      OBJECT-IDENTIFIER (hash algorithm oid),
      NULL
    },
    OCTET-STRING (hash digest)
  }
  ```

  This is implemented in [pkcs1_v1_5.py](src/pkcs1_v1_5.py). A subset of ASN.1
  DER is implemented under [asn1.py](src/asn1.py).

  The vulnerability in this challenge comes from extracting the `digest_info`
  essentially via a regex `\x00\x01\xff+\x00(.*)`, without ensuring that there
  are enough `ff`s to cover the entire space (i.e. without making sure that
  `digest_info` is right-justified). Because ASN.1 encodes the length of the
  digest, this will accept a signature that encrypts as:

  ```
  00 01 FF .. FF 00 <digest_info> <garbage>
  ```

  Because signature validation implies doing `signature^3` and checking the
  digest, if we are able to find a value that cubes to something of the form
  above, we can forge a signature.

  We can do so like this:

  ```
  digest = hashlib.sha1(b"hi mom").digest()
  digest_info = pkcs1_v1_5.sha1_digest_info(digest)
  target_digest_info = pkcs1_v1_5.signing_pad(digest_info, total_len=1024//8)
  forged_padded = b"\x00\x01\xFF\x00" + target_digest_info
  forged_padded += b"\xff" * (1024 - len(forged_padded))
  forged_signature = iroot(int.from_bytes(forged_padded, "big"), 3)
  ```

  ... And it works! Note that I couldn't get this to work at first with SHA-256,
  because there's not much space to find a valid cube root with a SHA-256 digest
  and 1024 bits total size.

  Out of curiosity, I also implemented the "by hand" approach from 
  [Bleichenbacher](https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/)
  , with some personal notes to understand why it works:

  ```
  Let's work with a 3072-bit key (more space to find a root).
  Size of 00<digest_info> for SHA-1 is 36 bytes (288 bits).
  We'll be producing 00 01 FF ... FF 00 <digest_info> <garbage>.

  Reminder that (A-B)^3 = A^3 - 3(A^2)B + 3A(B^2) - B^3.
  So if we can formulate our target as something that looks like that, we can
  just use (A-B) as our forged signature.

  Following Bleichenbacher's notes, we define:
  D := 00 <digest_info>
  N := 2^288 - D  (note 288 comes from size in bits of <digest_info>)
  We assume that N = 0 (mod 3) (we'll have a division by 3 later).
  We choose to place D 2072 bits over from the right (numerically, D * 2^2072).
  Our padded version will look like:
  00 01 FF ... FF <D> <GARBAGE>

  To represent our "prefix" (00 01 FF ... FF) numerically (followed by zeros
  since it's just the prefix), we can do:
  2^(3072 - 15) - 2^(2072 + 288) = 2^3057 - 2^2360
    => '15' is the number of 0 bits in 00 01
    => '2072 + 288' is the number of bits for <D> <GARBAGE>
  By doing one minus the other, we get the numerical value for having a series
  of 1s in the positions where we want 01 FF ... FF.

  Our padded numerical value is thus:
  2^3057 - 2^2360 + D*2^2072 + garbage
  This can be rewritten as:
  2^3057 - N*2^2072 + garbage
  The cube root of this is then 2^1019 - (N*2^34/3). That's our forged
  signature.

  To check that this works, let's cube it:
  (2^1019 - (N * 2^34 / 3))^3  (note this is of the form (A-B)^3)
  Reminder that (A-B)^3 = A^3 - 3(A^2)B + 3A(B^2) - B^3.
  = (2^1019)^3 - 3*(2^1019)^2*(N*2^34/3) + 3*2^1019*(N*2^34/3)^2 - (N*2^34/3)^3
  = 2^3057 - (3*2^2038*N*2^34/3) + (3*2^1019*N^2*2^68/9) - (N^3*2^102/27)
  = 2^3057 - N*2^2072 + N^2*2^1087/3 - N^3*2^102/27
  This fits the pattern:
  2^3057 - N*2^2072 + garbage
  So it works!
  ```


  Now, there is a more interesting variant of this attack that we can look at:
  What if we have a validator that checks that the ASN.1 decoding has no
  left-over (i.e. the hash is right-justified), but not that the padding is a
  sequence of `FF`s? In other words, what if the validator checks:

  ```
  ^00 01 [^00]+ 00 <digest_info>$
  ```

  This attack broke python-rsa, as decribed in this
  [blog post](https://blog.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/).

  We know how to find `x` such that `x^3` has a given prefix, but what about a
  given suffix? The blog post above gives an iterative algorithm if `suffix` is
  odd, motivated by the observation that flipping the Nth bit (from the right)
  in `x` causes the Nth bit in `x^3` to flip, while leaving the bits 0 to N-1
  unaffected. We can thus start from bit 0 and iteratively flip bits (as needed)
  of `x` to find our target suffix. Once we have found the prefix and suffix of
  our signature, we try random filler bytes in-between until we find a cube that
  doesn't have `00`s in the padding area.

  This got me curious about how to solve the cube suffix generally for even
  suffixes and how could we show that this algorithm works for any odd number,
  so I wrote up about this in a separate
  [repository](https://github.com/JesseEmond/theoretical/tree/master/cube-suffix).
  The tl;dr is that we can state this problem as:

  ```
  Solve for x in x^3 = suffix (mod 2^bitlen(suffix))
    or, equivalently,
  Find roots of f(x) = x^3 - suffix (mod 2^bitlen(suffix))
    or, more generally,
  Solve for x in f(x) = x^3 - suffix = 0 (mod p^k), for prime 'p'.
  ```

  We find that we can make use of
  [Hensel's Lemma](https://en.wikipedia.org/wiki/Hensel%27s_lemma) to "lift" a
  solution `(mod p^k)` to `(mod p^(k+1))` when `f'(x) != 0 (mod p)`. That
  solution is unique and can be computed directly. We find that in our case, an
  odd suffix implies `f'(x) != 0 (mod 2)`, which explains why we can always lift
  a solution to the next power of 2 (the N+1th bit). For even suffixes, we need
  a recursive approach, described in more details in the linked repository, but
  summarized here:

  ```
  hensel_lift(f, p, k):
    if k = 1: return [x for x in range(p) if f(x) = 0 (mod p)]

    prev_roots := hensel_lift(f, p, k-1)
    new_roots  := []
    for r in prev_roots:
      if f'(r) != 0 (mod p):                     # Hensel's Lemma (simple root)
        s := (r - f(r) * f'(r)^(-1))) (mod p^k)  # Note f'(r)^(-1) is in (mod p)
        new_roots.append(s)
      elif f(r) = 0 (mod p^k):                   # If r+tp^(k-1) are all solutions
        for t in range(p):
          s := (r + tp^(k-1)) (mod p^k)
          new_roots.append(s)
    return new_roots
  ```

- [x] [43. DSA key recovery from nonce](src/set_6/43.py)

  Code for DSA lies under [dsa.py](src/dsa.py). We implement parameter
  generation following [FIPS 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) documentation.

  We implement the key recovery as described in the challenge, derived here:

  ```
  s = k^(-1) (h + xr) mod q
  => sk = h + xr mod q
  => sk - h = xr mod q
  => x = (sk - h) / r mod q
  ```

  Then, we can test `x` by checking if `g^x mod p` equals `y`.

  A lot of subtle bugs because of how we manually handle `mod n` operations, as
  opposed to using a construct like `Mod` in Sage.

  Regarding DSA's correctness (i.e. why does signature validation work), if we follow the notes on Wikipedia:

  ```
  Note that g = h^((p-1)/q)         mod p.
  This means that g^q = h^(p-1) = 1 mod p  (Fermat's little theorem)
  With this and g > 0, q is prime => g must have order q.
  
  The signer computes:
  s = k^(-1) (H(m) + xr) mod q
  Which we can rearrange:
  k = H(m)s^(-1) + xrs^(-1) mod q
    = H(m)w + xrw           mod q
  Now, since g has order q and k = H(m)w + xrw mod q:
  g^k = g^(H(m)w) g^(xrw) mod p
      = g^(H(m)w) y^(rw)  mod p
      = g^u1 y^u2         mod p
      
  And when verifying:
  r = (g^k mod p)       mod q
    = (g^u1 y^u2 mod p) mod q
    = v
  ```

  Regarding the FIPS 186-4 parameter generation procedure, it seems a bit cryptic at first. I found [this answer](https://stackoverflow.com/a/21273368/395386) helpful in understanding why it is done this way -- it is mainly to be able to verify the generation through a seed. The computation shifts and adds multiple hash outputs to generate a pseudorandom sequence, then subtracts a remainder to have it be `p = 1 mod 2q` (IIUC so that `q` divides `p-1`, and so that it is an odd number). Alternatively, we could have generated a sequence of random bits, set the top and bottom bits to `1`, and done a similar trick to make `p = 1 mod q`.

- [x] [44. DSA nonce recovery from repeated nonce](src/set_6/44.py)

  The formula comes from:

  ```
  Assuming k was reused for (m1, s1) and (m2, s2):
  (all mod q)
  s1 = (h1 + x * r1) / k
  s2 = (h2 + x * r2) / k
  r1 = r2, since r = ((g^k) mod p) mod q
  
  Then:
  s1 - s2
  => k (s1 - s2) = h1 + xr - (h2 + xr)
  => k (s1 - s2) = h1 - h2
  => k = (h1 - h2) / (s1 - s2)
  ```

  This also means that we just need to find a duplicate `r` in the signatures to know that `k` was reused. Then, we recover `k` with the formula above, and recover the private key with the attack from the previous challenge.

- [x] [45. DSA parameter tampering](src/set_6/45.py)

  For this one, we assume that `y` was generated initially using some `g`, and that we overwrite the `g` used in signature/verification. Otherwise, `y` would be computed using our tampered `g` and be trivial to deduce.

  For `g = 0`:

  ```
  Assume we are signing "hello".
  The signer does:
  	r = (g^k mod p) mod q
  	s = k^(-1) (H(m) + xr) mod q
  So r=0.
  And s has not dependence on the private key anymore!
  	s = k^(-1) H(m) mod q
  When verifying:
  	v = (g^u1 * y^u2 mod p) mod q
  g^u1 will give 0, so v will always be 0, so will allow any s we give, for any message.
  E.g. (0, s) is valid for "hello", (0, s) is valid for "hi", (0, 424242) is valid for "hi".
  ```

  We had to make changes to sign/verify to pass a flag that allows 0s to avoid checks, which means that this is somewhat dependent on the implementation not making checks on `r`  or `s`.

  For `g = p + 1 = 1 mod p`:

  ```
  Assume we are signing "hello".
  The signer does:
  	r = (g^k mod p) mod q
  	s = k^(-1) (H(m) + xr) mod q
  So r = 1.
  	s = k^(-1) (H(m) + xr) mod q
  	=> sk = H(m) + x mod q
  Still some dependence on unknowns x and k.
  
  Note that verifying (r, s) would fail, because the g used for generating y
  is not the same as what we are passing now, in our setup.
  
  When verifying:
  	v = (g^u1 * y^u2 mod p) mod q
  	  = (y^u2 mod p) mod q
  	u2 = r/s mod q
  If we choose some fixed z value and compute:
  	r = (y^z mod p) mod q
  	s = r/z mod q
  So in our setup:
  	u2 = r/s mod q
  	   = r / (r/z) mod q
  	   = z mod q
  Verification will do:
  	v = (y^u2 mod p) mod q
  	  = (y^z mod p) mod q
  	  = r mod q
  So we can craft a signature that looks somewhat normal and will pass verification!
  E.g.
  	z = 2**32 -5  # Arbitrary
  	r = Zq(pow(y, z, p))
  	s = r / z
  Then we can sign any string.
  ```

- [x] [46. RSA parity oracle](src/set_6/46.py)

  When we manipulate our ciphertext `c = p^e mod n`, we mess with the plaintext `p`:

  ```
  2^e * c mod n
  = 2^e * p^e mod n
  = (2p)^e mod n
  i.e. ciphertext for 2p
  ```

  Through that, knowing that `n` is odd, being the product of two odd primes, we know that an even number going over the modulus once will produce an odd number `2p - n = even - odd = odd`. We can start with a range for our plaintext value of `[0, n)` and do `log2(n)` steps to narrow it down to our exact plaintext value.

  So, if we look at a small example:

  ```python
  p, q = 3, 5
  n = p * q  # 15
  phi = (p-1) * (q-1)
  e = 3
  d = pow(e, -1, phi)  # Nice Python 3.8 feature :)
  pt = 2  # what we want to recover
  ct = pow(pt, e, n)  # what we're given, 8
  oracle = lambda c: pow(c, d, n) % 2 == 0
  
  # 4 iterations, since n.bit_length() == 4
  # 0 <= pt < 15
  # Double our plaintext through our ciphertext
  ct = (ct * pow(2, e, n)) % n  # 2pt, encrypted
  print(oracle(ct))  # True, did not wrap. I.e. 2pt < 15 (that is, 4 < 15)
  
  # 0 <= pt < 15/2
  ct = (ct * pow(2, e, n)) % n  # 4pt, encrypted
  print(oracle(ct))  # True, did not wrap. I.e. 4pt < 15 (that is, 8 < 15)
  
  # 0 <= p < 15/4
  ct = (ct * pow(2, e, n)) % n  # 8pt, encrypted
  print(oracle(ct))  # False, wrapped. I.e. 8pt >= 15 (that is, 16 >= 15)
  
  # 15/8 <= pt < 15/4
  ct = (ct * pow(2, e, n)) % n  # 2(8pt-n), encrypted
  print(oracle(ct))  # True, did not wrap. I.e. 2(8pt-n) < 15 (that is, 2 < 15)
  
  16pt - 2n < n
  16pt < 3n
  
  # We end up with 15/8 <= pt < 3*15/16, i.e. 1.875 <= pt < 2.8125, i.e. pt = 2
  ```

  One thing that was surprising to me was that when I tried to implement it similar to a regular binary search, I was able to decrypt all the plaintext except for the last byte. E.g. with this approach:

  ```python
  lower, upper = 0, n
  for _ in range(n.bit_length()):
      c = (c * 2**e) % n
      mid = (upper + lower) // 2
      if parity_oracle_fn(c):
          upper = mid
      else:
          lower = mid
      print(byteops.int_to_bytes(upper))  # !! NOTE: Does not recover the last byte !!
  ```

  I would get an incorrect last byte (e.g. non-printable ascii). and not always the same.

  Looking around, I found that a github project called _Crypton_ had the [same problem](https://github.com/ashutosh1206/Crypton/blob/30c090647c110cf76c068e4b1fdfd158032b44a6/RSA-encryption/Attack-LSBit-Oracle/lsbitoracle.py#L27). Looking around for other solutions to this challenge, I found [this repository](https://github.com/akalin/cryptopals-python3/blob/master/challenge46.py) that solved the problem by keeping track of numerators/denominators instead of using divisions in the loop. This makes sense, we can end up with bounds like `3/4 N`, and truncating multiple times along the way will create slight inaccuracies. So we can instead implement the attack like so (available in [rsa.py](src/rsa.py)):

  ```python
  lower, upper = 0, 1
  denominator = 1
  for _ in range(n.bit_length()):
  	c = (c * 2**e) % n
      delta = upper - lower
      lower *= 2
      upper *= 2
      denominator *= 2
      if parity_oracle_fn(c):
          upper -= delta
      else:
          lower += delta
      plaintext = n * upper // denominator
      print(byteops.int_to_bytes(plaintext))
  ```

  While we're at it, also sent a [PR](https://github.com/ashutosh1206/Crypton/pull/9) to _Crypton_.


- [x] [47. Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)](src/set_6/47.py)

- [x] [48. Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)](src/set_6/48.py)

  Had to take a look at other implementations of this attack to iron out some mis-readings on my part of the formulas and exact meaning of the union of intervals in step 3, but this works out to a relatively concise algorithm! We add PKCS #1 encryption padding to [pkcs1_v1_5.py](src/pkcs1_v1_5.py) and change our RSA decryption to make use of the [CRT optimization](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm), because this does involve running sometimes millions of oracle decryptions. We also implement a `ceil_div` function, following [this nice trick](https://stackoverflow.com/a/17511341/395386). Even with a 256-bit modulus, I would still end up often getting more than one interval, so had to implement all steps to really test things out. Challenge 48 is then the same problem, but with a larger modulus.
  
  Following [the paper](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf), we end up with something along the lines of:
  
  ```python
  def oracle_s(s):
      """Test out an `s` value through our PKCS#1 oracle."""
      return oracle((c * pow(s, e, n)) % n)
  
  # Step 1: Blinding. Nothing to do for us, we have a known 'c'.
  B = 2**(8 * (k - 2))
  M = {(2*B, 3*B-1)}
  
  # Step 2: Search for PKCS-conforming messages.
  # Step 2.a: Starting the search.
  s = next(s1 for s1 in range(ceil_div(n, 3*B), n) if oracle_s(s1))
  
  while len(M) > 1 or next(iter(M))[0] != next(iter(M))[1]:
      if len(M) > 1:
          # Step 2.b: Searching with more than one interval left.
          s = next(si for si in range(s+1, n) if oracle_s(si))
      else:
          # Step 2.c: Searching with one interval left.
          a, b = next(iter(M))
          r = ceil_div(2 * (b*s - 2*B), n)
          found = False
          while not found:
              s_min = ceil_div(2*B + r*n, b)
              s_max = ceil_div(3*B + r*n, a)
              for new_s in range(s_min, s_max):
                  if oracle_s(new_s):
                      found = True
                      break
              r += 1
          s = new_s
      # Step 3: Narrowing the set of solutions.
      new_M = set()
      for a, b in M:
          r_min = ceil_div(a*s-3*B+1, n)
          r_max = ceil_div(b*s-2*B, n)
          for r in range(r_min, r_max+1):
              interval_min = max(a, ceil_div(2*B+r*n, s))
              interval_max = min(b, (3*B-1+r*n) // s)
              if interval_min <= interval_max:
                  new_M.add((interval_min, interval_max))
      M = new_M
  a, _ = next(iter(M))
  m = a  # because s0 == 1
  ```
  
  I found [this resource](http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html) invaluable to understand the steps of the attack and possible follow-up improvements to lower the median number of oracle calls required to decrypt.

## Set 7: Hashes

- [x] [49. CBC-MAC Message Forgery](src/set_7/49.py)

  It took me some time to understand the architecture described in the challenge, originally I was trying with a single server and was confused how the key management was done. I later realized that I should treat one server as the "web server", that will sign transactions after authenticating that the user owns the account, and an "API" that will apply transactions with valid MACs. Both servers share a secret key. We are in a position where we can MITM between the two servers.

  For the first variant (controlled IV), we can manipulate the first block by doing the same bitflips to the IV as we are doing to the plaintext. We then make a transaction against ourselves (e.g. `from=2&to=2&amount=1`), manipulate it to make it come from Alice, then repeat each time, increasing the amount to our current balance (so that the server accepts our initial useful transaction by seeing that we have the funds).

  ```python
  # Our transaction: from=2&to=2&amount=1234...
  #  (block 0)       ||||||||||||||||
  # We want:         from=0&to=2&amount=1234
  msg, iv, mac = parse(my_transaction)
  block0 = msg[:16]
  target = b"from=0&to=2&amou"
  xors = xor_bytes(block0, target)
  iv = xor_bytes(iv, xors)
  payload = target + msg[16:] + iv + mac
  ```

  For the second variant (fixed IV), we can append a full message, as long as it's fine for our first appended block to get scrambled. This is because we are in a similar situation where we know the "IV" at a certain stage during decryption (i.e. Alice's MAC is the decryption of the last block of her padded message), we can do similar to the previous attack. but now using a plaintext to make sure the xored value comes off to the same first block as our appended message. With this, we know our final MAC will be the same as the MAC of our appended message. Now, we intercept a message from Alice, create a message with two transactions to ourselves (to have things align well), append our message to Alice's to have her also send cash to us, and repeat until we're rich.

  ```python
  alice_msg, alice_mac = parse(intercepted)
  # We are sending: from=2&tx_list=2:0;2:1000
  #  (block 0)      ||||||||||||||||
  # Appending to Alice with a scrambled first block (after xors to match fixed IV), we'll get:
  #    <Alice's msg><scrambled data>:0;2:1000
  # We're assuming a lenient server that will accept the scrambled data and ignore that one.
  my_msg, my_mac = parse(my_transaction)
  block0 = my_msg[:16]
  # Note: the fixed IV is 0.
  block0_fixed = xor_bytes(block0, alice_mac)  # block0_fixed will give block0 when xored in CBC.
  # Note: alice_mac was computed based on pad(alice_msg) behind-the-scenes! Do the same here.
  payload = pad(alice_msg) + block0_fixed + my_msg[16:] + my_mac
  ```

  Remembering to pad Alice's message prior to appending our message turns out to be important.

  

  In a way, the nature of our protocol allowed us to attack it in such a way. Ideas for improvements:

  - (not sufficient) More stringent validation of format, deny all transactions if we fail to parse one in the list.
  - User-derived keys as opposed to a fixed key.
  - Include the length of the message at the start, as part of the protocol (note: at the end is not sufficient).
  - Reading [on Wikipedia](https://en.wikipedia.org/wiki/CBC-MAC), we also learn about another approach: re-encrypt the last block, using a separate key.

- [x] [50. Hashing with CBC-MAC](src/set_7/50.py)

  All that we care about to produce `target_hash` is that our last block's pre-encryption value looks like `decrypt_block(key, target_hash)`. With the known key, we can craft a Javascript message with strategic middle bytes to push our last block's pre-encryption bytes to fit:

  ```python
  assert cbc_mac_hash(b"alert('MZA who was that?');\n") == target_hash
  target_pre = aes_decrypt_block(key, target_hash)  # What we want to dupe the hash.
  
  payload = b"alert('Ayo, the Wu is back!');/*"  # Open comments, we'll add noise to get there.
  payload += b"A" * (-len(payload) % 16)  # Pad to block size for convenience
  
  # Figure out what `iv` will be at this stage in CBC (the last decrypted block)
  iv = b"\x00" * 16
  for block in get_blocks(payload):
      block = xor_bytes(iv, block)
      iv = aes_encrypt_block(key, block)
  
  # We want our last block to look like:
  # <...>*/\x01  (close comment & \x01 for implicit CBC padding)
  ending = b"BBBBBBBBBBBBB*/"  # Leave room for \x01 byte
  ending_padded = ending + b"\x01"
  
  # Craft middle bytes to produce our target_pre bytes at the end.
  middle_encrypted = xor_bytes(ending_padded, target_pre)
  middle = aes_decrypt_block(key, middle_encrypted)
  middle = xor_bytes(iv, middle)
  
  crafted += middle + ending
  assert cbc_mac_hash(crafted) == target_hash
  ```

- [x] [51. Compression Ratio Side-Channel Attacks](src/set_7/51.py)

  The first case is relatively simple -- try every char, remember the ones that produced the lower oracle length (so more compressed). Here it's possible that we have more than one candidate, since the compressions operates at the bit level and we are getting byte-level information, it can happen that our guess doesn't cross a byte boundary. To overcome this, when we have multiple candidates, we try each of them as if they were now part of our known prefix and see which one gave us the shorter next-step of our next iteration. This is a bit wasteful in terms of oracle calls, but gives a relatively concise algorithm where we can reuse a function for "give me all next-letter candidates with this prefix".

  The block encryption case is trickier, because due to block-padding during encryption, we need to be at a block boundary to get informative oracle lengths. I approached this one by a simple retry approach of the previous algorithm: if we failed to fully deduce the next byte (even after trying each candidates at the next stage), retry with extra padding before our known prefix. We add a random byte to make our padding less likely to be compressible. Eventually, this will lead our next byte to fall on a block boundary, where we can do our previous attack successfully. Again, this is wasteful in terms of oracle calls (we could maybe figure out where we are in a block, then reusing that information to pad for the next bytes to guess), but keeps the code simple while still being functional.

  ```python
  def decrypt_compression(oracle_fn, known_prefix, done_fn, block_based=False):
      decrypted = bytearray()
      padding = b""  # For block-based decryption.
      while not done_fn(decrypted):
          prefix = padding + known_prefix + decrypted
          candidates, _ = next_char_candidates(oracle_fn, prefix)
          if len(candidates) > 1:
              # Didn't cross a byte boundary, perhaps. Try each one on the next step
              # to narrow down our candidates to one.
              candidates = narrow_candidates(candidates, oracle_fn, prefix)
              if len(candidates) > 1:
                  assert block_based, "For byte-based decryption, this should have worked."
                  # Perhaps we didn't cross a block boundary. Try again, with extra
                  # random padding.
                  rand_byte = random_number(below=128)  # ascii char
                  padding += byte([rand_byte])
                  continue
          decrypted.append(ord(candidates[0]))
      return bytes(decrypted)
  
  def next_char_candidates(oracle_fn, prefix):
      alphabet = string.printable
      letters_lens = {letter: oracle_fn(prefix + letter.encode("ascii")) for letter in alphabet}
      best_len = min(letters_lens.values())
      candidates = [letter for letter, len_ in letters_lens.items()
                    if len_ == best_len]
      return candidates, best_len
  
  def narrow_candidates(candidates, oracle_fn, prefix):
      next_candidates = {
          letter: next_char_candidates(oracle_fn, prefix + letter.encode("ascii"))
          for letter in candidates
      }
      best_len = min(oracle_len for _, (_, oracle_len) in next_candidates.items())
      best_candidates = [letter for letter, (_, oracle_len) in next_candidates.items()
                         if oracle_len == best_len]
      return best_candidates
  
  
  # Usage:
  ends_in_newline = lambda text: text.endswith(b"\n")
  print(decrypt_compression(oracle_stream_cipher, known_prefix=b"sessionid=",
                            done_fn=ends_in_newline))
  print(decrypt_compression(oracle_block_cipher, known_prefix=b"sessionid=",
                            done_fn=ends_in_newline, block_based=True))
  ```

- [x] [52. Iterated Hash Function Multicollisions](src/set_7/52.py)

  We can write a generic implementation of collision generation directly as part of our [merkle_damgard.py](src/merkle_damgard.py) class. In particular, we can turn this in to a `CollisionGenerator`class to make it easier to do the second part, where we have a chance of not finding a `g` collision with `b2/2` `f` collisions. By having it as a class that remembers its state, we can just do the extra work of generating twice as many collisions by finding one more block, as opposed to starting over with `n+1`. This ends up looking like:

  ```python
  class CollisionGenerator:
      """Helper class to iteratively generator more collisions of a MD hash."""
      def __init__(self, hash_cls: merkle_damgard.Hash):
          self.hash_cls = hash_cls
          # Sequential pairs of blocks that give a collision under 'hash_cls'.
          # With 'n' pairs of colliding blocks, we can generate 2**n collisions.
          self.colliding_blocks = []
          self.current_state = hash_cls()._state  # start from default internal state
          self.n = 0  # Number of steps that we ran (2**n collisions).
          self.num_calls = 0  # Total calls made to the hash function.
      
      def next(self):
          """Finds the next colliding block, doubling our total collisions."""
          state_to_block = {}
          while True:
              block = random_helper.random_bytes(self.hash_cls.BLOCK_SIZE)
              state = tuple(self.current_state)
              # Note: we could do a full hash from the total sequence of blocks so far,
              # but it's equivalent to just focus on the current's block processing.
              state = self.hash_cls.process_chunk(block, state)
              self.num_calls += 1
              if state in state_to_block and block != state_to_block[state]:
                  # New collision!
                  self.colliding_blocks.append((block, state_to_block[state]))
                  break
              state_to_block[state] = block
          self.current_state = state
          self.n += 1
          
      def num_collisions(self):
          return 2**self.n
      
      def all_collisions(self):
          return (b"".join(blocks) for blocks in itertools.product(*self.colliding_blocks))
  ```

  I chose to implement `f`'s compression function as an AES call using `h` (16-bits) left-padded with zeros as key and 2-byte blocks to be left-padded with zeros, using the first 2 bytes of the output as our output. `g` was implemented similarly, but with `h` twice as big, taking 4 bytes from the output. The collision finding code for `h ` then looks like:

  ```python
  b2 = 32
  f_generator = merkle_damgard.CollisionGenerator(CheapHash)
  for _ in range(b2//2):
      f_generator.next()
  done = False
  while not done:
      g_hash_to_block = {}
      for x in f_generator.all_collisions():
          g_hash = g(x)
          if g_hash in g_hash_to_block and x != g_hash_to_block[g_hash]:
              y = g_hash_to_block[g_hash]
              done = True
              break
          g_hash_to_block[g_hash] = x
      if not done:
          f_generator.next()
  assert f(x) == f(y)
  assert g(x) == g(y)
  assert h(x) == h(y)
  ```

- [x] [53. Kelsey and Schneier's Expandable Messages](src/set_7/53.py)

  Building expandable messages gives us `k` choices, each path leading to the same final state -- either we use a single block, or `2**i+1` blocks (`i` goes over `[0, k]`). What this allows us to do is to generate any message with length `n` blocks, as long as `k <= n <= k + 2**k - 1`. The way we do this is first by noticing that each step we either add `1`, or `1` plus a power of `2`. That means that if we look at the binary representation of `n - k`, it tells us whether we should take the longer block (to get `+2**i`) or a shorter one (to leave that bit as 0).

  We can build a helper class to create expandable messages:

  ```python
  class ExpandableMessages:
  def __init__(self, hash_cls: merkle_damgard.Hash, k: int):
      self.k = k
      self.hash_cls = hash_cls
      self.short_blocks = []  # When we want +1
      self.long_blocks = []  # When we want +2**i+1
      
      state = hash_cls().state()  # Initial state
      for i in reversed(range(k)):
          long = bytearray()
          long_state = state
          for _ in range(2**i):  # The 2**i blocks before our 2**i+1th
              block = random_helper.random_bytes(self.hash_cls.BLOCK_SIZE)
              long_state = hash_cls.process_chunk(block, long_state)
              long.extend(block)
          state, short_block, long_block = self._block_collision(state, long_state)
          
          long.extend(long_block)
          self.short_blocks.append(short_block)
          self.long_blocks.append(bytes(long))
      self.final_state = state
  
  def _block_collision(self, left_state, right_state):
      """Returns (colliding_state, left_block, right_block)."""
      left_seen = {}
      right_seen = {}
      while True:
          block = random_helper.random_bytes(self.hash_cls.BLOCK_SIZE)
          left_hash = self.hash_cls.process_chunk(block, left_state)
          if left_hash in right_seen:
              return left_hash, block, right_seen[left_hash]
          left_seen[left_hash] = block
          right_hash = self.hash_cls.process_chunk(block, right_state)
          if right_hash in left_seen:
              return right_hash, left_seen[right_hash], block
          right_seen[right_hash] = block
  
  def expand_to(self, n):
      """Generate n blocks (in [k, k+2**k-1]) that produce 'final_state'."""
      assert self.k <= n <= self.k + 2**self.k - 1
      message = bytearray()
      binary = bin(n - self.k)[2:].zfill(self.k)
      for i, bit in enumerate(binary):
          if bit == "0":
              message.extend(self.short_blocks[i])
          else:
              message.extend(self.long_blocks[i])
      return bytes(message)
  ```

  With this, we can create a 2nd preimage collision for a message that has `2**k` blocks:

  ```python
  def second_preimage_collision(hash_cls, msg):
      """Find m s.t. H(m) = H(msg), |msg| must have 2**k blocks, int k."""
      k = round(math.log2(len(msg) / hash_cls.BLOCK_SIZE))
      assert 2**k * hash_cls.BLOCK_SIZE == len(msg)
      expandable = ExpandableMessages(hash_cls, k)
      intermediate = {}
      state = hash_cls().state()  # Initial state.
      for i in range(2**k):
          block = msg[i * hash_cls.BLOCK_SIZE:(i+1) * hash_cls.BLOCK_SIZE]
          if i > k:  # Need at least k+1 for prefix+bridge.
          	intermediate[state] = i
          state = hash_cls.process_chunk(block, state)
      bridge_state = None
      while bridge_state not in intermediate:
          bridge = random_helper.random_bytes(hash_cls.BLOCK_SIZE)
          bridge_state = hash_cls.process_chunk(bridge, expandable.final_state)
      suffix_idx = intermediate[bridge_state]
      suffix = msg[suffix_idx * hash_cls.BLOCK_SIZE:]
      prefix_len = len(msg) - len(bridge) - len(suffix)
      assert prefix_len % hash_cls.BLOCK_SIZE == 0
      prefix = expandable.expand_to(prefix_len // hash_cls.BLOCK_SIZE)
      collision = prefix + bridge + suffix
      assert len(collision) == len(msg)
      return collision
  ```

  It is not obvious to me how one would deal with messages that don't have exactly `2**k` blocks, but this is a very neat attack nonetheless.

- [x] [54. Kelsey and Kohno's Nostradamus Attack](src/set_7/54.py)

  This one is relatively straightforward -- we create a funnel starting from `2**k` states, colliding pairs at each stage to eventually get a single final state.

  We can create a helper class that handles all of it:

  ```python
  class NostradamusGenerator:
      def __init__(self, hash_cls, k, msg_len):
          """Precompute 2**k states to collide into known final digest, for |msg|."""
          assert msg_len % hash_cls.BLOCK_SIZE == 0
          self.k = k
          self.msg_len = msg_len
          self.funnel = []  # k elements, each a map from state to block
          self.hash_cls = hash_cls
          states = set()
          while len(states) < 2**k:
              block = hash_cls.random_block()  # Helper function, like above.
              states.add(hash_cls.process_chunk(block, hash_cls.init_state()))
          states = list(states)
          for _ in range(k):
              new_states = []
              state_to_block = {}
              for i in range(0, len(states), 2):
                  left, right = states[i:i+2]
                  new_state, left_block, right_block = _block_collision_parallel(
                  	hash_cls, left, right)  # Find collision from 2 start states.
                  new_states.append(new_state)
                  states_to_block[left] = left_block
                  states_to_block[right] = right_block
              self.funnel.append(state_to_block)
              states = new_states
          assert len(states) == 1
          final_state = next(iter(states))
          padding = hash_cls.length_padding(msg_len)
          # Helper method to process multiple blocks in a row.
          _, digest_state = hash_cls.process_blocks(padding, final_state)
          self.digest = hash_cls.state_to_digest(digest_state)
      
      def get_message(self, prefix, pad_char):
          """Produces msg m with given prefix s.t. H(m) = self.digest."""
          glue_len = (self.k + 1) * self.hash_cls.BLOCK_SIZE
          assert len(prefix) + glue_len <= self.msg_len
          pad = pad_char * (self.msg_len - glue_len - len(prefix))
          prefix += pad.encode("ascii")
          assert len(prefix) + glue_len == self.msg_len
          return prefix + self._get_glue(prefix)
      
      def _get_glue(self, prefix):
          assert len(prefix) % self.hash_cls.BLOCK_SIZE == 0
          _, state = self.hash_cls.process_blocks(prefix,
                                                  self.hash_cls.init_state())
          leaves = self.funnel[0]
          state, bridge = _block_collision_into(self.hash_cls, state, leaves)
          glue = bytearray()
          glue.extend(bridge)
          for state_to_block in self.funnel:
              assert state in state_to_block
              block = state_to_block[state]
              glue.extend(block)
              state = self.hash_cls.process_chunk(block, state)
          assert len(glue) == (self.k + 1) * self.hash_cls.BLOCK_SIZE
          return glue
  ```

  With that, we can now show off!

  ```python
  msg_len = 5000  # Roughly. We'll pad to it.
  b = MyHash.state_size() * 8
  generator = NostradamusGenerator(MyHash, k=b//2, msg_len=msg_len)
  print("I am Nostradamus. I know the baseball future. Here is my proof:")
  print(generator.digest.hex())
  
  scores = baseball_season()  # Wait...
  
  print("Ah. Just like I predicted! My prediction was...")
  prediction_prefix = scores.encode("ascii") + b"\n\nMy secret notes (ignore):\n"
  prediction = generator.get_message(prediction_prefix, pad_char=" ")
  print(prediction)
  print(f"Hash: {MyHash().update(prediction).digest().hex()}")
  assert generator.digest == MyHash().update(prediction).digest()
  ```

  Here again I'm not sure how one would go around removing the restriction on `msg_len` (to be a block size multiple in this case), since all our precomputations assume that we are at a block boundary, but presumably this wouldn't often be an issue in practice since we are already adding some padding, let's assume we can add a bit more to reach a block size multiple.

- [ ] [55. MD4 Collisions](src/set_7/55.py)

*TODO: challenge*
