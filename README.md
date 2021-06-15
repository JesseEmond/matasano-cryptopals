# Matasano - [Cryptopals](http://cryptopals.com/)

[![Build Status](https://travis-ci.org/JesseEmond/matasano-cryptopals.svg?branch=unittests)](https://travis-ci.org/JesseEmond/matasano-cryptopals)

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
  values that I extracted with C++'s implementation.

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

  ```
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

  ```
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
  target_digest_info = pkcs1_v1_5.encode_sha1(digest, total_len=1024//8)
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
  generation following
  [FIPS 186](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
  documentation.

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

- [ ] [44. DSA nonce recovery from repeated nonce](src/set_6/44.py)

*TODO: challenge*
