module chacha20

import encoding.hex

const (
	// size in bytes
	key_size = 32
	nonce_size = 12
	block_size = 64
	// ChaCha20 = 20 rounds (or 80 quarter rounds)
	chacha_rounds = 20
)

type State = []u32

struct Cipher {
mut:
	state State
pub mut:
	block State
}

fn lrot(u u32, b u8) u32 {
	return (u << b) | (u >> (32 - b))
}

[inline]
fn (mut s State) quarter_round(a u32, b u32, c u32, d u32) {
	/*
	1.  a += b; d ^= a; d <<<= 16;
	2.  c += d; b ^= c; b <<<= 12;
	3.  a += b; d ^= a; d <<<= 8;
	4.  c += d; b ^= c; b <<<= 7;
	*/
	s[a] += s[b]
	s[d] ^= s[a]
	s[d]  = lrot(s[d], 16)
	s[c] += s[d]
	s[b] ^= s[c]
	s[b]  = lrot(s[b], 12)
	s[a] += s[b]
	s[d] ^= s[a]
	s[d]  = lrot(s[d], 8)
	s[c] += s[d]
	s[b] ^= s[c]
	s[b]  = lrot(s[b], 7)
}

[inline]
fn (mut s State) chacha_round() {
	/*
	1.  QUARTERROUND(0, 4, 8,12)
    2.  QUARTERROUND(1, 5, 9,13)
    3.  QUARTERROUND(2, 6,10,14)
    4.  QUARTERROUND(3, 7,11,15)
    5.  QUARTERROUND(0, 5,10,15)
    6.  QUARTERROUND(1, 6,11,12)
    7.  QUARTERROUND(2, 7, 8,13)
    8.  QUARTERROUND(3, 4, 9,14)
	*/
	s.quarter_round(0, 4, 8,12)
    s.quarter_round(1, 5, 9,13)
    s.quarter_round(2, 6,10,14)
    s.quarter_round(3, 7,11,15)
    s.quarter_round(0, 5,10,15)
    s.quarter_round(1, 6,11,12)
    s.quarter_round(2, 7, 8,13)
    s.quarter_round(3, 4, 9,14)
}

pub fn new_chacha20(key []u8, nonce []u8) Cipher {
	assert key.len == key_size, "Wrong key size (${key.len})"
	assert nonce.len == nonce_size, "Wrong nonce size (${nonce.len})"
	mut c := Cipher{
		state: State([]u32{cap: 16})
		block: State([]u32{cap: 16, len: 16, init: 0})
	}
	c.state << [u32(0x61707865), 0x3320646e, 0x79622d32, 0x6b206574]
	unsafe {
		// key
		kptrs := key.pointers()
		for i := 0; i < kptrs.len; i += 4 {
			c.state << *(&u32(kptrs[i]))
		}
		// 32 bits of block counter
		c.state << u32(0)
		// nonce
		nptrs := nonce.pointers()
		for i := 0; i < nptrs.len; i += 4 {
			c.state << *(&u32(nptrs[i]))
		}
	}
	return c
}

[inline]
pub fn (mut c Cipher) transform_block(counter u32) {
	for i in 0 .. c.state.len {
		c.block[i] = c.state[i]
	}

	c.block[12] = counter

	for _ in 0 .. 5 {
		c.block.chacha_round()
		c.block.chacha_round()
	}

	for i, mut b in c.block {
		b += c.state[i]
	}
}

pub fn (mut c Cipher) reset_counter() {
	c.state[12] = 0
}

pub fn (mut c Cipher) next_bytes(mut dest []u8) {
	assert dest.len <= block_size, "Wrong size for 'dest' parameter (${dest.len})"
	c.transform_block(c.state[12])
	unsafe {
		ptr := &u8(c.block.pointers()[0])
		for i in 0 .. dest.len {
			dest[i] = ptr[i]
		}
	}
	c.state[12] ++
}

pub fn (mut c Cipher) xor_key_stream(mut dest []u8, src []u8) {
	mut i := u32(0)
	for i = 0; i < dest.len; i += block_size {
		mut s := i + 64
		if s > dest.len { s = u32(dest.len) }
		c.next_bytes(mut dest[i .. s])
	}

	for i = 0; i < dest.len; i ++ {
		dest[i] ^= src[i]
	}

	c.reset_counter()
}

pub fn test() {
	mut c := new_chacha20(
		hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") or { panic("$err") },
		hex.decode("000000000000004a00000000") or { panic("$err") }
	)

	// RFC 7539 examples start at block 1
	c.state[12] = 1

	text := "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

	mut dest := []u8{len: text.len, init: 0}
	c.xor_key_stream(mut dest, text.bytes())
	for i in 0 .. dest.len {
		print(dest[i].hex())
		if (i+1) & 3 == 0 {
			print(" ")
		}
	}
	println("")
	assert hex.encode(dest) == "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d", "Error while encrypting!"
	println("Encrypted correctly!")
	enc := dest.clone()
	c.state[12] = 1
	c.xor_key_stream(mut dest, enc)
	assert dest.bytestr() == text, "Error while decrypting!"
	println("Decrypted correctly!")
}
