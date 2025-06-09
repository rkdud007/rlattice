//! Implementation of PASTA: https://eprint.iacr.org/2021/731.pdf
//! Referred PASTA_3 from: https://github.com/isec-tugraz/hybrid-HE-framework/blob/master/ciphers/pasta_3/plain/pasta_3_plain.cpp

use std::io::Read;

use byteorder::{BigEndian, ByteOrder};
use sha3::{
    Shake128, Shake128Reader,
    digest::{ExtendableOutput, Update},
};

/// Plaintext size
pub const PASTA_T: usize = 128;
/// Round count
pub const PASTA_R: usize = 3;

const NONCE: u64 = 123_456_789;

type Block = [u64; PASTA_T];

#[inline(always)]
fn mul_mod(a: u64, b: u64, p: u64) -> u64 {
    ((a as u128 * b as u128) % p as u128) as u64
}
#[inline(always)]
fn add_mod(a: u64, b: u64, p: u64) -> u64 {
    let s = a.wrapping_add(b);
    if s >= p { s - p } else { s }
}

pub struct Pasta {
    key: Vec<u64>,
    p: u64,
    mask: u64,
    shake: Shake128Reader,
}

impl Pasta {
    pub fn new(key: Vec<u64>, modulus: u64) -> Self {
        let reader = Shake128::default().finalize_xof();
        let bits = 64 - modulus.leading_zeros();
        let mask = (1u64 << bits) - 1;
        Self {
            key,
            p: modulus,
            mask,
            shake: reader,
        }
    }

    // pub fn encrypt(&self, plain: &[u64]) -> Vec<u64> {
    //     let mut ct = plain.to_vec();
    //     let n_blocks = (plain.len() + PASTA_T - 1) / PASTA_T;

    //     for b in 0..n_blocks {
    //         let ks = self.keystream(NONCE, b as u64);
    //         for (i, w) in ct[b * PASTA_T..].iter_mut().take(PASTA_T).enumerate() {
    //             *w = add_mod(*w, ks[i], self.p);
    //         }
    //     }
    //     ct
    // }

    // pub fn decrypt(&self, cipher: &[u64]) -> Vec<u64> {
    //     let mut pt = cipher.to_vec();
    //     let n_blocks = (cipher.len() + PASTA_T - 1) / PASTA_T;

    //     for b in 0..n_blocks {
    //         let ks = self.keystream(NONCE, b as u64);
    //         for (i, w) in pt[b * PASTA_T..].iter_mut().take(PASTA_T).enumerate() {
    //             let mut v = *w;
    //             if v < ks[i] {
    //                 v = v.wrapping_add(self.p);
    //             }
    //             *w = v - ks[i];
    //         }
    //     }
    //     pt
    // }

    // pub fn keystream(&self, nonce: u64, ctr: u64) -> Block {
    //     // --- initial state (key split) ---
    //     let mut s1: Block = [0; PASTA_T];
    //     let mut s2: Block = [0; PASTA_T];
    //     s1.copy_from_slice(&self.key[..PASTA_T]);
    //     s2.copy_from_slice(&self.key[PASTA_T..]);

    //     let mut xof = Self::init_shake(nonce, ctr);

    //     for r in 0..PASTA_R {
    //         self.linear_layer(&mut s1, &mut xof);
    //         self.linear_layer(&mut s2, &mut xof);
    //         self.mix(&mut s1, &mut s2);

    //         if r == PASTA_R - 1 {
    //             Self::sbox_cube(&mut s1, self.p);
    //             Self::sbox_cube(&mut s2, self.p);
    //         } else {
    //             Self::sbox_feistel(&mut s1, self.p);
    //             Self::sbox_feistel(&mut s2, self.p);
    //         }
    //     }

    //     // final affine + mix
    //     self.linear_layer(&mut s1, &mut xof);
    //     self.linear_layer(&mut s2, &mut xof);
    //     self.mix(&mut s1, &mut s2);

    //     s1 // truncation – left branch only
    // }

    fn mix(&self, s1: &mut Block, s2: &mut Block) {
        for i in 0..PASTA_T {
            let sum = add_mod(s1[i], s2[i], self.p);
            s1[i] = add_mod(s1[i], sum, self.p);
            s2[i] = add_mod(s2[i], sum, self.p);
        }
    }

    fn sbox_cube(state: &mut Block, p: u64) {
        for v in state.iter_mut() {
            let sq = mul_mod(*v, *v, p);
            *v = mul_mod(sq, *v, p);
        }
    }

    fn sbox_feistel(state: &mut Block, p: u64) {
        let mut out = *state;
        for i in 1..PASTA_T {
            let sq = mul_mod(state[i - 1], state[i - 1], p);
            out[i] = add_mod(state[i], sq, p);
        }
        *state = out;
    }

    // fn linear_layer(&self, state: &mut Block, xof: &mut impl ExtendableXof) {
    //     let first = self.rand_vec(xof, false);
    //     let mut row = first.clone();
    //     let mut new_state = [0u64; PASTA_T];

    //     for i in 0..PASTA_T {
    //         for j in 0..PASTA_T {
    //             new_state[i] = add_mod(new_state[i], mul_mod(row[j], state[j], self.p), self.p);
    //         }
    //         if i != PASTA_T - 1 {
    //             row = Self::next_row(&row, &first, self.p);
    //         }
    //     }
    //     *state = new_state;
    //     let rc = self.rand_vec(xof, true);
    //     for i in 0..PASTA_T {
    //         state[i] = add_mod(state[i], rc[i], self.p);
    //     }
    // }

    fn next_row(prev: &[u64], first: &[u64], p: u64) -> Vec<u64> {
        let mut out = vec![0u64; PASTA_T];
        for j in 0..PASTA_T {
            let mut v = mul_mod(first[j], prev[PASTA_T - 1], p);
            if j != 0 {
                v = add_mod(v, prev[j - 1], p);
            }
            out[j] = v;
        }
        out
    }

    fn init_shake(&mut self, nonce: u64, block_counter: u64) {
        let mut shake = Shake128::default();
        let mut seed = [0u8; 16];
        BigEndian::write_u64(&mut seed[0..8], nonce);
        BigEndian::write_u64(&mut seed[8..16], block_counter);
        shake.update(&seed);
        self.shake = shake.finalize_xof();
    }

    fn rand_field_element(&mut self, allow_zero: bool) -> u64 {
        loop {
            let mut buf = [0u8; 8];
            self.shake.read(&mut buf).unwrap();
            let cand = u64::from_be_bytes(buf) & self.mask;
            if (!allow_zero && cand == 0) || cand >= self.p {
                continue;
            }
            return cand;
        }
    }

    fn rand_vec(&mut self, allow_zero: bool) -> Vec<u64> {
        (0..PASTA_T)
            .map(|_| self.rand_field_element(allow_zero))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    fn test_init_shake() {
        let mut pasta = Pasta::new(vec![1, 2, 3, 4], 100);
        pasta.init_shake(123456789, 0);
        let mut f = pasta.shake.clone();
        let mut buf = [0u8; 8];
        f.read(&mut buf).unwrap();
        println!("{:?}", buf);

        pasta.init_shake(123456789, 1);
        let mut f = pasta.shake.clone();
        let mut buf = [0u8; 8];
        f.read(&mut buf).unwrap();
        println!("{:?}", buf);

        pasta.init_shake(123456789, 2);
        let mut f = pasta.shake;
        let mut buf = [0u8; 8];
        f.read(&mut buf).unwrap();
        println!("{:?}", buf);
    }

    #[test]
    fn test_rand_field_element() {
        let mut pasta = Pasta::new(vec![1, 2, 3, 4], 100);
        pasta.init_shake(123456789, 0);
        let fp = pasta.rand_field_element(true);
        println!("{:?}", fp);
        let fp = pasta.rand_field_element(true);
        println!("{:?}", fp);
        let fp = pasta.rand_field_element(true);
        println!("{:?}", fp);
        let fp = pasta.rand_field_element(true);
        println!("{:?}", fp);
    }

    #[test]
    fn test_rand_vec() {
        let mut pasta = Pasta::new(vec![1, 2, 3, 4], 100);
        pasta.init_shake(123456789, 0);
        let fp = pasta.rand_vec(true);
        println!("{:?}", fp);
        let fp = pasta.rand_vec(true);
        println!("{:?}", fp);
        let fp = pasta.rand_vec(true);
        println!("{:?}", fp);
        let fp = pasta.rand_vec(true);
        println!("{:?}", fp);
    }
}
