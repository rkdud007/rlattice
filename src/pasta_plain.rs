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

    pub fn encrypt(&mut self, plaintext: &[u64]) -> Vec<u64> {
        let n_blocks = (plaintext.len() + PASTA_T - 1) / PASTA_T;
        let mut out = plaintext.to_vec();

        for b in 0..n_blocks {
            let ks = self.keystream(NONCE, b as u64);
            for (i, w) in out[b * PASTA_T..].iter_mut().take(PASTA_T).enumerate() {
                *w = add_mod(*w, ks[i], self.p);
            }
        }
        out
    }
    pub fn decrypt(&mut self, ciphertext: &[u64]) -> Vec<u64> {
        let n_blocks = (ciphertext.len() + PASTA_T - 1) / PASTA_T;
        let mut out = ciphertext.to_vec();

        for b in 0..n_blocks {
            let ks = self.keystream(NONCE, b as u64);
            for (i, w) in out[b * PASTA_T..].iter_mut().take(PASTA_T).enumerate() {
                let mut v = *w;
                if v < ks[i] {
                    v = v.wrapping_add(self.p);
                }
                *w = v - ks[i];
            }
        }
        out
    }

    pub fn keystream(&mut self, nonce: u64, block_counter: u64) -> Block {
        self.init_shake(nonce, block_counter);

        let mut l: Block = [0; PASTA_T];
        let mut r: Block = [0; PASTA_T];
        l.copy_from_slice(&self.key[..PASTA_T]);
        r.copy_from_slice(&self.key[PASTA_T..]);

        for r_idx in 0..PASTA_R {
            self.round(&mut l, &mut r, r_idx);
        }
        self.linear_layer(&mut l);
        self.linear_layer(&mut r);
        self.mix(&mut l, &mut r);

        l
    }

    fn round(&mut self, l: &mut Block, r: &mut Block, r_idx: usize) {
        self.linear_layer(l);
        self.linear_layer(r);
        self.mix(l, r);

        if r_idx == PASTA_R - 1 {
            Self::sbox_cube(l, self.p);
            Self::sbox_cube(r, self.p);
        } else {
            Self::sbox_feistel(l, self.p);
            Self::sbox_feistel(r, self.p);
        }
    }

    fn sbox_cube(state: &mut Block, p: u64) {
        for x in state.iter_mut() {
            let sq = mul_mod(*x, *x, p);
            *x = mul_mod(sq, *x, p);
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

    fn mix(&self, l: &mut Block, r: &mut Block) {
        for i in 0..PASTA_T {
            let s = add_mod(l[i], r[i], self.p);
            l[i] = add_mod(l[i], s, self.p);
            r[i] = add_mod(r[i], s, self.p);
        }
    }

    fn linear_layer(&mut self, state: &mut Block) {
        let mat = self.rand_matrix();
        let mut new = [0u64; PASTA_T];
        for i in 0..PASTA_T {
            for j in 0..PASTA_T {
                new[i] = add_mod(new[i], mul_mod(mat[i][j], state[j], self.p), self.p);
            }
        }
        *state = new;
        let rc = self.rand_vec(true);
        for i in 0..PASTA_T {
            state[i] = add_mod(state[i], rc[i], self.p);
        }
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

    fn rand_matrix(&mut self) -> Vec<Vec<u64>> {
        let first_row = self.rand_vec(false);
        let mut mat: Vec<Vec<u64>> = Vec::with_capacity(PASTA_T);
        mat.push(first_row);

        for i in 1..PASTA_T {
            let next = self.calculate_row(&mat[i - 1], &mat[0]);
            mat.push(next);
        }

        mat
    }

    fn calculate_row(&self, prev_row: &Vec<u64>, first_row: &Vec<u64>) -> Vec<u64> {
        debug_assert_eq!(prev_row.len(), PASTA_T);
        debug_assert_eq!(first_row.len(), PASTA_T);

        let m = self.p as u128;

        (0..PASTA_T)
            .map(|j| {
                let mut tmp = (first_row[j] as u128 * prev_row[PASTA_T - 1] as u128) % m;
                if j != 0 {
                    tmp = (tmp + prev_row[j - 1] as u128) % m;
                }

                tmp as u64
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, rng};
    use std::io::Read;

    use super::*;

    const P: u64 = 65_537;

    fn demo_key() -> Vec<u64> {
        let mut rng = rng();
        (0..2 * PASTA_T).map(|_| rng.random_range(0..P)).collect()
    }

    #[test]
    fn roundtrip() {
        let mut rng = rng();
        let key = demo_key();
        let mut pasta = Pasta::new(key, P);

        let plain: Vec<u64> = (0..500).map(|_| rng.random_range(0..P)).collect();
        println!("{:?}", plain);
        let ct = pasta.encrypt(&plain);
        println!("{:?}", ct);
        let dec = pasta.decrypt(&ct);
        println!("{:?}", dec);

        assert_eq!(plain, dec);
    }

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

    #[test]
    fn test_rand_matrix() {
        let mut pasta = Pasta::new(vec![1, 2, 3, 4], 100);
        pasta.init_shake(123456789, 0);
        let m = pasta.rand_matrix();
        println!("{:?}", m);
        let m = pasta.rand_matrix();
        println!("{:?}", m);
        let m = pasta.rand_matrix();
        println!("{:?}", m);
    }
}
