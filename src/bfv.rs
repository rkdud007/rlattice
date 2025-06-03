use crate::polynomial::Polynomial;
use std::ops::{Add, Mul};

pub struct Bfv<const N: usize, const Q: u64, const T: u64> {
    pk: (Polynomial<N, Q>, Polynomial<N, Q>),
}

pub struct BfvCipher<const N: usize, const Q: u64, const T: u64> {
    c_1: Polynomial<N, Q>,
    c_2: Polynomial<N, Q>,
}

impl<const N: usize, const Q: u64, const T: u64> Bfv<N, Q, T> {
    pub fn keygen() -> (Self, Polynomial<N, T>) {
        let sk = Polynomial::<N, T>::rand();
        let a = Polynomial::<N, Q>::rand();
        let e = Polynomial::<N, Q>::ternary_error();
        let pk1 = -(a * sk.lift::<Q>() + e);
        (Self { pk: (pk1, a) }, sk)
    }

    pub fn encrypt(&self, message: u64) -> BfvCipher<N, Q, T> {
        let delta = (Q / T) as i64;
        let m = Polynomial::<N, Q>::from_int_scaled(message, delta);
        let u = Polynomial::<N, Q>::ternary_error();
        let e_1 = Polynomial::<N, Q>::ternary_error();
        let e_2 = Polynomial::<N, Q>::ternary_error();

        let c_1 = self.pk.0 * u + e_1 + m;
        let c_2 = self.pk.1 * u + e_2;

        BfvCipher { c_1, c_2 }
    }
}

impl<const N: usize, const Q: u64, const T: u64> BfvCipher<N, Q, T> {
    pub fn decrypt(self, sk: Polynomial<N, T>) -> u64 {
        let delta = (Q / T) as i64;
        let d = self.c_1 + self.c_2 * sk.lift::<Q>();
        let dec = d.decode::<T>(delta);
        let lsb: Vec<i64> = dec.inner[0..(T as usize)]
            .into_iter()
            .map(|d| d.get_value())
            .collect();
        println!("{:?}", lsb);
        bits_lsb_first_to_u64(&lsb)
    }
}

impl<const N: usize, const Q: u64, const T: u64> Add for BfvCipher<N, Q, T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let c_1 = self.c_1 + rhs.c_1;
        let c_2 = self.c_2 + rhs.c_2;
        Self { c_1, c_2 }
    }
}

impl<const N: usize, const Q: u64, const T: u64> Mul for BfvCipher<N, Q, T> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let c_1 = self.c_1 * rhs.c_1;
        let c_2 = self.c_2 * rhs.c_2;
        Self { c_1, c_2 }
    }
}

fn bits_lsb_first_to_u64(bits: &[i64]) -> u64 {
    bits.iter().enumerate().fold(0u64, |acc, (i, &bit)| {
        let b = (bit & 1) as u64;
        acc | (b << i)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bfv_add() {
        const N: usize = 4096;
        // todo when t was 2, it doesn't worked
        const T: u64 = 6;
        const Q: u64 = 100000000000000;
        let (bfv, sk) = Bfv::<N, Q, T>::keygen();
        // maximum message can be represent as 2^T - 1
        let message_1 = 3;
        let enc_1 = bfv.encrypt(message_1);

        let message_2 = 4;
        let enc_2 = bfv.encrypt(message_2);

        /* Homomorphic */
        // todo: in case of add some value that over binary, it also not working
        let enc_3 = enc_1 + enc_2;

        let dec = enc_3.decrypt(sk);
        /* Decryption */
        println!("dec d      = {:?}", dec);
    }

    #[test]
    fn test_bfv_mul() {
        // todo mul is just not working rn
        const N: usize = 4096;

        const T: u64 = 6;
        const Q: u64 = 100000000000000;
        let (bfv, sk) = Bfv::<N, Q, T>::keygen();
        // maximum message can be represent as 2^T - 1
        let message_1 = 3;
        let enc_1 = bfv.encrypt(message_1);

        let message_2 = 4;
        let enc_2 = bfv.encrypt(message_2);

        /* Homomorphic */
        let enc_3 = enc_1 * enc_2;

        let dec = enc_3.decrypt(sk);
        /* Decryption */
        println!("dec d      = {:?}", dec);
    }
}
