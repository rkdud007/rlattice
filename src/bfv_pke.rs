//! Implementation of BFV especially public key FHE.
//! https://inferati.azureedge.net/docs/inferati-fhe-bfv.pdf
//! https://github.com/openfheorg/openfhe-development/tree/02a8e9c76c3e2eff53392530199c63e4da53eb65/src/pke/lib/scheme/bfvrns
//!
//! q = ciphertext modulus
//! t = plaintext modulus
//! n = ring dimension

use crate::polynomial::{Element, Polynomial};
use std::ops::{Add, Mul};

pub struct Bfv<const N: usize, const Q: u64, const T: u64> {
    pk: (Polynomial<N, Q>, Polynomial<N, Q>),
}

#[derive(Debug)]
pub struct BfvCipher<const N: usize, const Q: u64, const T: u64> {
    c_1: Polynomial<N, Q>,
    c_2: Polynomial<N, Q>,
}

impl<const N: usize, const Q: u64, const T: u64> Bfv<N, Q, T> {
    pub fn keygen() -> (Self, Polynomial<N, 2>) {
        /*
            a <- R_q
            e <- X
            pk[0] <- (-(a*sk)+e) mod q
            pk[1] <- a
        */
        let sk = Polynomial::<N, 2>::rand();
        let a = Polynomial::<N, Q>::rand();
        let e = Polynomial::<N, Q>::ternary_error();
        println!("e {:?}", e);
        let pk1 = -(a * sk.lift::<Q>() + e);
        (Self { pk: (pk1, a) }, sk)
    }

    pub fn encrypt(&self, message: Polynomial<N, T>) -> BfvCipher<N, Q, T> {
        let delta_elem = Element::<Q>::new(Q.div_ceil(T) as i64);
        let delta_m = message.lift::<Q>() * delta_elem;
        let u = Polynomial::<N, 2>::rand();
        let e_1 = Polynomial::<N, Q>::ternary_error();
        let e_2 = Polynomial::<N, Q>::ternary_error();
        println!("e_1 {:?}", e_1);
        println!("e_2 {:?}", e_2);
        let u = u.lift::<Q>();

        let c_1 = self.pk.0 * u + e_1 + delta_m;
        let c_2 = self.pk.1 * u + e_2;

        BfvCipher { c_1, c_2 }
    }
}

impl<const N: usize, const Q: u64, const T: u64> BfvCipher<N, Q, T> {
    pub fn decrypt(self, sk: Polynomial<N, 2>) -> Polynomial<N, T> {
        let ct = self.c_1 + self.c_2 * sk.lift::<Q>();
        let delta: u64 = Q.div_ceil(T);
        // (ct + Δ/2) / Δ  mod t
        let p_inner: [_; N] = ct
            .inner
            .iter()
            .map(|e| {
                let rounded = (e.value() as u64 + delta / 2) / delta;
                println!("{}", rounded);
                Element::<T>::new(rounded as i64)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Polynomial::new(p_inner)
        // ct.msb()
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

/// plaintext * ciphertext
impl<const N: usize, const Q: u64, const T: u64> Mul<Polynomial<N, Q>> for &BfvCipher<N, Q, T> {
    type Output = BfvCipher<N, Q, T>;

    fn mul(self, pt: Polynomial<N, Q>) -> Self::Output {
        let c0 = self.c_1 * pt;
        let c1 = self.c_2 * pt;

        BfvCipher { c_1: c0, c_2: c1 }
    }
}

// todo fix
// impl<const N: usize, const Q: u64, const T: u64> Mul for BfvCipher<N, Q, T> {
//     type Output = Self;

//     fn mul(self, rhs: Self) -> Self::Output {
//         let c_1 = self.c_1 * rhs.c_1;
//         let c_2 = self.c_2 * rhs.c_2;
//         Self { c_1, c_2 }
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bfv_add_t_2_example() {
        const T: u64 = 2;
        type E = Element<T>;
        const N: usize = 4;
        const Q: u64 = 32;

        let (bfv, sk) = Bfv::<N, Q, T>::keygen();

        let m_a_1 = E::new(1);
        let m_a_2 = E::new(0);
        let m_a_3 = E::new(1);
        let m_a_4 = E::new(0);
        let m_a = Polynomial::<N, T>::new([m_a_1, m_a_2, m_a_3, m_a_4]);
        println!("m_a {:?}", m_a);
        let enc_a = bfv.encrypt(m_a);
        let enc_a_ct = enc_a.c_1 + enc_a.c_2 * sk.lift::<Q>();
        println!("enc_a_ct {:?}", enc_a_ct);

        let m_b_1 = E::new(0);
        let m_b_2 = E::new(1);
        let m_b_3 = E::new(1);
        let m_b_4 = E::new(1);
        let m_b = Polynomial::<N, T>::new([m_b_1, m_b_2, m_b_3, m_b_4]);
        println!("m_b {:?}", m_b);
        let enc_b = bfv.encrypt(m_b);
        let enc_b_ct = enc_b.c_1 + enc_b.c_2 * sk.lift::<Q>();
        println!("enc_b_ct {:?}", enc_b_ct);

        /* Homomorphic */
        let enc_3 = enc_a + enc_b;
        let enc_3_ct = enc_3.c_1 + enc_3.c_2 * sk.lift::<Q>();
        println!("enc_3_ct {:?}", enc_3_ct);

        let dec = enc_3.decrypt(sk);
        /* Decryption */
        // expect 1, 1, 0, 1
        println!("dec d      = {:?}", dec);
        let raw_add = m_a + m_b;
        println!("raw = {:?}", raw_add);
        assert_eq!(raw_add, dec);
    }

    #[test]
    fn test_bfv_add_t_3_example() {
        const T: u64 = 3;
        type E = Element<T>;
        const N: usize = 4;
        const Q: u64 = 128;

        let (bfv, sk) = Bfv::<N, Q, T>::keygen();

        let m_a_1 = E::new(1);
        let m_a_2 = E::new(2);
        let m_a_3 = E::new(1);
        let m_a_4 = E::new(0);
        let m_a = Polynomial::<N, T>::new([m_a_1, m_a_2, m_a_3, m_a_4]);
        println!("m_a {:?}", m_a);
        let enc_a = bfv.encrypt(m_a);
        let enc_a_ct = enc_a.c_1 + enc_a.c_2 * sk.lift::<Q>();
        println!("enc_a_ct {:?}", enc_a_ct);

        let m_b_1 = E::new(0);
        let m_b_2 = E::new(2);
        let m_b_3 = E::new(2);
        let m_b_4 = E::new(1);
        let m_b = Polynomial::<N, T>::new([m_b_1, m_b_2, m_b_3, m_b_4]);
        println!("m_b {:?}", m_b);
        let enc_b = bfv.encrypt(m_b);
        let enc_b_ct = enc_b.c_1 + enc_b.c_2 * sk.lift::<Q>();
        println!("enc_b_ct {:?}", enc_b_ct);

        /* Homomorphic */
        let enc_3 = enc_a + enc_b;
        let enc_3_ct = enc_3.c_1 + enc_3.c_2 * sk.lift::<Q>();
        println!("enc_3_ct {:?}", enc_3_ct);

        let dec = enc_3.decrypt(sk);
        /* Decryption */
        // expect 1, 1, 0, 1
        println!("dec d      = {:?}", dec);
        let raw_add = m_a + m_b;
        println!("raw = {:?}", raw_add);
        assert_eq!(raw_add, dec);
    }
}
