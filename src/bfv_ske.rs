use crate::polynomial::{Element, Polynomial};
use std::ops::Add;

pub struct Bfv<const N: usize, const Q: u64, const T: u64> {}

#[derive(Debug)]
pub struct BfvCipher<const N: usize, const Q: u64, const T: u64> {
    c_1: Polynomial<N, Q>,
    c_2: Polynomial<N, Q>,
}

impl<const N: usize, const Q: u64, const T: u64> Bfv<N, Q, T> {
    pub fn keygen() -> (Self, Polynomial<N, 2>) {
        let sk = Polynomial::<N, 2>::rand();
        (Self {}, sk)
    }

    pub fn encrypt(&self, message: Polynomial<N, T>, sk: Polynomial<N, 2>) -> BfvCipher<N, Q, T> {
        let delta_elem = Element::<Q>::new(Q.div_ceil(T) as i64);
        let delta_m = message.lift::<Q>() * delta_elem;

        let a = Polynomial::<N, Q>::rand();
        let e = Polynomial::<N, Q>::ternary_error();
        let c_1 = sk.lift::<Q>() * a + delta_m + e;
        let c_2 = -a;

        BfvCipher { c_1, c_2 }
    }
}

impl<const N: usize, const Q: u64, const T: u64> BfvCipher<N, Q, T> {
    pub fn decrypt(self, sk: Polynomial<N, 2>) -> Polynomial<N, T> {
        let ct = self.c_1 + self.c_2 * sk.lift::<Q>();
        ct.msb()
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_bfv_add_t_2_example() {
        const T: u64 = 2;
        type E = Element<T>;
        const N: usize = 4;
        const Q: u64 = 32;

        let (bfv, sk) = Bfv::<N, Q, T>::keygen();
        let mut rng = rand::rng();

        let m_a_coeffs: [E; N] = core::array::from_fn(|_| E::new(rng.random_range(0..T) as i64));
        let m_a = Polynomial::<N, T>::new(m_a_coeffs);
        println!("m_a {:?}", m_a);
        let enc_a = bfv.encrypt(m_a, sk);

        let m_b_coeffs: [E; N] = core::array::from_fn(|_| E::new(rng.random_range(0..T) as i64));
        let m_b = Polynomial::<N, T>::new(m_b_coeffs);
        println!("m_b {:?}", m_b);
        let enc_b = bfv.encrypt(m_b, sk);

        /* Homomorphic */
        let enc_3 = enc_a + enc_b;

        /* Decryption */
        let raw_add = m_a + m_b;
        println!("expected = {:?}", raw_add);
        let dec = enc_3.decrypt(sk);
        println!("actual = {:?}", dec);
        assert_eq!(raw_add, dec);
    }
}
