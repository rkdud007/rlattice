use rand::{distr::Uniform, prelude::*};
use std::{
    fmt,
    ops::{Add, Mul, Neg, Sub},
    usize,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Element<const A: u64> {
    value: u64,
}

impl<const A: u64> Element<A> {
    pub fn new(value: i64) -> Self {
        let value = Self::balanced(value);
        Self { value }
    }

    fn balanced(x: i64) -> u64 {
        ((x % A as i64 + A as i64) % A as i64) as u64
    }

    pub fn value(&self) -> u64 {
        self.value
    }
}

impl<const A: u64> Add for Element<A> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let value = Self::balanced(self.value as i64 + rhs.value as i64);
        Self { value }
    }
}

impl<const A: u64> Sub for Element<A> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let value = Self::balanced(self.value as i64 - rhs.value as i64);
        Self { value }
    }
}

impl<const A: u64> Neg for Element<A> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::new(-(self.value as i64))
    }
}

impl<const A: u64> Mul for Element<A> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let value = Self::balanced(self.value as i64 * rhs.value as i64);
        Self { value }
    }
}

/// R_{a} = Z_{a}[x]/(x^n+1)
#[derive(PartialEq, Clone, Copy)]
pub struct Polynomial<const N: usize, const A: u64> {
    pub inner: [Element<A>; N],
}

impl<const N: usize, const A: u64> Polynomial<N, A> {
    pub fn new(inner: [Element<A>; N]) -> Self {
        Self { inner }
    }

    pub fn from_int_scaled(int: u64, delta: i64) -> Self {
        let inner: [Element<A>; N] = (0..N)
            .map(|i| {
                if i < u16::BITS as usize {
                    // multiply bit by Δ before lifting into Z_q
                    Element::<A>::new(((int >> i) & 1) as i64 * delta)
                } else {
                    Element::<A>::new(0)
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Self { inner }
    }

    pub fn rand() -> Self {
        let mut rng = rand::rng();
        let side = Uniform::new(0, A as i64).unwrap();
        let inner: [Element<A>; N] = (0..N)
            .map(|_| Element::new(side.sample(&mut rng)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Self { inner }
    }

    pub fn lift<const B: u64>(&self) -> Polynomial<N, B> {
        Polynomial::<N, B>::new(core::array::from_fn(|i| {
            Element::<B>::new(self.inner[i].value as i64)
        }))
    }

    /// Uniform error in {-1,0,+1}.  Good enough for tests.
    pub fn ternary_error() -> Self {
        let mut rng = rand::rng();
        Self::new(core::array::from_fn(|_| {
            let r: i8 = rng.random_range(0..=1);
            Element::new(r as i64)
        }))
    }

    pub fn msb(self) -> Polynomial<N, 2> {
        Polynomial::<N, 2>::new(core::array::from_fn(|i| {
            let v = self.inner[i].value;
            let bit = u64_msb(v, A.ilog2() as usize);
            Element::<2>::new(bit as i64)
        }))
    }
}

pub fn u64_msb(value: u64, len: usize) -> u64 {
    (value >> (len - 1)) & 1
}

impl<const N: usize, const A: u64> fmt::Debug for Polynomial<N, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let coeffs: Vec<u64> = self.inner.iter().map(|e| e.value).collect();
        write!(f, "{:?}", coeffs)
    }
}

impl<const N: usize, const A: u64> Add for Polynomial<N, A> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let inner = core::array::from_fn(|i| self.inner[i] + rhs.inner[i]);
        Self { inner }
    }
}

// todo: NTT/iNTT
impl<const N: usize, const A: u64> Mul<Polynomial<N, A>> for Polynomial<N, A> {
    type Output = Self;

    fn mul(self, rhs: Polynomial<N, A>) -> Self::Output {
        let mut out = [Element::<A>::new(0); N];

        for i in 0..N {
            for j in 0..N {
                let prod = self.inner[i] * rhs.inner[j];
                let k = i + j;
                if k < N {
                    out[k] = out[k] + prod;
                } else {
                    out[k - N] = out[k - N] - prod;
                }
            }
        }
        Self::new(out)
    }
}

// Polynomial * Element
impl<const N: usize, const A: u64> Mul<Element<A>> for Polynomial<N, A> {
    type Output = Self;

    fn mul(self, rhs: Element<A>) -> Self::Output {
        let mut out = [Element::<A>::new(0); N];

        for i in 0..N {
            out[i] = self.inner[i] * rhs;
        }
        Self::new(out)
    }
}

impl<const N: usize, const A: u64> Neg for Polynomial<N, A> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self::new(core::array::from_fn(|i| -self.inner[i]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_element_add_and_mul_mod_32() {
        type E = Element<32>;

        let x_1 = E::new(5);
        let y_1 = E::new(7);
        let x_2 = E::new(9);
        let y_2 = E::new(9);
        let x_3 = E::new(-8);
        let y_3 = E::new(-5);
        let x_4 = E::new(8);
        let y_4 = E::new(-8);

        let p_x = Polynomial::<4, 32>::new([x_1, x_2, x_3, x_4]);
        let p_y = Polynomial::<4, 32>::new([y_1, y_2, y_3, y_4]);

        let z_add = Polynomial::<4, 32>::new([
            E::new(5 + 7),
            E::new(9 + 9),
            E::new(-8 + -5),
            E::new(8 + -8),
        ]);

        assert_eq!(p_x + p_y, z_add);

        let z_mul_elementwise =
            Polynomial::<4, 32>::new([x_1 * y_1, x_2 * y_2, x_3 * y_3, x_4 * y_4]);

        let coeffwise_product = Polynomial::<4, 32>::new([
            E::new(5 * 7),
            E::new(9 * 9),
            E::new(-8 * -5),
            E::new(8 * -8),
        ]);

        assert_eq!(z_mul_elementwise, coeffwise_product);
    }

    #[test]
    fn test_add_and_mul_mod_2() {
        type E = Element<2>;

        let x_1 = E::new(1);
        let y_1 = E::new(1);
        let x_2 = E::new(0);
        let y_2 = E::new(1);
        let x_3 = E::new(-1);
        let y_3 = E::new(-1);
        let x_4 = E::new(2);
        let y_4 = E::new(3);

        let p_x = Polynomial::<4, 2>::new([x_1, x_2, x_3, x_4]);
        let p_y = Polynomial::<4, 2>::new([y_1, y_2, y_3, y_4]);

        let z_add =
            Polynomial::<4, 2>::new([E::new(1 + 1), E::new(0 + 1), E::new(-1 + -1), E::new(2 + 3)]);

        assert_eq!(p_x + p_y, z_add);

        let z_mul_elementwise =
            Polynomial::<4, 2>::new([x_1 * y_1, x_2 * y_2, x_3 * y_3, x_4 * y_4]);

        let coeffwise_product =
            Polynomial::<4, 2>::new([E::new(1 * 1), E::new(0 * 1), E::new(-1 * -1), E::new(2 * 3)]);

        assert_eq!(z_mul_elementwise, coeffwise_product);
    }

    #[test]
    fn test_polynomial_rand_mod_32() {
        type P = Polynomial<4, 32>;
        let poly = P::rand();
        for elem in poly.inner.iter() {
            let val = elem.value();
            assert!(val < 32, "Value {} is not less than 32", val);
        }
    }

    #[test]
    fn test_polynomial_rand_mod_2() {
        type P = Polynomial<4, 2>;
        let poly = P::rand();
        for elem in poly.inner.iter() {
            let val = elem.value();
            assert!(val < 2, "Value {} is not less than 2", val);
        }
    }
}
