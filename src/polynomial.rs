use rand::{distr::Uniform, prelude::*};
use std::{
    fmt,
    ops::{Add, Mul, Neg, Sub},
    usize,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Element<const A: u64> {
    value: i64,
}

impl<const A: u64> Element<A> {
    pub fn new(value: i64) -> Self {
        let a = A as i64;
        let mid = a / 2;
        let balanced = (value + mid).rem_euclid(a) - mid;

        Self { value: balanced }
    }

    fn balanced(x: i64) -> i64 {
        let a = A as i64;
        let half = a / 2;
        (x + half).rem_euclid(a) - half
    }

    pub fn get_value(&self) -> i64 {
        self.value
    }
}

impl<const A: u64> Add for Element<A> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let value = Self::balanced(self.value + rhs.value);
        Self { value }
    }
}

impl<const A: u64> Sub for Element<A> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let value = Self::balanced(self.value - rhs.value);
        Self { value }
    }
}

impl<const A: u64> Neg for Element<A> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::new(-self.value)
    }
}

impl<const A: u64> Mul for Element<A> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let a = A as i64;
        Self::new((self.value.saturating_mul(rhs.value)) % a)
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
        let half_a = (A / 2) as i64;
        let side = Uniform::new(-half_a, half_a).unwrap();
        let inner: [Element<A>; N] = (0..N)
            .map(|_| Element::new(side.sample(&mut rng)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Self { inner }
    }

    pub fn lift<const B: u64>(&self) -> Polynomial<N, B> {
        Polynomial::<N, B>::new(core::array::from_fn(|i| {
            Element::<B>::new(self.inner[i].value)
        }))
    }

    /// Uniform error in {-1,0,+1}.  Good enough for tests.
    pub fn ternary_error() -> Self {
        let mut rng = rand::rng();
        Self::new(core::array::from_fn(|_| {
            let r: i8 = rng.random_range(-1..=1);
            Element::new(r as i64)
        }))
    }

    pub fn decode<const B: u64>(self, delta: i64) -> Polynomial<N, B> {
        Polynomial::<N, B>::new(core::array::from_fn(|i| {
            // Round: ( value / Δ ), i.e. (value + Δ/2) / Δ  for positive Δ
            let rounded = ((self.inner[i].value + delta / 2) / delta) as i64;
            Element::<B>::new(rounded)
        }))
    }
}

impl<const N: usize, const A: u64> fmt::Debug for Polynomial<N, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let coeffs: Vec<i64> = self.inner.iter().map(|e| e.value).collect();
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
impl<const N: usize, const A: u64> Mul for Polynomial<N, A> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut out = [Element::<A>::new(0); N];

        for i in 0..N {
            for j in 0..N {
                let prod = self.inner[i] * rhs.inner[j];
                let k = i + j;
                if k < N {
                    out[k] = out[k] + prod; // x^k
                } else {
                    out[k - N] = out[k - N] - prod; // −x^{k-N}
                }
            }
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
    fn test_add() {
        type E = Element<17>;
        let x_1 = E::new(5);
        let y_1 = E::new(7);
        let x_2 = E::new(9);
        let y_2 = E::new(9);
        let x_3 = E::new(-8);
        let y_3 = E::new(-5);
        let x_4 = E::new(8);
        let y_4 = E::new(-8);
        let p_x = Polynomial::<4, 17>::new([x_1, x_2, x_3, x_4]);
        let p_y = Polynomial::<4, 17>::new([y_1, y_2, y_3, y_4]);
        let z_1 = E::new(-5);
        let z_2 = E::new(1);
        let z_3 = E::new(4);
        let z_4 = E::new(0);
        let p_z = Polynomial::<4, 17>::new([z_1, z_2, z_3, z_4]);
        assert_eq!((p_x + p_y), p_z);
    }

    #[test]
    fn test_mul() {}
}
