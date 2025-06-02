use crate::polynomial::Polynomial;

pub struct Params {
    pub n: usize,
    pub t: u64,
    pub q: u64,
}

pub struct Bfv<const N: usize, const A: u64> {
    param: Params,
    c: (Polynomial<N, A>, Polynomial<N, A>),
}

// impl<const N: usize, const A: u64> Bfv<N, A> {
//     pub fn new(param: Params, message: u64) ->  {
//         let delta = (param.q / param.t) as i64;
//         let m = Polynomial::<N, A>::from_int_scaled(message, delta);
//     }
// }
