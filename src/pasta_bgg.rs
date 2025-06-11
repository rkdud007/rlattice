//! Attempt to implement Pasta homomorphically over bgg.
//! But while realized I need to hide the Pasta key by fhe ciphertext which is PRF key in our context.
//! Will back with this after try simple bgg/bfv experiments.
//!
//! Also unlike plain this logic is incorrect.

use byteorder::{BigEndian, ByteOrder};
use diamond_io::poly::PolyElem;
use diamond_io::{
    bgg::{BggEncoding, circuit::Evaluable},
    poly::{Poly, PolyMatrix, PolyParams},
};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const PASTA_T: usize = 128;
/// Number of rounds (Pasta-3)
pub const PASTA_R: usize = 3;

pub fn keystream_bgg<M: PolyMatrix>(
    params: &<M::P as Poly>::Params,
    enc_left: &BggEncoding<M>,
    enc_right: &BggEncoding<M>,
    enc_one: &BggEncoding<M>,
    nonce: u64,
    ctr: u64,
) -> BggEncoding<M>
where
    BggEncoding<M>: Clone,
{
    /* init shake */
    let mut seed = [0u8; 16];
    BigEndian::write_u64(&mut seed[..8], nonce);
    BigEndian::write_u64(&mut seed[8..], ctr);
    let mut hasher = Shake128::default();
    hasher.update(&seed);
    let mut xof = hasher.finalize_xof();

    let mut mats_l = Vec::<M>::new();
    let mut mats_r = Vec::<M>::new();
    let mut rcs_l = Vec::<M::P>::new();
    let mut rcs_r = Vec::<M::P>::new();

    for _ in 0..=PASTA_R {
        mats_l.push(random_sequential_matrix::<M>(&mut xof, params));
        mats_r.push(random_sequential_matrix::<M>(&mut xof, params));
        rcs_l.push(random_constant::<M>(&mut xof, params));
        rcs_r.push(random_constant::<M>(&mut xof, params));
    }

    let mut l = enc_left.clone();
    let mut r = enc_right.clone();

    for round_idx in 0..=PASTA_R {
        pasta_round::<M>(
            params,
            &mut l,
            &mut r,
            &mats_l[round_idx],
            &mats_r[round_idx],
            &rcs_l[round_idx],
            &rcs_r[round_idx],
            round_idx == PASTA_R - 1,
            enc_one,
        );
    }
    pasta_affine::<M>(&mut l, &mats_l[PASTA_R], &rcs_l[PASTA_R], enc_one);
    pasta_affine::<M>(&mut r, &mats_r[PASTA_R], &rcs_r[PASTA_R], enc_one);
    mix::<M>(&mut l, &mut r);

    l
}

fn random_constant<M: PolyMatrix>(
    xof: &mut dyn XofReader,
    params: &<M::P as Poly>::Params,
) -> M::P {
    let coeffs = (0..PASTA_T)
        .map(|_| {
            let mut buf = [0u8; 8];
            xof.read(&mut buf);
            <M::P as Poly>::Elem::constant(&params.modulus(), u64::from_le_bytes(buf))
        })
        .collect::<Vec<_>>();
    M::P::from_coeffs(params, &coeffs)
}

fn random_sequential_matrix<M: PolyMatrix>(
    xof: &mut dyn XofReader,
    params: &<M::P as Poly>::Params,
) -> M {
    let first = random_constant::<M>(xof, params)
        .coeffs()
        .into_iter()
        .collect::<Vec<_>>();
    let mut rows = Vec::<M::P>::with_capacity(PASTA_T);
    rows.push(M::P::from_coeffs(params, &first));

    for _ in 1..PASTA_T {
        let prev = rows
            .last()
            .unwrap()
            .coeffs()
            .into_iter()
            .collect::<Vec<_>>();
        let mut nxt = vec![<M::P as Poly>::Elem::zero(&params.modulus()); PASTA_T];
        for j in 0..PASTA_T {
            let term = first[j].clone() * prev[PASTA_T - 1].clone();
            nxt[j] = if j == 0 {
                term
            } else {
                term + prev[j - 1].clone()
            };
        }
        rows.push(M::P::from_coeffs(params, &nxt));
    }
    M::from_poly_vec_row(&params, rows)
}

fn pasta_round<M: PolyMatrix>(
    params: &<M::P as Poly>::Params,
    l: &mut BggEncoding<M>,
    r: &mut BggEncoding<M>,
    mat_l: &M,
    mat_r: &M,
    rc_l: &M::P,
    rc_r: &M::P,
    last_round: bool,
    enc_one: &BggEncoding<M>,
) {
    pasta_affine::<M>(l, mat_l, rc_l, enc_one);
    pasta_affine::<M>(r, mat_r, rc_r, enc_one);
    mix::<M>(l, r);

    if last_round {
        cube::<M>(l);
        cube::<M>(r);
    } else {
        feistel::<M>(params, l);
        feistel::<M>(params, r);
    }
}

fn pasta_affine<M: PolyMatrix>(
    state: &mut BggEncoding<M>,
    mat: &M,
    rc: &M::P,
    enc_one: &BggEncoding<M>,
) {
    // todo cannot multiply `BggEncoding<M>` by `<M as PolyMatrix>::P`
    // todo condition failed: self.ncol (136) must equal rhs.nrow (1)
    let mut state_m = state.clone().vector * mat.clone();
    state_m = state_m.clone() + enc_one.clone().vector * rc.clone();
    *state = BggEncoding::<M>::new(state_m, state.pubkey.clone(), None);
}

fn mix<M: PolyMatrix>(l: &mut BggEncoding<M>, r: &mut BggEncoding<M>) {
    let sum = l.clone() + r.clone();
    *l = l.clone() + sum.clone();
    *r = r.clone() + sum;
}

fn feistel<M: PolyMatrix>(params: &<M::P as Poly>::Params, state: &mut BggEncoding<M>) {
    let rot1 = state.rotate(params, 1);
    *state = state.clone() + rot1.clone() * rot1;
}

fn cube<M: PolyMatrix>(state: &mut BggEncoding<M>) {
    *state = state.clone() * state.clone();
    *state = state.clone() * state.clone();
}

#[cfg(test)]
mod tests {
    use super::*;
    use diamond_io::{
        bgg::sampler::{BGGEncodingSampler, BGGPublicKeySampler},
        io::utils::build_poly_vec,
        poly::{
            dcrt::{
                DCRTPolyHashSampler, DCRTPolyParams, DCRTPolyUniformSampler,
                matrix::base::BaseMatrix,
            },
            sampler::PolyUniformSampler,
        },
        utils::create_bit_random_poly,
    };
    use sha3::Keccak256;

    #[test]
    fn test_encoding_add() {
        // Create parameters for testing
        // todo: if ring dimension is less than PASTA_T it return error.
        let params = DCRTPolyParams::new(256, 2, 17, 1);
        // Create samplers
        let key: [u8; 32] = rand::random();
        let d = 3;
        let bgg_pubkey_sampler =
            BGGPublicKeySampler::<_, DCRTPolyHashSampler<Keccak256>>::new(key, d);
        let uniform_sampler = DCRTPolyUniformSampler::new();

        // Generate random tag for sampling
        let tag: u64 = rand::random();
        let tag_bytes = tag.to_le_bytes();

        // Create random public keys
        let reveal_plaintexts = [true; 3];
        let pubkeys = bgg_pubkey_sampler.sample(&params, &tag_bytes, &reveal_plaintexts);

        // Create secret and plaintexts
        let secrets = vec![create_bit_random_poly(&params); d];
        let plaintexts =
            build_poly_vec::<BaseMatrix<_>>(&params, &[true, true, true, true], 1, 4, 4, None);
        println!("{:?}", plaintexts.len());

        // Create encoding sampler and encodings
        let bgg_encoding_sampler = BGGEncodingSampler::new(&params, &secrets, uniform_sampler, 0.0);
        let encs = bgg_encoding_sampler.sample(&params, &pubkeys, &plaintexts);
        // BGG.enc(1, poly1, poly2)
        assert_eq!(encs.len(), 3);
        let enc_one = encs[0].clone();
        let enc_left = encs[1].clone();
        let enc_right = encs[2].clone();
        println!("sampled bgg");

        let _ = keystream_bgg(&params, &enc_left, &enc_right, &enc_one, 0, 0);
        // let ks1 = keystream_bgg(&params, &enc_left, &enc_right, &enc_one, 0, 1);
        println!("sampled ks0");
        // assert_ne!(ks0.vector, ks1.vector);

        // later turn into
    }
}
