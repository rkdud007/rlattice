#[cfg(test)]
mod tests {
    use diamond_io::{
        bgg::sampler::{BGGEncodingSampler, BGGPublicKeySampler},
        poly::{
            dcrt::{DCRTPolyHashSampler, DCRTPolyParams, DCRTPolyUniformSampler},
            sampler::PolyUniformSampler,
        },
        utils::{create_bit_random_poly, create_random_poly},
    };
    use sha3::Keccak256;

    #[test]
    fn test_encoding_add() {
        // Create parameters for testing
        let params = DCRTPolyParams::default();
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
        let plaintexts = vec![create_random_poly(&params), create_random_poly(&params)];

        // Create encoding sampler and encodings
        let bgg_encoding_sampler = BGGEncodingSampler::new(&params, &secrets, uniform_sampler, 0.0);
        let encodings = bgg_encoding_sampler.sample(&params, &pubkeys, &plaintexts);
    }
}
