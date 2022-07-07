use ecdsa::ecdsa_circuit::TestCircuitEcdsaVerify;
use ecdsa::halo2;
use ecc::maingate::big_to_fe;
use ecc::maingate::fe_to_big;
use group::ff::Field;
use group::{Curve, Group};
use halo2::arithmetic::CurveAffine;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Value;
use halo2::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2::poly::{commitment::Params};
use halo2::transcript::{Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge};
use halo2::dev::MockProver;
use rand_core::OsRng;
use std::marker::PhantomData;
use ecdsa::curves::pasta::{Eq, EqAffine};

fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
    let x_big = fe_to_big(x);
    big_to_fe(x_big)
}

fn run<C: CurveAffine, N: FieldExt>() {
    println!("At top of run function");
    let g = C::generator();

    // Generate a key pair
    let sk = <C as CurveAffine>::ScalarExt::random(OsRng);
    let public_key = (g * sk).to_affine();

    // Generate a valid signature
    // Suppose `m_hash` is the message hash
    let msg_hash = <C as CurveAffine>::ScalarExt::random(OsRng);

    // Draw arandomness
    let k = <C as CurveAffine>::ScalarExt::random(OsRng);
    let k_inv = k.invert().unwrap();

    // Calculate `r`
    let r_point = (g * k).to_affine().coordinates().unwrap();
    let x = r_point.x();
    let r = mod_n::<C>(*x);

    // Calculate `s`
    let s = k_inv * (msg_hash + (r * sk));
    println!("Calculated a signature");

    // Sanity check. Ensure we construct a valid signature. So lets verify it
    {
        let s_inv = s.invert().unwrap();
        let u_1 = msg_hash * s_inv;
        let u_2 = r * s_inv;
        let r_point = ((g * u_1) + (public_key * u_2))
            .to_affine()
            .coordinates()
            .unwrap();
        let x_candidate = r_point.x();
        let r_candidate = mod_n::<C>(*x_candidate);
        assert_eq!(r, r_candidate);
    }
    println!("Done with sanity check");

    let k = 20;
    let aux_generator = C::CurveExt::random(OsRng).to_affine();
    let circuit = TestCircuitEcdsaVerify::<C, N> {
        public_key: Value::known(public_key),
        signature: Value::known((r, s)),
        msg_hash: Value::known(msg_hash),

        aux_generator,
        window_size: 2,
        _marker: PhantomData,
    };

    let public_inputs = vec![vec![]];
    let prover = match MockProver::run(k, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    println!("Done with mock prover.");

    assert_eq!(prover.verify(), Ok(()));
    println!("Prover verified.");

    // This is with the real prover

    let empty_circuit = TestCircuitEcdsaVerify::<C, N> {
        public_key: Value::unknown(),
        signature: Value::unknown(),
        msg_hash: Value::unknown(),
        aux_generator,
        window_size: 2,
        _marker: PhantomData,
    };
    const K: u32 = 5;
    let params: Params<EqAffine> = Params::new(K);
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
    // alert("Line 56");

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    // Create a proof
    create_proof(
        &params,
        &pk,
        &[circuit.clone(), circuit.clone()],
        // public_
        &[&[&public_inputs], &[&public_inputs]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    // alert("Line 70");

    let proof: Vec<u8> = transcript.finalize();


}


fn main() {
    println!("Hello world");
    use ecdsa::curves::bn256::Fr as BnScalar;
    use ecdsa::curves::pasta::{Fp as PastaFp, Fq as PastaFq};
    use ecdsa::curves::secp256k1::Secp256k1Affine as Secp256k1;
    println!("Running first instance with BnScalar field");
    run::<Secp256k1, BnScalar>();
    run::<Secp256k1, PastaFp>();
    run::<Secp256k1, PastaFq>();
}