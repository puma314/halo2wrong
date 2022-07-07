use ecdsa::ecdsa_circuit::TestCircuitEcdsaVerify;
use ecdsa::halo2;
use ecc::maingate::big_to_fe;
use ecc::maingate::fe_to_big;
use ecdsa::halo2::transcript::TranscriptWrite;
use group::ff::Field;
use group::{Curve, Group};
use halo2::arithmetic::CurveAffine;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Value;
use halo2::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2::poly::{commitment::Params};
use halo2::transcript::{Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge, TranscriptWriterBuffer, TranscriptReadBuffer};
use halo2::dev::MockProver;
use rand_core::OsRng;
use std::marker::PhantomData;
use ecdsa::curves::pasta::{Eq, EqAffine};
use halo2::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2::poly::commitment::{CommitmentScheme, ParamsProver, Prover as _Prover};
use halo2::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
// use halo2::poly::kzg::strategy::AccumulatorStrategy;
use ecdsa::curves::bn256::Bn256;

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

    // let empty_circuit = TestCircuitEcdsaVerify::<<KZGCommitmentScheme<Bn256> as Trait>::Scalar> {
    //     public_key: Value::unknown(),
    //     signature: Value::unknown(),
    //     msg_hash: Value::unknown(),
    //     aux_generator,
    //     window_size: 2,
    //     _marker: PhantomData,
    // };
    const K: u32 = 5;
    type Scheme = KZGCommitmentScheme<Bn256>;
    let params = ParamsKZG::<Bn256>::new(K);
    let rng = OsRng;

    let empty_circuit: TestCircuitEcdsaVerify<C, <Scheme as CommitmentScheme>::Scalar> = TestCircuitEcdsaVerify {
        public_key: Value::unknown(),
        signature: Value::unknown(),
        msg_hash: Value::unknown(),
        aux_generator,
        window_size: 2,
        _marker: PhantomData,
    };

    let vk = keygen_vk::<Scheme, _>(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk::<Scheme, _>(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    // let proof = create_proof::<_, Blake2bWrite<_, _, Challenge255<_>>, ProverGWC<_>, _, _>(
    //     rng, &params, &pk,
    // );
    // fn create_proof<
    //     'params,
    //     Scheme: CommitmentScheme,
    //     TranscriptWrite: TranscriptWriterBuffer<Vec<u8>, Scheme::Curve, Ch>,
    //     Prover: _Prover<'params, Scheme>,
    //     Ch,
    //     Rng,
    // >
    // create_plonk_proof::<Scheme, Prover, _, _, _, _>(
    //     params,
    //     pk,
    //     &[circuit.clone(), circuit.clone()],
    //     &[&[&[instance]], &[&[instance]]],
    //     rng,
    //     &mut transcript,
    // )
    // .expect("proof generation should not fail");

    let mut transcript = Blake2bWrite::<_, C, Challenge255<C>>::init(vec![]);
    // Create a proof
    create_proof::<_, ProverGWC<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit.clone(), circuit.clone()],
        // public_
        &[&[&public_inputs], &[&public_inputs]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");

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