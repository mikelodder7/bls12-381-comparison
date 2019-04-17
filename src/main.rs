use std::io::{self, Write};
use std::time::Instant;
use clap::{Arg, App};

fn main() {
    use rand::RngCore;
    use oldrand::Rng;

    let matches = App::new("Milagro vs ZCash BLS signatures")
        .version("0.1")
        .author("Michael Lodder")
        .about("Compares pairing library from zcash vs apache milagro for the BLS signature")
        .arg(Arg::with_name("iterations")
            .short("i")
            .long("iterations")
            .default_value("100")
            .help("The number of signatures to generate and verify for the test")
            .takes_value(true))
        .get_matches();

    let iterations = matches.value_of("iterations").unwrap().parse::<usize>().expect("Unable to parse iterations argument");;
    const MESSAGE: &[u8; 37] = b"This is a message that will be signed";

    // Make sure we get somewhat random data
    let mut throw_away = vec![0u8; 256];
    rand::rngs::OsRng::new().unwrap().fill_bytes(throw_away.as_mut_slice());
    oldrand::OsRng::new().unwrap().fill_bytes(throw_away.as_mut_slice());

    println!("\n");
    run_apache_test(iterations, &MESSAGE[..]);
    println!("\n");
    run_librustzcash(iterations, &MESSAGE[..])
}

fn run_apache_test(iterations: usize, message: &[u8]) {
    println!("================================================================================");
    println!("BLS Apache Milagro");
    println!("------------------");
    let mut signatures = Vec::with_capacity(iterations);
    let mut signkeys = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        signkeys.push(apache::SignKey::new());
    }
    print!("Generating - {} signatures...", iterations);
    io::stdout().flush().unwrap();
    let start = Instant::now();
    for key in &signkeys {
        let sig = apache::Bls::sign(message, key);
        signatures.push(sig);
    }
    let elapsed = Instant::now() - start;
    println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);

    print!("Verifying - {} signatures...", iterations);
    io::stdout().flush().unwrap();
    let mut verkeys = Vec::with_capacity(iterations);
    let mut results = Vec::with_capacity(iterations);
    let g = apache::Generator::new();
    for key in &signkeys {
        verkeys.push(apache::VerKey::new_with_generator(&g, key));
    }
    let start = Instant::now();
    for i in 0..iterations {
        let res = apache::Bls::verify(message, &g, &signatures[i], &verkeys[i]);
        results.push(res);
    }
    let elapsed = Instant::now() - start;
    println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);
    assert!(results.iter().all(|t| *t));

    print!("Verifying - multisignature...");
    io::stdout().flush().unwrap();
    let start = Instant::now();
    let msig = apache::MultiSignature::from_signatures(signatures.as_slice());
    assert!(msig.verify(message, &g, verkeys.as_slice()));
    let elapsed = Instant::now() - start;
    println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);

    print!("Verifying - aggregated signature...");
    io::stdout().flush().unwrap();
    let mut messages = Vec::with_capacity(iterations);
    for i in 0..iterations {
        let msg = format!("Message {} {}", String::from_utf8(message.to_vec()).unwrap(), i);
        let signature = apache::Bls::sign(&msg.as_bytes(), &signkeys[i]);
        signatures[i] = signature;
        messages.push(msg);
    }
    let inputs = messages.iter().zip(verkeys.iter()).map(|(s, k)| (s.as_bytes(), k)).collect::<Vec<(&[u8], &apache::VerKey)>>();
    let start = Instant::now();
    let asig = apache::AggregatedSignature::from_signatures(signatures.as_slice());
    assert!(asig.verify(&g, inputs.as_slice()));
    let elapsed = Instant::now() - start;
    println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);
    println!("================================================================================");
}

fn run_librustzcash(iterations: usize, message: &[u8]) {
    println!("================================================================================");
    println!("BLS ZCash pairing");
    println!("-----------------");
    let mut signatures = Vec::with_capacity(iterations);
    let mut signkeys = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        signkeys.push(librustzcash::SignKey::<pairing::bls12_381::Bls12>::new());
    }
    print!("Generating - {} signatures...", iterations);
    io::stdout().flush().unwrap();
    let start = Instant::now();
    for key in &signkeys {
        let sig = librustzcash::Bls::sign(message, key);
        signatures.push(sig);
    }
    let elapsed = Instant::now() - start;
    println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);

    print!("Verifying - {} signatures...", iterations);
    io::stdout().flush().unwrap();
    let mut verkeys = Vec::with_capacity(iterations);
    let mut results = Vec::with_capacity(iterations);
    let g = librustzcash::Generator::<pairing::bls12_381::Bls12>::new();
    for key in &signkeys {
        verkeys.push(librustzcash::VerKey::new_with_generator(&g,key));
    }
    let start = Instant::now();
    for i in 0..iterations {
        let res = librustzcash::Bls::verify(message, &g, &signatures[i], &verkeys[i]);
        results.push(res);
    }
    let elapsed = Instant::now() - start;
    println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);
    assert!(results.iter().all(|t| *t));

    print!("Verifying - multisignature...");
    io::stdout().flush().unwrap();
    let start = Instant::now();
    let asig = librustzcash::MultiSignature::from_signatures(signatures.as_slice());
    assert!(asig.verify(message, &g, verkeys.as_slice()));
    let elapsed = Instant::now() - start;
    println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);

    print!("Verifying - aggregated signature...");
    io::stdout().flush().unwrap();
    let mut messages = Vec::with_capacity(iterations);
    for i in 0..iterations {
        let msg = format!("Message {} {}", String::from_utf8(message.to_vec()).unwrap(), i);
        let signature = librustzcash::Bls::sign(&msg.as_bytes(), &signkeys[i]);
        signatures[i] = signature;
        messages.push(msg);
    }
    let inputs = messages.iter().zip(verkeys.iter()).map(|(s, k)| (s.as_bytes(), k)).collect::<Vec<(&[u8], &librustzcash::VerKey<pairing::bls12_381::Bls12>)>>();
    let start = Instant::now();
    let asig = librustzcash::AggregatedSignature::from_signatures(signatures.as_slice());
    assert!(asig.verify(&g, inputs.as_slice()));
    let elapsed = Instant::now() - start;
    println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);
    println!("================================================================================");
}

mod librustzcash {
    use pairing::{Engine, CurveAffine, CurveProjective, Field};
    use oldrand::{Rand, OsRng};

    pub struct Generator<E: Engine> {
        point: E::G2Affine
    }

    impl<E: Engine> Generator<E> {
        pub fn new() -> Self {
            let mut rng = OsRng::new().unwrap();
            let mut t0 = E::G2::one();
            t0.mul_assign(E::Fr::rand( & mut rng));
            Generator {
                point: t0.into()
            }
        }
    }

    pub struct SignKey<E: Engine> {
        x: E::Fr
    }

    impl<E: Engine> SignKey<E> {
        pub fn new() -> Self {
            let mut rng = OsRng::new().unwrap();
            SignKey {
                x: E::Fr::rand(&mut rng)
            }
        }
    }

    pub struct VerKey<E: Engine> {
        point: E::G2
    }

    impl<E: Engine> VerKey<E> {
        pub fn new(sk: &SignKey<E>) -> Self {
            VerKey {
                point: E::G2Affine::one().mul(sk.x)
            }
        }

        pub fn new_with_generator(g: &Generator<E>, sk: &SignKey<E>) -> Self {
            VerKey {
                point: g.point.mul(sk.x)
            }
        }

        pub fn verify(&self, message: &[u8], g: &Generator<E>, signature: &Signature<E>) -> bool {
            let h = E::G1Affine::hash(message);
            let lhs = E::pairing(signature.point, g.point);
            let rhs = E::pairing(h, self.point);
            lhs == rhs
        }
    }

    pub struct Signature<E: Engine> {
        point: E::G1
    }

    pub struct MultiSignature<E: Engine>(Signature<E>);

    impl<E: Engine> MultiSignature<E> {
        pub fn new() -> Self {
            MultiSignature(Signature{point: E::G1::zero()})
        }

        pub fn from_signatures(signatures: &[Signature<E>]) -> Self {
            let mut s = Self::new();
            for sig in signatures {
                s.aggregate(sig);
            }
            s
        }

        pub fn aggregate(&mut self, sig: &Signature<E>) {
            self.0.point.add_assign(&sig.point);
        }

        pub fn verify(&self, message: &[u8], g: &Generator<E>, vks: &[VerKey<E>]) -> bool {
            let mut aggregated_vk  = E::G2::zero();
            for vk in vks {
                aggregated_vk.add_assign(&vk.point);
            }
            let vk = VerKey {
                point: aggregated_vk
            };

            vk.verify(message, g, &self.0)
        }
    }

    pub struct AggregatedSignature<E: Engine>(Signature<E>);

    impl<E: Engine> AggregatedSignature<E> {
        pub fn new() -> Self {
            AggregatedSignature(Signature{point: E::G1::zero()})
        }

        pub fn from_signatures(signatures: &[Signature<E>]) -> Self {
            let mut s = Self::new();
            for sig in signatures {
                s.aggregate(sig);
            }
            s
        }

        pub fn aggregate(&mut self, sig: &Signature<E>) {
            self.0.point.add_assign(&sig.point);
        }

        pub fn verify(&self, g: &Generator<E>, inputs: &[(&[u8], &VerKey<E>)]) -> bool {
            let lhs = E::pairing(self.0.point, g.point);

            let mut rhs = E::Fqk::one();
            for input in inputs {
                let h = E::G1Affine::hash(input.0);
                rhs.mul_assign(&E::pairing(h, input.1.point))
            }
            lhs == rhs
        }
    }

    pub struct Bls;

    impl Bls {
        pub fn sign(message: &[u8], sk: &SignKey<pairing::bls12_381::Bls12>) -> Signature<pairing::bls12_381::Bls12> {
            let hash = <pairing::bls12_381::Bls12 as Engine>::G1Affine::hash(message);
            Signature {
                point: hash.mul(sk.x)
            }
        }

        pub fn verify(message: &[u8], g: &Generator<pairing::bls12_381::Bls12>, signature: &Signature<pairing::bls12_381::Bls12>, vk: &VerKey<pairing::bls12_381::Bls12>) -> bool {
            let h = <pairing::bls12_381::Bls12 as Engine>::G1Affine::hash(message);
            let lhs = pairing::bls12_381::Bls12::pairing(signature.point, g.point);
            let rhs = pairing::bls12_381::Bls12::pairing(h, vk.point);
            lhs == rhs
        }
    }
}

mod apache {
    use rand::RngCore;
    use amcl::bls381::rom::{CURVE_ORDER, MODBYTES};
    use amcl::bls381::ecp::ECP;
    use amcl::bls381::ecp2::ECP2;
    use amcl::bls381::big::BIG;
    use amcl::bls381::fp12::FP12;
    use amcl::bls381::pair::{g1mul, g2mul, ate, fexp};
    use amcl::rand::RAND;
    use blake2::digest::Digest;
    use std::fmt;
    use super::u32_to_u8;

    const SIGNATURE_CONTEXT: u32 = 1;
//    const PROOF_OF_POSSESSION_CONTEXT: u32 = 2;

    fn random_mod_order() ->  BIG {
        let mut seed = vec![0u8; 128];
        rand::rngs::OsRng::new().unwrap().fill_bytes(seed.as_mut_slice());
        let mut new_rand = RAND::new();
        new_rand.clean();
        new_rand.seed(128, seed.as_slice());
        BIG::randomnum(&BIG::new_ints(&CURVE_ORDER), &mut new_rand)
    }

    pub struct Generator {
        pub point: ECP2
    }

    impl Generator {
        pub fn new() -> Self {
            let point = g2mul( & ECP2::generator(), &random_mod_order());
            Generator {
                point
            }
        }
    }

    impl Clone for Generator {
        fn clone(&self) -> Self {
            let mut point = ECP2::new();
            point.copy(&self.point);
            Generator { point }
        }
    }

    pub struct SignKey {
        pub x: BIG
    }

    impl SignKey {
        pub fn new() -> Self {
            SignKey {
                x: random_mod_order()
            }
        }
    }

    pub struct VerKey {
        pub point: ECP2,
    }

    impl VerKey {
        pub fn new(sk: &SignKey) -> Self {
            let g = Generator::new();
            VerKey {
                point: g.point.mul(&sk.x),
            }
        }

        pub fn new_with_generator(g: &Generator, sk: &SignKey) -> Self {
            VerKey {
                point: g.point.mul(&sk.x)
            }
        }

//        pub fn as_bytes(&self) -> Vec<u8> {
//            let len = MODBYTES * 4;
//            let mut vec = vec![0u8; len];
//            self.point.tobytes(&mut vec);
//            vec
//        }
    }

//    pub struct ProofOfPossession {
//        point: ECP
//    }
//
//    impl ProofOfPossession {
//        pub fn new(vk: &VerKey, sk: &SignKey) -> Self {
//            Bls::new_proof_of_possession(&vk, &sk)
//        }
//    }

    pub struct Signature {
        point: ECP
    }

    impl Signature {
        pub fn new() -> Self {
            let mut point = ECP::new();
            point.inf();
            Signature { point }
        }
    }

    impl fmt::Debug for Signature {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Signature {{ point: {} }}", self.point.to_hex())
        }
    }

    impl fmt::Display for Signature {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Signature {{ point: {} }}", self.point.to_hex())
        }
    }


    pub struct MultiSignature(Signature);

    impl MultiSignature {
//        pub fn new() -> Self {
//            MultiSignature(Signature::new())
//        }

        pub fn from_signatures(signatures: &[Signature]) -> Self {
            let mut asig = Signature::new();
            for sig in signatures {
                asig.point.add(&sig.point);
            }
            MultiSignature(asig)
        }

//        pub fn aggregate(&mut self, sig: &Signature) {
//            self.0.point.add(&sig.point);
//        }

        pub fn verify(&self, message: &[u8], g: &Generator, vks: &[VerKey]) -> bool {
            let mut aggregated_vk = ECP2::new();
            aggregated_vk.inf();
            for vk in vks {
                aggregated_vk.add(&vk.point);
            }
            let vk = VerKey { point: aggregated_vk };
            Bls::verify(message, g, &self.0, &vk)
        }
    }

    pub struct AggregatedSignature(Signature);

    impl AggregatedSignature {
        pub fn from_signatures(signatures: &[Signature]) -> Self {
            let mut asig = Signature::new();
            for sig in signatures {
                asig.point.add(&sig.point);
            }
            AggregatedSignature(asig)
        }

        pub fn verify(&self, g: &Generator, inputs: &[(&[u8], &VerKey)]) -> bool {
            let lhs = Bls::pair(&self.0.point, &g.point);

            let mut rhs = FP12::new();
            rhs.one();

            for input in inputs {
                let h = Bls::hash_message(input.0, SIGNATURE_CONTEXT);
                rhs.mul(&Bls::pair(&h, &input.1.point));
            }
            rhs.reduce();
            lhs == rhs
        }
    }

    pub struct Bls {}

    impl Bls {
//        pub fn new_proof_of_possession(vk: &VerKey, sk: &SignKey) -> ProofOfPossession {
//            let point = Bls::hash_message(vk.as_bytes().as_slice(), PROOF_OF_POSSESSION_CONTEXT);
//            let mut bn = sk.x;
//            ProofOfPossession {
//                point: g1mul(&point, &mut bn)
//            }
//        }

        pub fn sign(message: &[u8], sk: &SignKey) -> Signature {
            let point = Bls::hash_message(message, SIGNATURE_CONTEXT);
            let mut bn = sk.x;
            Signature {
                point: g1mul(&point, &mut bn)
            }
        }

        pub fn verify(message: &[u8], g: &Generator, signature: &Signature, vk: &VerKey) -> bool {
            let point = Bls::hash_message(message, SIGNATURE_CONTEXT);
            Bls::pair(&signature.point, &g.point).eq(&Bls::pair(&point, &vk.point))
        }

        pub fn hash_message(message: &[u8], ctx: u32) -> ECP {
            let mut blake = blake2::Blake2b::new();
            blake.input(u32_to_u8(ctx));
            blake.input(message);
            Bls::from_hash(blake.result().as_slice())
        }

        pub fn pair(p: &ECP, q: &ECP2) -> FP12 {
            let mut result = fexp(&ate(&q, &p));
            result.reduce();
            result
        }

        fn from_hash(hash: &[u8]) -> ECP {
            let mut vec = hash.to_vec();
            let len = vec.len();

            if len < MODBYTES {
                let diff = MODBYTES - len;
                let mut more = vec![0u8; diff];
                vec.append(&mut more);
            }

            let mut e = BIG::frombytes(vec.as_slice());
            let mut point = ECP::new_big(&e);

            while point.is_infinity() {
                e.inc(1);
                point = ECP::new_big(&e);
            }
            point
        }
    }
}

fn u32_to_u8(i: u32) -> [u8; 4] {
    [((i >> 24) as u8), ((i >> 16) as u8), ((i >> 8) as u8), i as u8]
}
