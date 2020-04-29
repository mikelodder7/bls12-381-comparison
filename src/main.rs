use std::io::{self, Write};
use std::time::Instant;
use clap::{Arg, App};

fn main() {
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

    let iterations = matches.value_of("iterations").unwrap().parse::<usize>().expect("Unable to parse iterations argument");
    const MESSAGE: &[u8; 37] = b"This is a message that will be signed";

    // Make sure we get somewhat random data
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
    for key in &signkeys {
        verkeys.push(apache::VerKey::new(&key));
    }
    let start = Instant::now();
    for i in 0..iterations {
        let res = apache::Bls::verify(message, &signatures[i], &verkeys[i]);
        results.push(res);
    }
    let elapsed = Instant::now() - start;
    println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);
    assert!(results.iter().all(|t| *t));

    print!("Verifying - multisignature...");
    io::stdout().flush().unwrap();
    let start = Instant::now();
    let msig = apache::MultiSignature::from_signatures(signatures.as_slice());
    assert!(msig.verify(message, verkeys.as_slice()));
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
    assert!(asig.verify(inputs.as_slice()));
    let elapsed = Instant::now() - start;
    println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);
    println!("================================================================================");
}

fn run_librustzcash(iterations: usize, message: &[u8]) {
    use rand::prelude::*;
    use bls_sigs_ref::*;
    use pairing_plus::bls12_381::{G1, G2};
    use pairing_plus::hash_to_field::ExpandMsgXmd;

    const CSUITE: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    println!("================================================================================");
    println!("BLS ZCash pairing");
    println!("-----------------");
    let mut verkeys = Vec::with_capacity(iterations);
    let mut signatures = Vec::with_capacity(iterations);
    let mut signkeys = Vec::with_capacity(iterations);
    let mut rng = thread_rng();
    for _ in 0..iterations {
        let mut tk = [0u8; 32];
        rng.fill_bytes(&mut tk);
        let (sk, pk) = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::keygen(&tk[..]);
        signkeys.push(sk);
        verkeys.push(pk);
    }
    print!("Generating - {} signatures...", iterations);
    io::stdout().flush().unwrap();
    let start = Instant::now();
    for key in &signkeys {
        let x_prime = (*key).clone();
        let sig = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_sign(x_prime, message, CSUITE);
        signatures.push(sig);
    }
    let elapsed = Instant::now() - start;
    println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);

    print!("Verifying - {} signatures...", iterations);
    io::stdout().flush().unwrap();
    let mut results = Vec::with_capacity(iterations);
    let start = Instant::now();
    for i in 0..iterations {
        let res = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_verify(verkeys[i], signatures[i], message, CSUITE);
        results.push(res);
    }
    let elapsed = Instant::now() - start;
    println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);
    assert!(results.iter().all(|t| *t));

    print!("Verifying - multisignature...");
    io::stdout().flush().unwrap();
    let asig = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::aggregate(signatures.as_slice());
    let apk = <G2 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::aggregate(verkeys.as_slice());
    let start = Instant::now();
    assert!(<G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_verify(apk, asig, message, CSUITE));
    let elapsed = Instant::now() - start;
    println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);

    print!("Verifying - aggregated signature...");
    io::stdout().flush().unwrap();
    let mut messages = Vec::with_capacity(iterations);
    for i in 0..iterations {
        let msg = format!("Message {} {}", String::from_utf8(message.to_vec()).unwrap(), i);
        let x_prime = signkeys[i].clone();
        let signature = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_sign( x_prime,  &msg.as_bytes(), CSUITE);
        signatures[i] = signature;
        messages.push(msg);
    }
    let asig = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::aggregate(signatures.as_slice());
    <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_aggregate_verify(verkeys.as_slice(), messages.as_slice(), asig, CSUITE);
    assert!(<G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_aggregate_verify(verkeys.as_slice(), messages.as_slice(), asig, CSUITE));
    let elapsed = Instant::now() - start;
    println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);
    println!("================================================================================");
}

fn get_secret_okm() -> [u8; 48] {
    use rand::prelude::*;
    let mut rng = thread_rng();
    let mut ikm = [0u8; 33];
    let mut okm = [0u8; 48];
    rng.fill_bytes(&mut ikm);
    ikm[32] = 0;
    let salt = b"BLS-SIG-KEYGEN-SALT-";
    let info = [0u8, 48u8]; // I2OSP(L, 2)

    let h = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt[..]), &ikm);
    h.expand(&info[..], &mut okm).unwrap();
    okm
}

mod apache {
    use hash2curve::prelude::*;
    use amcl::bls381::rom::CURVE_ORDER;
    use amcl::bls381::big::BIG;
    use amcl::bls381::ecp::ECP;
    use amcl::bls381::ecp2::ECP2;
    use amcl::bls381::fp12::FP12;
    use amcl::bls381::pair::{g1mul, g2mul, ate, fexp};
    use amcl::arch::Chunk;
    use std::fmt;
    use crate::get_secret_okm;

    const SIGNATURE_CONTEXT: u32 = 1;
//    const PROOF_OF_POSSESSION_CONTEXT: u32 = 2;

    pub struct SignKey {
        pub x: BIG
    }

    impl SignKey {
        pub fn new() -> Self {
            let okm = get_secret_okm();

            let mut x = BIG::new();
            for b in okm.iter() {
                x.shl(8);
                x.w[0] += *b as Chunk;
            }
            x.rmod(&BIG { w: CURVE_ORDER });

            SignKey { x }
        }
    }

    pub struct VerKey {
        pub point: ECP2,
    }

    impl VerKey {
        pub fn new(sk: &SignKey) -> Self {
            let g = ECP2::generator();
            VerKey {
                point: g2mul(&g, &sk.x),
            }
        }

        // pub fn new_with_generator(g: &Generator, sk: &SignKey) -> Self {
        //     VerKey {
        //         point: g.point.mul(&sk.x)
        //     }
        // }

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

        pub fn verify(&self, message: &[u8], vks: &[VerKey]) -> bool {
            let mut aggregated_vk = ECP2::new();
            aggregated_vk.inf();
            for vk in vks {
                aggregated_vk.add(&vk.point);
            }
            let vk = VerKey { point: aggregated_vk };
            Bls::verify(message, &self.0, &vk)
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

        pub fn verify(&self, inputs: &[(&[u8], &VerKey)]) -> bool {
            let lhs = Bls::pair(&self.0.point, &ECP2::generator());

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

        pub fn verify(message: &[u8], signature: &Signature, vk: &VerKey) -> bool {
            let point = Bls::hash_message(message, SIGNATURE_CONTEXT);
            Bls::pair(&signature.point, &ECP2::generator()).eq(&Bls::pair(&point, &vk.point))
        }

        pub fn hash_message(message: &[u8], ctx: u32) -> ECP {
            let dst = DomainSeparationTag::new(&ctx.to_be_bytes()[..], None, None, None).unwrap();
            let hasher = Bls12381G1Sswu::new(dst);
            hasher.hash_to_curve_xmd::<sha2::Sha256>(message).unwrap().0
        }

        pub fn pair(p: &ECP, q: &ECP2) -> FP12 {
            let mut result = fexp(&ate(&q, &p));
            result.reduce();
            result
        }
    }
}
