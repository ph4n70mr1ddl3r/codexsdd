use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar, SecretKey};
use rand::rngs::OsRng;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ElGamalCiphertext {
    c1: ProjectivePoint,
    c2: ProjectivePoint,
}

impl fmt::Display for ElGamalCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({}, {})",
            hex::encode(self.c1.to_bytes()),
            hex::encode(self.c2.to_bytes())
        )
    }
}

struct ElGamalKeyPair {
    public_key: ProjectivePoint,
    secret_key: SecretKey,
}

impl ElGamalKeyPair {
    fn generate() -> Self {
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = ProjectivePoint::GENERATOR * secret_key.to_nonzero_scalar().as_ref();
        Self {
            public_key,
            secret_key,
        }
    }
}

struct ElGamal {
    keypair: ElGamalKeyPair,
}

impl ElGamal {
    fn new() -> Self {
        Self {
            keypair: ElGamalKeyPair::generate(),
        }
    }

    fn encrypt(&self, message: &ProjectivePoint) -> ElGamalCiphertext {
        let random_scalar: Scalar = Scalar::random(&mut OsRng);
        let c1 = ProjectivePoint::GENERATOR * &random_scalar;
        let c2 = *message + (self.keypair.public_key * &random_scalar);
        ElGamalCiphertext { c1, c2 }
    }

    fn decrypt(&self, ciphertext: &ElGamalCiphertext) -> ProjectivePoint {
        let nonzero = self.keypair.secret_key.to_nonzero_scalar();
        let s = ciphertext.c1 * nonzero.as_ref();
        ciphertext.c2 - s
    }

    fn rerandomize(&self, ciphertext: &ElGamalCiphertext) -> ElGamalCiphertext {
        let random_scalar: Scalar = Scalar::random(&mut OsRng);
        let c1 = ciphertext.c1 + (ProjectivePoint::GENERATOR * &random_scalar);
        let c2 = ciphertext.c2 + (self.keypair.public_key * &random_scalar);
        ElGamalCiphertext { c1, c2 }
    }
}

fn main() {
    println!("=== ElGamal Encryption on Koblitz Curve (secp256k1) ===\n");

    let elgamal = ElGamal::new();

    let random_point: ProjectivePoint = ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng);

    println!("1. Generated random point P on curve:");
    println!("   P = {}", hex::encode(random_point.to_bytes()));

    println!("\n2. Encrypting P with ElGamal...");
    let ciphertext = elgamal.encrypt(&random_point);
    println!("   C1 = {}", hex::encode(ciphertext.c1.to_bytes()));
    println!("   C2 = {}", hex::encode(ciphertext.c2.to_bytes()));

    println!("\n3. Rerandomizing the encryption (multiple times)...");
    let mut rerandomized = ciphertext.clone();
    for i in 1..=3 {
        rerandomized = elgamal.rerandomize(&rerandomized);
        println!(
            "   Iteration {}: C1 = ...{}, C2 = ...{}",
            i,
            &hex::encode(rerandomized.c1.to_bytes())[56..],
            &hex::encode(rerandomized.c2.to_bytes())[56..]
        );
    }

    println!("\n4. Decrypting rerandomized ciphertext...");
    let decrypted = elgamal.decrypt(&rerandomized);
    println!("   Decrypted point = {}", hex::encode(decrypted.to_bytes()));

    println!("\n5. Verification:");
    if decrypted == random_point {
        println!("   ✓ SUCCESS: Decrypted point matches original!");
        println!("   ✓ Elliptic curve ElGamal with rerandomization works correctly.");
    } else {
        println!("   ✗ FAILURE: Points do not match!");
        println!("   Original:    {}", hex::encode(random_point.to_bytes()));
        println!("   Decrypted:   {}", hex::encode(decrypted.to_bytes()));
    }

    println!("\n=== Technical Notes ===");
    println!("• Koblitz curve (secp256k1) is a NIST-recommended elliptic curve");
    println!("• ElGamal encryption: C = (rG, M + rY) where Y is public key");
    println!("• Decryption: M = C2 - x*C1 where x is private key");
    println!("• Rerandomization: Add (sG, sY) for random s to get equivalent encryption");
    println!("• The rerandomized ciphertext looks completely different but decrypts to same M");
}
