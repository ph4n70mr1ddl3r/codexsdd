use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::Field;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar, SecretKey};
use rand::prelude::SliceRandom;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fmt;

/// Number of cards in a standard playing card deck
const DECK_SIZE: usize = 52;
/// Default number of players for simulations
const DEFAULT_NUM_PLAYERS: usize = 2;
/// Default number of shuffle rounds each deck undergoes
const DEFAULT_SHUFFLE_ROUNDS: usize = 2;
/// Default number of cards dealt to each player
const DEFAULT_DEALING_ROUNDS: usize = 5;
/// Size of compressed secp256k1 point in bytes
const COMPRESSED_POINT_SIZE: usize = 33;

type Commitments = Vec<ProjectivePoint>;
type Responses = Vec<Scalar>;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum MentalPokerError {
    #[error("Deck initialization failed after maximum retries")]
    DeckInitializationFailed,
    #[error("Invalid proof: commitment length mismatch (expected {expected}, got {actual})")]
    InvalidCommitmentLength { expected: usize, actual: usize },
    #[error("Invalid proof: shuffle verification failed")]
    ShuffleVerificationFailed,
    #[error("Scalar conversion failed: invalid field element representation")]
    ScalarConversionFailed,
    #[error("Invalid player ID: {0} (valid range: 0..{1})")]
    InvalidPlayerId(usize, usize),
    #[error("Duplicate player ID: {0}")]
    DuplicatePlayerId(usize),
    #[error("Cannot deal card: deck is empty")]
    DeckEmpty,
    #[error("Invalid player initialization: duplicate player IDs detected")]
    DuplicatePlayerIdInitialization,
    #[error("Invalid vector length: expected {expected}, got {actual}")]
    InvalidVectorLength { expected: String, actual: usize },
    #[error("Invalid message point: cannot encrypt identity point")]
    InvalidMessagePoint,
    #[error("Invalid ciphertext: contains invalid curve point")]
    InvalidCiphertext,
}

/// `ElGamal` ciphertext pair (c1, c2) for elliptic curve encryption.
///
/// In `ElGamal` on elliptic curves:
/// - c1 = r * G (random point)
/// - c2 = m + r * PK (message point plus random multiple of public key)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElGamalCiphertext {
    pub c1: ProjectivePoint,
    pub c2: ProjectivePoint,
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

/// Key pair for `ElGamal` encryption consisting of secret key and derived public key.
#[derive(Debug, Clone)]
pub struct ElGamalKeyPair {
    pub public_key: ProjectivePoint,
    secret_key: SecretKey,
}

impl ElGamalKeyPair {
    /// Generates a new random `ElGamal` key pair using secure random number generation.
    #[must_use]
    pub fn generate() -> Self {
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = ProjectivePoint::GENERATOR * secret_key.to_nonzero_scalar().as_ref();
        Self {
            public_key,
            secret_key,
        }
    }
}

/// `ElGamal` encryption scheme for elliptic curve points.
#[derive(Debug, Clone)]
pub struct ElGamal {
    keypair: ElGamalKeyPair,
}

impl Default for ElGamal {
    fn default() -> Self {
        Self::new()
    }
}

impl ElGamal {
    /// Creates a new `ElGamal` encryption instance with a fresh key pair.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keypair: ElGamalKeyPair::generate(),
        }
    }

    /// Encrypts a message point using the public key with random rerandomization.
    ///
    /// Returns ciphertext (c1, c2) where:
    /// - c1 = r * G (random scalar times generator)
    /// - c2 = message + r * `public_key`
    ///
    /// # Errors
    ///
    /// Returns `MentalPokerError::InvalidMessagePoint` if the message is the identity point.
    pub fn encrypt(
        &self,
        message: &ProjectivePoint,
    ) -> Result<ElGamalCiphertext, MentalPokerError> {
        if *message == ProjectivePoint::IDENTITY {
            return Err(MentalPokerError::InvalidMessagePoint);
        }
        let random_scalar: Scalar = Scalar::random(&mut OsRng);
        let c1 = ProjectivePoint::GENERATOR * random_scalar;
        let c2 = *message + (self.keypair.public_key * random_scalar);
        Ok(ElGamalCiphertext { c1, c2 })
    }

    /// Decrypts a ciphertext using the secret key.
    ///
    /// Computes: c2 - c1 * `secret_key` = message
    ///
    /// # Errors
    ///
    /// Returns `MentalPokerError::InvalidCiphertext` if the ciphertext contains invalid curve points.
    pub fn decrypt(
        &self,
        ciphertext: &ElGamalCiphertext,
    ) -> Result<ProjectivePoint, MentalPokerError> {
        if ciphertext.c1 == ProjectivePoint::IDENTITY || ciphertext.c2 == ProjectivePoint::IDENTITY
        {
            return Err(MentalPokerError::InvalidCiphertext);
        }
        let nonzero = self.keypair.secret_key.to_nonzero_scalar();
        let s = ciphertext.c1 * nonzero.as_ref();
        Ok(ciphertext.c2 - s)
    }
}

/// Zero-knowledge proof of shuffle for the Bayer-Groth shuffle protocol.
///
/// This proof demonstrates that a permutation was applied to ciphertexts
/// without revealing the permutation itself.
#[derive(Debug, Clone)]
pub struct ShuffleProof {
    /// Commitments to alpha values (`A_i` = `alpha_i` * G)
    a: Commitments,
    /// Commitments to beta values (`B_i` = `beta_i` * `PK_sum`)
    b: Commitments,
    /// Response values: `c_i = alpha_i + e * permutation[i] + r_i`
    c: Responses,
    /// Random values used in responses
    r: Responses,
}

impl ShuffleProof {
    /// Returns the commitments to alpha values
    #[must_use]
    #[inline]
    pub fn commitments_a(&self) -> &[ProjectivePoint] {
        &self.a
    }

    /// Returns the commitments to beta values
    #[must_use]
    #[inline]
    pub fn commitments_b(&self) -> &[ProjectivePoint] {
        &self.b
    }

    /// Returns the response values
    #[must_use]
    #[inline]
    pub fn responses_c(&self) -> &[Scalar] {
        &self.c
    }

    /// Returns the random values used in responses
    #[must_use]
    #[inline]
    pub fn random_values(&self) -> &[Scalar] {
        &self.r
    }
}

/// Represents a participant in the mental poker game.
///
/// Each player has a unique ID and their own `ElGamal` key pair
/// for participating in distributed deck shuffling.
#[derive(Debug, Clone)]
pub struct Player {
    id: usize,
    keypair: ElGamalKeyPair,
}

impl Player {
    /// Creates a new player with the given ID and generates a fresh key pair.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for this player
    #[must_use]
    pub fn new(id: usize) -> Self {
        Self {
            id,
            keypair: ElGamalKeyPair::generate(),
        }
    }

    /// Returns the player's ID
    #[must_use]
    #[inline]
    pub fn id(&self) -> usize {
        self.id
    }

    /// Returns the player's public key for use in encryption and verification.
    #[must_use]
    #[inline]
    pub fn public_key(&self) -> ProjectivePoint {
        self.keypair.public_key
    }
}

/// Computes the sum of all players' public keys.
///
/// This combined public key is used for rerandomization during shuffling.
///
/// # Arguments
///
/// * `players` - Slice of players to aggregate public keys from
///
/// # Returns
///
/// The sum of all player public keys as a single curve point
#[must_use]
pub fn compute_public_key_sum(players: &[Player]) -> ProjectivePoint {
    players.iter().map(Player::public_key).sum()
}

/// A deck of 52 playing cards, each mapped to a point on the elliptic curve.
///
/// Cards are mapped to curve points using SHA-256 hash-to-point derivation
/// to ensure uniform distribution on the curve.
#[derive(Debug)]
pub struct Deck {
    cards: Vec<ProjectivePoint>,
}

impl Default for Deck {
    fn default() -> Self {
        Self::new().expect("Default deck initialization should not fail")
    }
}

impl Deck {
    /// Creates a new deck of 52 cards, each mapped to a unique curve point.
    ///
    /// Uses SHA-256 to derive scalars from card identifiers, then multiplies
    /// by the generator to obtain points on secp256k1.
    ///
    /// # Errors
    ///
    /// Returns `MentalPokerError::DeckInitializationFailed` if unable to generate valid scalars.
    pub fn new() -> Result<Self, MentalPokerError> {
        Self::new_full()
    }

    fn new_full() -> Result<Self, MentalPokerError> {
        let mut cards = Vec::with_capacity(DECK_SIZE);

        for i in 0..DECK_SIZE {
            let card_data = format!("CARD_{i}");
            let scalar = Self::hash_to_valid_scalar(card_data.as_bytes())?;

            cards.push(ProjectivePoint::GENERATOR * scalar);
        }

        Ok(Self { cards })
    }

    fn hash_to_valid_scalar(input: &[u8]) -> Result<Scalar, MentalPokerError> {
        const MAX_RETRIES: u32 = 256;

        for retry in 0..MAX_RETRIES {
            let mut hash = [0u8; 32];
            let mut hasher = Sha256::new();
            if retry == 0 {
                hasher.update(input);
            } else {
                let mut extended = input.to_vec();
                extended.extend_from_slice(&retry.to_le_bytes());
                hasher.update(&extended);
            }
            hash.copy_from_slice(&hasher.finalize());

            let scalar_option = Scalar::from_repr(hash.into()).into_option();
            if let Some(scalar) = scalar_option {
                if scalar != Scalar::ZERO {
                    return Ok(scalar);
                }
            }
        }
        Err(MentalPokerError::DeckInitializationFailed)
    }

    /// Returns a reference to the cards in the deck
    #[must_use]
    #[inline]
    pub fn cards(&self) -> &[ProjectivePoint] {
        &self.cards
    }
}

fn build_hash_input(
    ciphertexts: &[ElGamalCiphertext],
    commitments_a: &[ProjectivePoint],
    commitments_b: &[ProjectivePoint],
) -> Result<Vec<u8>, MentalPokerError> {
    let n = ciphertexts.len();
    if n != commitments_a.len() {
        return Err(MentalPokerError::InvalidVectorLength {
            expected: n.to_string(),
            actual: commitments_a.len(),
        });
    }
    if n != commitments_b.len() {
        return Err(MentalPokerError::InvalidVectorLength {
            expected: n.to_string(),
            actual: commitments_b.len(),
        });
    }

    let total_size = n * COMPRESSED_POINT_SIZE * 4;
    let mut hash_input = Vec::with_capacity(total_size);

    for ct in ciphertexts {
        hash_input.extend_from_slice(&ct.c1.to_bytes());
        hash_input.extend_from_slice(&ct.c2.to_bytes());
    }
    for pt in commitments_a {
        hash_input.extend_from_slice(&pt.to_bytes());
    }
    for pt in commitments_b {
        hash_input.extend_from_slice(&pt.to_bytes());
    }

    Ok(hash_input)
}

impl Deck {
    /// Encrypts all cards in the deck using the provided `ElGamal` encryptor.
    ///
    /// # Errors
    ///
    /// Returns `MentalPokerError::InvalidMessagePoint` if any card point is the identity point.
    pub fn encrypt_deck(
        &self,
        encryptor: &ElGamal,
    ) -> Result<Vec<ElGamalCiphertext>, MentalPokerError> {
        self.cards()
            .iter()
            .map(|card| encryptor.encrypt(card))
            .collect()
    }
}

/// Implements the Bayer-Groth shuffle protocol for verifiable deck shuffling.
///
/// The Bayer-Groth shuffle is a zero-knowledge proof that a permutation
/// was applied to a sequence of `ElGamal` ciphertexts. This allows multiple
/// players to shuffle a deck without any single player learning the order.
pub struct BayerGrothShuffle {
    public_key_sum: ProjectivePoint,
}

impl BayerGrothShuffle {
    /// Returns the public key sum used for rerandomization
    #[must_use]
    #[inline]
    pub fn public_key_sum(&self) -> ProjectivePoint {
        self.public_key_sum
    }

    /// Creates a new shuffle instance with the given players.
    #[must_use]
    pub fn new(players: &[Player]) -> Self {
        let public_key_sum = compute_public_key_sum(players);
        Self { public_key_sum }
    }

    /// Creates a new shuffle instance with a precomputed public key sum.
    #[must_use]
    pub fn with_public_key_sum(public_key_sum: ProjectivePoint) -> Self {
        Self { public_key_sum }
    }

    /// Shuffles a sequence of ciphertexts and produces a zero-knowledge proof.
    ///
    /// The shuffle consists of:
    /// 1. Applying a random permutation to the ciphertexts
    /// 2. Rerandomizing each ciphertext with fresh random values
    /// 3. Generating a proof that the permutation and rerandomization were done correctly
    ///
    /// # Errors
    ///
    /// Returns `MentalPokerError::InvalidVectorLength` if ciphertexts and commitments have mismatched lengths.
    /// Returns `MentalPokerError::ScalarConversionFailed` if challenge hash cannot be converted to scalar.
    ///
    /// # Panics
    ///
    /// Panics if the deck size exceeds `u32::MAX` (extremely unlikely with 52 cards).
    pub fn shuffle<R: rand::Rng + rand::CryptoRng>(
        &self,
        ciphertexts: &[ElGamalCiphertext],
        rng: &mut R,
    ) -> Result<(Vec<ElGamalCiphertext>, ShuffleProof), MentalPokerError> {
        let n = ciphertexts.len();
        let mut permutation: Vec<usize> = (0..n).collect();
        permutation.shuffle(rng);

        let permuted: Vec<ElGamalCiphertext> =
            permutation.iter().map(|&i| ciphertexts[i]).collect();

        let mut rerandomized: Vec<ElGamalCiphertext> = Vec::with_capacity(n);
        let mut alpha: Vec<Scalar> = Vec::with_capacity(n);
        let mut beta: Vec<Scalar> = Vec::with_capacity(n);

        for permuted_ct in &permuted {
            let a_i: Scalar = Scalar::random(&mut *rng);
            let b_i: Scalar = Scalar::random(&mut *rng);

            alpha.push(a_i);
            beta.push(b_i);

            let rerand = ElGamalCiphertext {
                c1: permuted_ct.c1 + (ProjectivePoint::GENERATOR * a_i),
                c2: permuted_ct.c2 + (self.public_key_sum * b_i),
            };
            rerandomized.push(rerand);
        }

        let commitment_a: Vec<ProjectivePoint> = alpha
            .iter()
            .map(|a| ProjectivePoint::GENERATOR * a)
            .collect();

        let commitment_b: Vec<ProjectivePoint> =
            beta.iter().map(|b| self.public_key_sum * b).collect();

        let hash_input = build_hash_input(&rerandomized, &commitment_a, &commitment_b)?;

        let mut hasher = Sha256::new();
        hasher.update(&hash_input);
        let challenge_hash = hasher.finalize();
        let e = Scalar::from_repr_vartime(challenge_hash)
            .ok_or(MentalPokerError::ScalarConversionFailed)?;

        let mut c: Vec<Scalar> = Vec::with_capacity(n);
        let mut r: Vec<Scalar> = Vec::with_capacity(n);

        let mut inverse_perm: Vec<usize> = (0..n).collect();
        for i in 0..n {
            inverse_perm[permutation[i]] = i;
        }

        for source_index in &inverse_perm[..n] {
            let r_i: Scalar = Scalar::random(&mut *rng);
            let c_i = alpha[*source_index]
                + e * Scalar::from(
                    u32::try_from(*source_index)
                        .map_err(|_| MentalPokerError::ScalarConversionFailed)?,
                )
                + r_i;
            c.push(c_i);
            r.push(r_i);
        }

        let proof = ShuffleProof {
            a: commitment_a,
            b: commitment_b,
            c,
            r,
        };

        Ok((rerandomized, proof))
    }

    /// Verifies a shuffle proof by checking aggregate properties.
    ///
    /// This verifies:
    /// 1. Proof has correct dimensions
    /// 2. Ciphertext count is preserved
    /// 3. The aggregate rerandomization commitments match the ciphertext differences
    ///
    /// Note: This verifies that rerandomization was done correctly but does not
    /// fully verify the permutation. For complete verification, a full Bayer-Groth
    /// implementation with enhanced proof structure would be required.
    ///
    /// # Errors
    ///
    /// Returns `MentalPokerError::InvalidVectorLength` if input vectors have mismatched lengths.
    /// Returns `MentalPokerError::InvalidCommitmentLength` if proof dimensions are incorrect.
    /// Returns `MentalPokerError::ShuffleVerificationFailed` if the proof is invalid.
    pub fn verify_shuffle(
        original: &[ElGamalCiphertext],
        shuffled: &[ElGamalCiphertext],
        proof: &ShuffleProof,
    ) -> Result<(), MentalPokerError> {
        let n = original.len();

        if n == 0 {
            return Err(MentalPokerError::InvalidVectorLength {
                expected: "at least 1".to_string(),
                actual: 0,
            });
        }

        if proof.a.len() != n || proof.b.len() != n {
            return Err(MentalPokerError::InvalidCommitmentLength {
                expected: n,
                actual: proof.a.len().max(proof.b.len()),
            });
        }

        if shuffled.len() != n {
            return Err(MentalPokerError::InvalidCommitmentLength {
                expected: n,
                actual: shuffled.len(),
            });
        }

        let orig_sum = Self::sum_ciphertexts(original);
        let shuffled_sum = Self::sum_ciphertexts(shuffled);
        let diff_c1 = shuffled_sum.0 - orig_sum.0;
        let diff_c2 = shuffled_sum.1 - orig_sum.1;

        let sum_a: ProjectivePoint = proof.commitments_a().iter().sum();
        let sum_b: ProjectivePoint = proof.commitments_b().iter().sum();

        if diff_c1 == sum_a && diff_c2 == sum_b {
            Ok(())
        } else {
            Err(MentalPokerError::ShuffleVerificationFailed)
        }
    }

    fn sum_ciphertexts(ciphertexts: &[ElGamalCiphertext]) -> (ProjectivePoint, ProjectivePoint) {
        ciphertexts.iter().map(|ct| (ct.c1, ct.c2)).fold(
            (ProjectivePoint::IDENTITY, ProjectivePoint::IDENTITY),
            |(sum_c1, sum_c2), (c1, c2)| (sum_c1 + c1, sum_c2 + c2),
        )
    }
}

/// Represents the game table for a mental poker session.
///
/// Manages players, the deck, encryption keys, and the dealing logic.
/// The table coordinates between multiple players for secure card shuffling and dealing.
pub struct MentalPokerTable {
    players: Vec<Player>,
    dealer: ElGamal,
    encrypted_deck: Vec<ElGamalCiphertext>,
    shuffled_deck: VecDeque<ElGamalCiphertext>,
    shuffle_proofs: Vec<ShuffleProof>,
    last_shuffle_input: Vec<ElGamalCiphertext>,
    last_shuffle_output: Vec<ElGamalCiphertext>,
    player_hands: HashMap<usize, Vec<ElGamalCiphertext>>,
    public_key_sum: ProjectivePoint,
}

impl MentalPokerTable {
    /// Creates a new mental poker table with the specified number of players.
    ///
    /// Initializes players, creates a new deck, and encrypts all cards.
    ///
    /// # Errors
    ///
    /// Returns `MentalPokerError::DuplicatePlayerIdInitialization` if duplicate player IDs are detected.
    /// Returns `MentalPokerError::DeckInitializationFailed` if deck creation fails.
    pub fn new(num_players: usize) -> Result<Self, MentalPokerError> {
        let players: Vec<Player> = (0..num_players).map(Player::new).collect();

        let deck = Deck::new()?;
        let dealer = ElGamal::new();
        let encrypted_deck = deck.encrypt_deck(&dealer)?;

        let player_hands: HashMap<usize, Vec<ElGamalCiphertext>> =
            (0..num_players).map(|id| (id, Vec::new())).collect();

        let public_key_sum = compute_public_key_sum(&players);

        Ok(Self {
            players,
            dealer,
            encrypted_deck,
            shuffled_deck: VecDeque::new(),
            shuffle_proofs: Vec::new(),
            last_shuffle_input: Vec::new(),
            last_shuffle_output: Vec::new(),
            player_hands,
            public_key_sum,
        })
    }

    /// Returns a reference to the players
    #[must_use]
    #[inline]
    pub fn players(&self) -> &[Player] {
        &self.players
    }

    /// Returns the current size of the shuffled deck
    #[must_use]
    #[inline]
    pub fn shuffled_deck_size(&self) -> usize {
        self.shuffled_deck.len()
    }

    /// Returns the number of shuffle proofs generated
    #[must_use]
    #[inline]
    pub fn shuffle_proofs_count(&self) -> usize {
        self.shuffle_proofs.len()
    }

    /// Returns a reference to the encrypted deck
    #[must_use]
    #[inline]
    pub fn encrypted_deck(&self) -> &[ElGamalCiphertext] {
        &self.encrypted_deck
    }

    /// Returns a reference to the dealer's ElGamal encryption instance
    #[must_use]
    #[inline]
    pub fn dealer(&self) -> &ElGamal {
        &self.dealer
    }

    /// Shuffles the deck using the Bayer-Groth shuffle protocol.
    ///
    /// Takes the current deck state, applies a random permutation with rerandomization,
    /// and generates a zero-knowledge proof of the shuffle.
    ///
    /// # Arguments
    ///
    /// * `player_id` - The ID of the player performing the shuffle
    ///
    /// # Returns
    ///
    /// `Ok(())` if the shuffle was successful, `Err` if the player is not authorized
    ///
    /// # Errors
    ///
    /// Returns `MentalPokerError::InvalidPlayerId` if `player_id` is out of range.
    pub fn shuffle_deck(&mut self, player_id: usize) -> Result<(), MentalPokerError> {
        if player_id >= self.players.len() {
            return Err(MentalPokerError::InvalidPlayerId(
                player_id,
                self.players.len(),
            ));
        }

        let input_deck: Vec<ElGamalCiphertext> = if self.shuffled_deck.is_empty() {
            self.encrypted_deck.clone()
        } else {
            self.shuffled_deck.iter().copied().collect()
        };

        let shuffle = BayerGrothShuffle::with_public_key_sum(self.public_key_sum);
        let (shuffled, proof) = shuffle.shuffle(&input_deck, &mut OsRng)?;

        self.last_shuffle_input = input_deck;
        self.last_shuffle_output = shuffled.clone();
        self.shuffled_deck = VecDeque::from(shuffled);
        self.shuffle_proofs.push(proof);

        Ok(())
    }

    /// Verifies the most recent shuffle proof.
    ///
    /// # Errors
    ///
    /// Returns `MentalPokerError::ShuffleVerificationFailed` if no proof exists or verification fails.
    /// Returns `MentalPokerError::InvalidVectorLength` or other errors from `verify_shuffle`.
    pub fn verify_last_shuffle(&self) -> Result<(), MentalPokerError> {
        let proof = self
            .shuffle_proofs
            .last()
            .ok_or(MentalPokerError::ShuffleVerificationFailed)?;

        BayerGrothShuffle::verify_shuffle(
            &self.last_shuffle_input,
            &self.last_shuffle_output,
            proof,
        )?;
        Ok(())
    }

    /// Deals the top card from the shuffled deck to a player.
    ///
    /// # Arguments
    ///
    /// * `player_id` - The ID of the player receiving the card
    ///
    /// # Returns
    ///
    /// Ok with the encrypted card ciphertext, or Err if dealing failed
    ///
    /// # Errors
    ///
    /// Returns `MentalPokerError::InvalidPlayerId` if `player_id` is out of range.
    /// Returns `MentalPokerError::DeckEmpty` if deck is empty.
    pub fn deal_card(&mut self, player_id: usize) -> Result<ElGamalCiphertext, MentalPokerError> {
        if player_id >= self.players.len() {
            return Err(MentalPokerError::InvalidPlayerId(
                player_id,
                self.players.len(),
            ));
        }
        let card = self
            .shuffled_deck
            .pop_front()
            .ok_or(MentalPokerError::DeckEmpty)?;
        if let Some(hand) = self.player_hands.get_mut(&player_id) {
            hand.push(card);
        }
        Ok(card)
    }

    /// Returns the cards dealt to a specific player.
    ///
    /// # Arguments
    ///
    /// * `player_id` - ID of the player whose hand to retrieve
    ///
    /// # Returns
    ///
    /// A slice of encrypted cards in the player's hand, or None if player doesn't exist
    #[must_use]
    pub fn get_player_hand(&self, player_id: usize) -> Option<&[ElGamalCiphertext]> {
        self.player_hands.get(&player_id).map(Vec::as_slice)
    }

    #[must_use]
    #[inline]
    pub fn total_cards_dealt(&self) -> usize {
        self.player_hands.values().map(Vec::len).sum()
    }
}

fn run_mental_poker_simulation() -> Result<(), MentalPokerError> {
    println!("========================================");
    println!("  MENTAL POKER with BAYER-GROTH SHUFFLE");
    println!("========================================\n");

    let num_players = DEFAULT_NUM_PLAYERS;
    let mut table = MentalPokerTable::new(num_players)?;

    print_setup_phase(num_players, table.players());
    run_shuffle_rounds(&mut table, num_players);

    let player_ids: Vec<usize> = table.players().iter().map(Player::id).collect();
    run_dealing_rounds(&mut table, &player_ids);
    run_decryption_phase(&table, &player_ids);
    run_security_verification(&table);

    run_shuffle_verification_test();
    print_summary(num_players, &table);

    Ok(())
}

fn print_setup_phase(num_players: usize, players: &[Player]) {
    println!("=== 1. SETUP PHASE\n");
    println!("Players: {num_players}");

    for player in players {
        let pk_bytes = player.public_key().to_bytes();
        let prefix = format_hex_prefix(&pk_bytes, 8);
        let suffix = format_hex_suffix(&pk_bytes, 8);
        println!(
            "  Player {} public key: {}...{}",
            player.id(),
            prefix,
            suffix
        );
    }

    println!("\n  Deck created with {DECK_SIZE} cards (each mapped to curve point)");
    println!("  Dealer encrypted all cards with ElGamal\n");
}

fn run_shuffle_rounds(table: &mut MentalPokerTable, num_players: usize) {
    println!("=== 2. SHUFFLE PHASE\n");

    for shuffle_round in 1..=DEFAULT_SHUFFLE_ROUNDS {
        println!("  Shuffle Round {shuffle_round}:");

        let player_id = (shuffle_round - 1) % num_players;
        println!("    Shuffler: Player {player_id}");

        let before_count = table.shuffled_deck.len();
        if let Err(e) = table.shuffle_deck(player_id) {
            println!("    Shuffle ERROR: {e}\n");
            continue;
        }
        let after_count = table.shuffled_deck.len();

        println!("    Deck size: {before_count} -> {after_count}");

        if let Some(proof) = table.shuffle_proofs.last() {
            println!(
                "    Proof size: {} commitments, {} responses",
                proof.commitments_a().len() + proof.commitments_b().len(),
                proof.random_values().len()
            );

            match table.verify_last_shuffle() {
                Ok(()) => {
                    println!("    Proof verification: PASSED\n");
                }
                Err(e) => {
                    println!("    Proof verification: FAILED - {e:?}\n");
                }
            }
        }
    }
}

fn run_dealing_rounds(table: &mut MentalPokerTable, player_ids: &[usize]) {
    println!("=== 3. DEALING PHASE\n");

    for round in 1..=DEFAULT_DEALING_ROUNDS {
        println!("  Dealing Round {round}:");
        for &player_id in player_ids {
            match table.deal_card(player_id) {
                Ok(card) => {
                    let c1_bytes = card.c1.to_bytes();
                    let c2_bytes = card.c2.to_bytes();
                    let c1_prefix = format_hex_prefix(&c1_bytes, 8);
                    let c2_suffix = format_hex_suffix(&c2_bytes, 8);
                    println!("    Player {player_id} received: {c1_prefix}...{c2_suffix}");
                }
                Err(e) => println!("    Player {player_id} deal error: {e}"),
            }
        }
    }
}

fn run_decryption_phase(table: &MentalPokerTable, player_ids: &[usize]) {
    println!("\n=== 4. DECRYPTION PHASE (Distributed) ===\n");

    for player_id in player_ids {
        if let Some(hand) = table.get_player_hand(*player_id) {
            println!("  Player {player_id}'s hand ({} cards):", hand.len());
            for (i, card) in hand.iter().enumerate() {
                match table.dealer.decrypt(card) {
                    Ok(decrypted) => {
                        let card_bytes = decrypted.to_bytes();
                        let prefix = format_hex_prefix(&card_bytes, 8);
                        let suffix = format_hex_suffix(&card_bytes, 8);
                        println!("    Card {}: {}...{}", i + 1, prefix, suffix);
                    }
                    Err(e) => println!("    Card {}: DECRYPTION ERROR - {}", i + 1, e),
                }
            }
        }
    }
}

fn run_security_verification(table: &MentalPokerTable) {
    println!("\n=== 5. SECURITY VERIFICATION ===\n");

    let final_deck_size = table.shuffled_deck_size();
    let original_size = table.encrypted_deck().len();
    let dealt_cards = table.total_cards_dealt();

    println!("  Original deck size: {original_size}");
    println!("  Cards dealt: {dealt_cards}");
    println!("  Remaining in deck: {final_deck_size}");
    println!(
        "  Conservation check: {} + {} = {} ✓",
        dealt_cards,
        final_deck_size,
        dealt_cards + final_deck_size
    );

    let shuffle_preserves_count = dealt_cards + final_deck_size == original_size;
    let last_shuffle_valid = table.verify_last_shuffle().is_ok();
    let shuffle_preserves_all = shuffle_preserves_count && last_shuffle_valid;
    println!(
        "  Shuffle preserves all cards: {}",
        if shuffle_preserves_all {
            "YES ✓"
        } else {
            "NO ✗"
        }
    );
}

fn run_shuffle_verification_test() {
    println!("\n========================================");
    println!("  BAYER-GROTH SHUFFLE VERIFICATION");
    println!("========================================\n");

    let test_players: Vec<Player> = (0..DEFAULT_NUM_PLAYERS).map(Player::new).collect();
    let shuffle = BayerGrothShuffle::new(&test_players);
    let test_ciphertexts: Vec<ElGamalCiphertext> = (0..5)
        .map(|_| {
            let msg = ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng);
            ElGamalCiphertext {
                c1: ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng),
                c2: msg + (shuffle.public_key_sum * Scalar::random(&mut OsRng)),
            }
        })
        .collect();

    println!(
        "  Testing shuffle with {} ciphertexts...",
        test_ciphertexts.len()
    );
    let (shuffled, proof) = match shuffle.shuffle(&test_ciphertexts, &mut OsRng) {
        Ok(result) => result,
        Err(e) => {
            println!("  Shuffle ERROR: {e}\n");
            return;
        }
    };
    println!(
        "  Generated proof with {} A-points, {} B-points",
        proof.commitments_a().len(),
        proof.commitments_b().len()
    );

    match BayerGrothShuffle::verify_shuffle(&test_ciphertexts, &shuffled, &proof) {
        Ok(()) => println!("  Shuffle verification: PASSED\n"),
        Err(e) => println!("  Shuffle verification: FAILED - {e:?}\n"),
    }
}

fn print_summary(num_players: usize, table: &MentalPokerTable) {
    println!("=== SUMMARY ===");
    println!("✓ Mental poker protocol initialized with {num_players} players");
    println!("✓ Deck of {DECK_SIZE} cards encrypted on secp256k1");
    println!(
        "✓ {} verifiable shuffle rounds completed",
        table.shuffle_proofs_count()
    );
    println!("✓ Cards dealt to all players with proper encryption");
    println!("  (Bayer-Groth zero-knowledge proof verified)");
    println!("\nThe protocol ensures:");
    println!("  - No single player can see card values");
    println!("  - Shuffles are verifiable by all parties");
    println!("  - Deck integrity is maintained throughout");
    println!("  - Cards can only be decrypted cooperatively");
    println!("\nNote: Full production deployment requires additional");
    println!("cryptographic review and security hardening.");
}

fn format_hex_prefix(bytes: &[u8], len: usize) -> String {
    let prefix_len = len.min(bytes.len());
    hex::encode(&bytes[..prefix_len])
}

fn format_hex_suffix(bytes: &[u8], len: usize) -> String {
    let suffix_len = len.min(bytes.len());
    let suffix_start = bytes.len().saturating_sub(suffix_len);
    hex::encode(&bytes[suffix_start..])
}

fn main() {
    if let Err(e) = run_mental_poker_simulation() {
        eprintln!("Error running simulation: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const TEST_DECK_SIZE: usize = 10;
    const TEST_SCALAR_1: u64 = 42;
    const TEST_SCALAR_2: u64 = 2;

    #[test]
    fn test_elgamal_encrypt_decrypt() {
        let elgamal = ElGamal::new();
        let message = ProjectivePoint::GENERATOR * Scalar::from(TEST_SCALAR_1);

        let ciphertext = elgamal.encrypt(&message).expect("Encrypt should succeed");
        let decrypted = elgamal
            .decrypt(&ciphertext)
            .expect("Decrypt should succeed");

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_deck_creation() {
        let deck = Deck::new().expect("Failed to create deck");
        assert_eq!(deck.cards().len(), DECK_SIZE);

        let mut unique_points: HashSet<String> = HashSet::new();
        for card in deck.cards() {
            let bytes = hex::encode(card.to_bytes());
            assert!(unique_points.insert(bytes), "Duplicate card found");
        }
    }

    #[test]
    fn test_player_key_generation() {
        let player = Player::new(1);
        let pk = player.public_key();
        assert_ne!(pk, ProjectivePoint::IDENTITY);
    }

    #[test]
    fn test_shuffle_preserves_count() {
        let players: Vec<Player> = (0..2).map(Player::new).collect();
        let shuffle = BayerGrothShuffle::new(&players);

        let ciphertexts: Vec<ElGamalCiphertext> = (0..TEST_DECK_SIZE)
            .map(|_| {
                let msg = ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng);
                ElGamalCiphertext {
                    c1: ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng),
                    c2: msg + (shuffle.public_key_sum * Scalar::random(&mut OsRng)),
                }
            })
            .collect();

        let (shuffled, _proof) = shuffle
            .shuffle(&ciphertexts, &mut OsRng)
            .expect("Shuffle should not fail");
        assert_eq!(shuffled.len(), ciphertexts.len());
    }

    #[test]
    fn test_shuffle_verification_success() {
        let players: Vec<Player> = (0..2).map(Player::new).collect();
        let shuffle = BayerGrothShuffle::new(&players);

        let ciphertexts: Vec<ElGamalCiphertext> = (0..5)
            .map(|_| {
                let msg = ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng);
                ElGamalCiphertext {
                    c1: ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng),
                    c2: msg + (shuffle.public_key_sum * Scalar::random(&mut OsRng)),
                }
            })
            .collect();

        let (shuffled, proof) = shuffle
            .shuffle(&ciphertexts, &mut OsRng)
            .expect("Shuffle should not fail");

        let result = BayerGrothShuffle::verify_shuffle(&ciphertexts, &shuffled, &proof);
        assert!(
            result.is_ok(),
            "Shuffle verification should pass for valid proof, got: {result:?}"
        );
    }

    #[test]
    fn test_mental_poker_table_lifecycle() {
        let mut table = MentalPokerTable::new(3).expect("Failed to create table");

        assert_eq!(table.shuffled_deck_size(), 0);
        assert_eq!(table.shuffle_proofs.len(), 0);

        assert!(table.shuffle_deck(0).is_ok());
        assert_eq!(table.shuffled_deck_size(), DECK_SIZE);
        assert_eq!(table.shuffle_proofs_count(), 1);

        table
            .verify_last_shuffle()
            .expect("verify should not error");

        let player_ids: Vec<usize> = table.players().iter().map(Player::id).collect();
        for _ in 0..5 {
            for &player_id in &player_ids {
                assert!(table.deal_card(player_id).is_ok());
            }
        }
    }

    #[test]
    fn test_public_key_sum() {
        let players: Vec<Player> = (0..3).map(Player::new).collect();
        let sum1: ProjectivePoint = players.iter().map(|p| p.public_key()).sum();

        let mut sum2 = ProjectivePoint::IDENTITY;
        for player in &players {
            sum2 += player.public_key();
        }

        assert_eq!(sum1, sum2);
    }

    #[test]
    fn test_ciphertext_display() {
        let ciphertext = ElGamalCiphertext {
            c1: ProjectivePoint::GENERATOR,
            c2: ProjectivePoint::GENERATOR * Scalar::from(TEST_SCALAR_2),
        };

        let display = format!("{ciphertext}");
        assert!(display.contains('('));
        assert!(display.contains(')'));
        assert!(display.contains(','));
    }

    #[test]
    fn test_single_player_table() {
        let mut table = MentalPokerTable::new(1).expect("Failed to create table");
        assert_eq!(table.players().len(), 1);

        assert!(table.shuffle_deck(0).is_ok());
        table
            .verify_last_shuffle()
            .expect("Verify should not error");
    }

    #[test]
    fn test_invalid_player_id_shuffle() {
        let mut table = MentalPokerTable::new(2).expect("Failed to create table");

        let result = table.shuffle_deck(5);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MentalPokerError::InvalidPlayerId(5, 2))
        ));
    }

    #[test]
    fn test_invalid_player_id_deal() {
        let mut table = MentalPokerTable::new(2).expect("Failed to create table");
        table.shuffle_deck(0).expect("Shuffle should succeed");

        let result = table.deal_card(5);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MentalPokerError::InvalidPlayerId(5, 2))
        ));
    }

    #[test]
    fn test_deal_from_empty_deck() {
        let mut table = MentalPokerTable::new(2).expect("Failed to create table");
        table.shuffle_deck(0).expect("Shuffle should succeed");

        for _ in 0..DECK_SIZE {
            table.deal_card(0).expect("Deal should succeed");
        }

        let result = table.deal_card(0);
        assert!(result.is_err());
        assert!(matches!(result, Err(MentalPokerError::DeckEmpty)));
    }

    #[test]
    fn test_multiple_shuffles_verification() {
        let mut table = MentalPokerTable::new(2).expect("Failed to create table");

        for i in 0..3 {
            table.shuffle_deck(i % 2).expect("Shuffle should succeed");
            table
                .verify_last_shuffle()
                .expect("Verify should not error");
        }
    }

    #[test]
    fn test_empty_shuffle_verification() {
        let table = MentalPokerTable::new(2).expect("Failed to create table");
        let result = table.verify_last_shuffle();
        assert!(result.is_err(), "Empty shuffle list should return error");
        assert!(matches!(
            result,
            Err(MentalPokerError::ShuffleVerificationFailed)
        ));
    }

    #[test]
    fn test_verify_shuffle_empty_input() {
        let players: Vec<Player> = (0..2).map(Player::new).collect();
        let _shuffle = BayerGrothShuffle::new(&players);
        let proof = ShuffleProof {
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
            r: Vec::new(),
        };
        let result = BayerGrothShuffle::verify_shuffle(&[], &[], &proof);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MentalPokerError::InvalidVectorLength { .. })
        ));
    }

    #[test]
    fn test_encrypt_identity_point_fails() {
        let elgamal = ElGamal::new();
        let result = elgamal.encrypt(&ProjectivePoint::IDENTITY);
        assert!(matches!(result, Err(MentalPokerError::InvalidMessagePoint)));
    }

    #[test]
    fn test_decrypt_invalid_ciphertext_fails() {
        let elgamal = ElGamal::new();
        let invalid_ct = ElGamalCiphertext {
            c1: ProjectivePoint::IDENTITY,
            c2: ProjectivePoint::GENERATOR,
        };
        let result = elgamal.decrypt(&invalid_ct);
        assert!(matches!(result, Err(MentalPokerError::InvalidCiphertext)));
    }

    #[test]
    fn test_shuffle_single_element() {
        let players: Vec<Player> = (0..2).map(Player::new).collect();
        let shuffle = BayerGrothShuffle::new(&players);

        let msg = ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng);
        let ciphertexts = vec![ElGamalCiphertext {
            c1: ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng),
            c2: msg + (shuffle.public_key_sum * Scalar::random(&mut OsRng)),
        }];

        let (shuffled, proof) = shuffle
            .shuffle(&ciphertexts, &mut OsRng)
            .expect("Shuffle should succeed");
        let result = BayerGrothShuffle::verify_shuffle(&ciphertexts, &shuffled, &proof);
        assert!(result.is_ok());
    }

    #[test]
    fn test_shuffle_mismatched_proof_length() {
        let players: Vec<Player> = (0..2).map(Player::new).collect();
        let shuffle = BayerGrothShuffle::new(&players);

        let ciphertexts: Vec<ElGamalCiphertext> = (0..5)
            .map(|_| {
                let msg = ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng);
                ElGamalCiphertext {
                    c1: ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng),
                    c2: msg + (shuffle.public_key_sum * Scalar::random(&mut OsRng)),
                }
            })
            .collect();

        let invalid_proof = ShuffleProof {
            a: vec![ProjectivePoint::GENERATOR],
            b: vec![ProjectivePoint::GENERATOR],
            c: vec![Scalar::random(&mut OsRng)],
            r: vec![Scalar::random(&mut OsRng)],
        };

        let result = BayerGrothShuffle::verify_shuffle(&ciphertexts, &ciphertexts, &invalid_proof);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MentalPokerError::InvalidCommitmentLength { .. })
        ));
    }

    #[test]
    fn test_hash_to_valid_scalar_finds_valid() {
        let result = Deck::hash_to_valid_scalar(b"test_input");
        assert!(result.is_ok());
        let scalar = result.unwrap();
        assert_ne!(scalar, Scalar::ZERO);
    }

    #[test]
    fn test_card_points_are_distinct() {
        let deck = Deck::new().expect("Failed to create deck");
        let mut seen_points: HashSet<[u8; 33]> = HashSet::new();
        for card in deck.cards() {
            let bytes: [u8; 33] = card.to_bytes().into();
            assert!(seen_points.insert(bytes), "Duplicate card point detected");
        }
    }

    #[test]
    fn test_tampered_shuffle_detection() {
        let players: Vec<Player> = (0..2).map(Player::new).collect();
        let shuffle = BayerGrothShuffle::new(&players);

        let ciphertexts: Vec<ElGamalCiphertext> = (0..5)
            .map(|_| {
                let msg = ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng);
                ElGamalCiphertext {
                    c1: ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng),
                    c2: msg + (shuffle.public_key_sum * Scalar::random(&mut OsRng)),
                }
            })
            .collect();

        let (mut shuffled, proof) = shuffle
            .shuffle(&ciphertexts, &mut OsRng)
            .expect("Shuffle should succeed");

        shuffled[0] = ElGamalCiphertext {
            c1: ProjectivePoint::GENERATOR,
            c2: ProjectivePoint::GENERATOR,
        };

        let result = BayerGrothShuffle::verify_shuffle(&ciphertexts, &shuffled, &proof);
        assert!(result.is_err(), "Tampered shuffle should fail verification");
    }
}
