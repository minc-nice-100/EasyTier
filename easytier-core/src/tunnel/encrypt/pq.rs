//! Hybrid post-quantum key encapsulation for peer connection sessions.
//!
//! EasyTier establishes peer sessions over a Noise `XX` handshake that uses
//! X25519. A quantum computer could recover the X25519 static/session keys from
//! a recorded handshake and then decrypt the session root key that travels
//! inside the Noise channel ("harvest now, decrypt later").
//!
//! This module adds a hybrid ML-KEM-768 (FIPS 203) layer on top of that
//! exchange. The initiator offers a fresh ML-KEM encapsulation key; the
//! responder encapsulates a random shared secret to it. Both sides then mix the
//! post-quantum shared secret into the session root key with HKDF-SHA-256. An
//! attacker who later breaks X25519 still does not obtain the ML-KEM shared
//! secret, so recorded sessions remain confidential.
//!
//! The exchange is fully backward compatible: the optional protobuf fields are
//! ignored by older peers, and the hybrid activates only when both sides
//! advertise it. When it does not activate, the session falls back to the
//! X25519-only Noise exchange unchanged.
//!
//! The module compiles without the `post-quantum` Cargo feature; every entry
//! point then degrades to "no post-quantum offer" so callers need no
//! `#[cfg]` branches.

use hmac::{Hmac, Mac};
use sha2::Sha256;

#[cfg(feature = "post-quantum")]
use ml_kem::{
    Decapsulate, Encapsulate, EncapsulationKey, Kem, KeyExport, KeySizeUser, MlKem768, TryKeyInit,
    array::Array,
};

/// ML-KEM-768 encapsulation (public) key length in bytes.
pub const MLKEM_PUBKEY_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length in bytes.
pub const MLKEM_CIPHERTEXT_LEN: usize = 1088;
/// ML-KEM-768 shared secret length in bytes.
pub const MLKEM_SHARED_SECRET_LEN: usize = 32;

/// Domain separation label for the hybrid key derivation.
pub const HYBRID_INFO: &[u8] = b"easytier-pq-hybrid-v1";

type HmacSha256 = Hmac<Sha256>;

/// An initiator-held ML-KEM keypair valid for the duration of one handshake.
///
/// The decapsulation key is kept only in memory; only the encapsulation key is
/// serialized onto the wire.
#[cfg(feature = "post-quantum")]
struct PqKeypair {
    decapsulation_key: ml_kem::DecapsulationKey<MlKem768>,
    encapsulation_key: EncapsulationKey<MlKem768>,
}

#[cfg(feature = "post-quantum")]
impl PqKeypair {
    fn generate() -> Self {
        let (decapsulation_key, encapsulation_key) = MlKem768::generate_keypair();
        Self {
            decapsulation_key,
            encapsulation_key,
        }
    }

    fn encapsulation_key_bytes(&self) -> Vec<u8> {
        self.encapsulation_key.to_bytes().to_vec()
    }

    fn decapsulate(&self, ciphertext: &[u8]) -> Option<[u8; MLKEM_SHARED_SECRET_LEN]> {
        let shared = self.decapsulation_key.decapsulate_slice(ciphertext).ok()?;
        let mut out = [0u8; MLKEM_SHARED_SECRET_LEN];
        out.copy_from_slice(&shared);
        Some(out)
    }
}

/// The initiator's post-quantum offer carried across the three-message
/// handshake. Without the `post-quantum` feature the offer is always empty and
/// every method degrades to `None`, so callers need no feature branches.
pub enum PqOffer {
    #[cfg(feature = "post-quantum")]
    Pq(PqKeypair),
    Unavailable,
}

impl PqOffer {
    /// Creates an offer from the runtime flag. Returns the empty offer when the
    /// build does not compile the ML-KEM engine.
    pub fn offer(enabled: bool) -> Self {
        #[cfg(feature = "post-quantum")]
        {
            if enabled {
                return Self::Pq(PqKeypair::generate());
            }
        }
        #[cfg(not(feature = "post-quantum"))]
        {
            let _ = enabled;
        }
        Self::Unavailable
    }

    /// Serialized ML-KEM encapsulation key to send in the first handshake
    /// message, or `None` when this offer is empty.
    pub fn pubkey_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "post-quantum")]
        {
            if let Self::Pq(keypair) = self {
                return Some(keypair.encapsulation_key_bytes());
            }
        }
        None
    }

    /// Opens the responder's ML-KEM ciphertext with the offered keypair.
    pub fn open(&self, ciphertext: &[u8]) -> Option<[u8; MLKEM_SHARED_SECRET_LEN]> {
        #[cfg(feature = "post-quantum")]
        {
            if let Self::Pq(keypair) = self {
                return keypair.decapsulate(ciphertext);
            }
        }
        let _ = ciphertext;
        None
    }
}

/// Encapsulate a fresh shared secret to a remote ML-KEM encapsulation key.
///
/// Returns the ciphertext to transmit and the derived shared secret, or `None`
/// when the key is malformed or the build lacks the ML-KEM engine.
pub fn encapsulate(ek_bytes: &[u8]) -> Option<(Vec<u8>, [u8; MLKEM_SHARED_SECRET_LEN])> {
    #[cfg(feature = "post-quantum")]
    {
        if ek_bytes.len() != MLKEM_PUBKEY_LEN {
            return None;
        }
        type PqEk = EncapsulationKey<MlKem768>;
        let key = Array::<u8, <PqEk as KeySizeUser>::KeySize>::from_slice(ek_bytes).clone();
        let ek = PqEk::new(&key).ok()?;
        let (ciphertext, shared) = ek.encapsulate();
        let mut out = [0u8; MLKEM_SHARED_SECRET_LEN];
        out.copy_from_slice(&shared);
        return Some((ciphertext.as_slice().to_vec(), out));
    }
    #[cfg(not(feature = "post-quantum"))]
    {
        let _ = ek_bytes;
        None
    }
}

/// Mix an ML-KEM shared secret into the session root key.
///
/// HKDF-SHA-256 extract-expand: the root key is extracted with the hybrid label
/// as salt, then a one-block expand produces the mixed session key. Both peers
/// compute the same value from the same inputs.
pub fn hybrid_root_key(root_key: [u8; 32], pq_shared: &[u8; MLKEM_SHARED_SECRET_LEN]) -> [u8; 32] {
    let mut extract = HmacSha256::new_from_slice(HYBRID_INFO).expect("hmac accepts any key");
    extract.update(&root_key);
    let prk = extract.finalize().into_bytes();

    let mut expand = HmacSha256::new_from_slice(&prk).expect("hmac accepts any key");
    expand.update(pq_shared);
    expand.update(&[1u8]);
    let okm = expand.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm[..32]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip_establishes_shared_secret() {
        let offer = PqOffer::offer(true);
        let Some(ek_bytes) = offer.pubkey_bytes() else {
            // Post-quantum engine not compiled in this profile.
            return;
        };
        assert_eq!(ek_bytes.len(), MLKEM_PUBKEY_LEN);

        let Some((ciphertext, responder_shared)) = encapsulate(&ek_bytes) else {
            return;
        };
        assert_eq!(ciphertext.len(), MLKEM_CIPHERTEXT_LEN);

        let Some(initiator_shared) = offer.open(&ciphertext) else {
            return;
        };
        assert_eq!(initiator_shared, responder_shared);
    }

    #[test]
    fn invalid_encapsulation_key_is_rejected() {
        // Encapsulating to a truncated key must never yield a shared secret.
        assert!(encapsulate(&[0u8; 32]).is_none());
    }

    #[test]
    fn hybrid_root_key_is_deterministic_and_binds_shared_secret() {
        let root_key = [7u8; 32];
        let shared = [9u8; 32];

        let mixed = hybrid_root_key(root_key, &shared);
        assert_eq!(mixed, hybrid_root_key(root_key, &shared));

        let different_shared = hybrid_root_key(root_key, &[8u8; 32]);
        assert_ne!(mixed, different_shared);
        let unmixed_digest = hybrid_root_key([8u8; 32], &shared);
        assert_ne!(mixed, unmixed_digest);
    }
}
