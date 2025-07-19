use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit},
    aes::Aes256,
};
use anyhow::{Result, anyhow, bail};
use base64::prelude::*;
use bincode::{Decode, Encode};
use ed25519_dalek::Signature;
use ed25519_dalek::ed25519::SignatureBytes;
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use rand::Rng;
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub type NodeId = [u8; 32];
pub type ShortId = [u8; 12];

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicIdentity {
    pub public_key: NodeId,
}

impl PublicIdentity {
    pub fn short_id(&self) -> ShortId {
        self.public_key[0..12]
            .try_into()
            .expect("couldn't convert NodeId into ShortId")
    }
}

impl std::fmt::Display for PublicIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.base64())
    }
}

#[derive(Clone, Debug)]
pub struct PrivateIdentity {
    private_key: [u8; 32],
    pub public_id: PublicIdentity,
}

impl PublicIdentity {
    pub fn verify(&self, msg: Vec<u8>, signature: &SignatureBytes) -> Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(&self.public_key)?;
        let signature = Signature::from_bytes(signature);
        Ok(verifying_key.verify(msg.as_slice(), &signature).is_ok())
    }

    pub fn base64(&self) -> String {
        BASE64_STANDARD.encode(self.public_key)
    }
}

impl PrivateIdentity {
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        Self {
            private_key: *signing_key.as_bytes(),
            public_id: PublicIdentity {
                public_key: *verifying_key.as_bytes(),
            },
        }
    }

    pub fn sign(&self, msg: Vec<u8>) -> SignatureBytes {
        let mut signing_key: SigningKey = SigningKey::from_bytes(&self.private_key);
        let signature = signing_key.sign(msg.as_slice());
        signature.to_bytes()
    }

    pub fn base64(&self) -> String {
        BASE64_STANDARD.encode(self.private_key)
    }
}

#[derive(Eq, PartialEq, Encode, Decode, Clone, Hash, Debug)]
pub struct KeyExchangeMessage {
    session_id: [u8; 8],
    public: [u8; 32],
}

pub struct KeyExchange {
    secret: EphemeralSecret,
    session_id: [u8; 8],
}

impl KeyExchange {
    pub fn new() -> Self {
        let mut osrng = OsRng;
        let secret = EphemeralSecret::random_from_rng(osrng);
        let mut session_id: [u8; 8] = [0; 8];
        osrng.fill(&mut session_id);
        Self { secret, session_id }
    }

    pub fn new_from_other_message(other_kex: &KeyExchangeMessage) -> Self {
        let osrng = OsRng;
        let secret = EphemeralSecret::random_from_rng(osrng);
        let session_id = other_kex.session_id;
        Self { secret, session_id }
    }

    pub fn public(&self) -> KeyExchangeMessage {
        KeyExchangeMessage {
            session_id: self.session_id,
            public: PublicKey::from(&self.secret).to_bytes(),
        }
    }

    pub fn into_encryption_session(
        self,
        other_kex: &KeyExchangeMessage,
    ) -> Result<EncryptionSession> {
        if other_kex.session_id != self.session_id {
            bail!("session_id doesn't match")
        }
        let mut new_session_id: [u8; 8] =
            PublicKey::from(&self.secret).to_bytes()[0..8].try_into()?;
        for (a, b) in new_session_id.iter_mut().zip(other_kex.public) {
            *a ^= b;
        }
        Ok(EncryptionSession::new(
            new_session_id,
            self.secret
                .diffie_hellman(&PublicKey::from(other_kex.public))
                .to_bytes(),
        ))
    }
}

pub struct EncryptionSession {
    session_id: [u8; 8],
    key: Key<Aes256Gcm>,
    iv: [u8; 12],
}

#[derive(Eq, PartialEq, Encode, Decode, Clone, Hash, Debug)]
pub struct EncryptedMessage {
    pub iv: [u8; 12],
    pub session_id: [u8; 8],
    pub ciphertext: Vec<u8>,
}

impl EncryptionSession {
    pub fn new(session_id: [u8; 8], key: [u8; 32]) -> Self {
        Self {
            session_id,
            key: key.into(),
            iv: Aes256Gcm::generate_nonce(OsRng).into(),
        }
    }

    fn incr_iv(&mut self) {
        let mut rollover = true;
        for b in self.iv.iter_mut() {
            if rollover {
                (*b, rollover) = b.overflowing_add(1)
            } else {
                break;
            }
        }
    }

    pub fn encrypt(&mut self, plaintext: &Vec<u8>) -> Result<EncryptedMessage> {
        let cipher = Aes256Gcm::new(&self.key);
        self.incr_iv();
        let Ok(ciphertext) = cipher.encrypt(&self.iv.into(), plaintext.as_slice()) else {
            bail!("crypto error")
        };
        Ok(EncryptedMessage {
            iv: self.iv,
            session_id: self.session_id,
            ciphertext,
        })
    }

    pub fn decrypt(&self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(&self.key);
        if let Ok(plaintext) = cipher.decrypt(&message.iv.into(), message.ciphertext.as_slice()) {
            Ok(plaintext)
        } else {
            bail!("crypto error")
        }
    }
}
