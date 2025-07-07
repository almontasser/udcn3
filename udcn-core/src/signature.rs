use crate::packets::{Data, KeyLocator, Name};
use crate::tlv::TlvError;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPublicKey};
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{RandomizedSigner, Verifier, SignatureEncoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Signature types supported by the NDN protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SignatureType {
    /// SHA256 with RSA signature
    Sha256WithRsa = 1,
    /// SHA256 with ECDSA signature
    Sha256WithEcdsa = 3,
    /// HMAC with SHA256
    HmacWithSha256 = 4,
    /// SHA256 digest only (no signature)
    DigestSha256 = 0,
}

impl From<u8> for SignatureType {
    fn from(value: u8) -> Self {
        match value {
            1 => SignatureType::Sha256WithRsa,
            3 => SignatureType::Sha256WithEcdsa,
            4 => SignatureType::HmacWithSha256,
            0 => SignatureType::DigestSha256,
            _ => SignatureType::DigestSha256, // Default fallback
        }
    }
}

/// Certificate information for signature validation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Certificate name
    pub name: Name,
    /// Certificate data
    pub certificate_data: Vec<u8>,
    /// Certificate validity period start
    pub valid_from: u64,
    /// Certificate validity period end  
    pub valid_to: u64,
    /// Certificate fingerprint
    pub fingerprint: Vec<u8>,
}

impl CertificateInfo {
    pub fn new(name: Name, certificate_data: Vec<u8>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Generate fingerprint from certificate data
        let mut hasher = Sha256::new();
        hasher.update(&certificate_data);
        let fingerprint = hasher.finalize().to_vec();
        
        Self {
            name,
            certificate_data,
            valid_from: now,
            valid_to: now + (365 * 24 * 3600), // 1 year default validity
            fingerprint,
        }
    }
    
    /// Check if certificate is currently valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now >= self.valid_from && now <= self.valid_to
    }
}

/// Core signature data structure containing all signature-related information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    /// Type of signature algorithm used
    pub signature_type: SignatureType,
    /// Key locator pointing to the signing key
    pub key_locator: Option<KeyLocator>,
    /// Certificate chain for signature validation
    pub certificate_chain: Vec<CertificateInfo>,
    /// Timestamp when signature was created
    pub signing_time: u64,
    /// Signature value bytes
    pub signature_value: Vec<u8>,
    /// Additional signature attributes
    pub attributes: HashMap<String, Vec<u8>>,
    /// Digest of the signed data
    pub digest: Vec<u8>,
}

impl Signature {
    /// Create a new signature with specified type
    pub fn new(signature_type: SignatureType) -> Self {
        let signing_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            signature_type,
            key_locator: None,
            certificate_chain: Vec::new(),
            signing_time,
            signature_value: Vec::new(),
            attributes: HashMap::new(),
            digest: Vec::new(),
        }
    }
    
    /// Set the key locator for this signature
    pub fn with_key_locator(mut self, key_locator: KeyLocator) -> Self {
        self.key_locator = Some(key_locator);
        self
    }
    
    /// Add a certificate to the certificate chain
    pub fn with_certificate(mut self, certificate: CertificateInfo) -> Self {
        self.certificate_chain.push(certificate);
        self
    }
    
    /// Set the signature value
    pub fn with_signature_value(mut self, signature_value: Vec<u8>) -> Self {
        self.signature_value = signature_value;
        self
    }
    
    /// Add a custom attribute
    pub fn with_attribute(mut self, name: String, value: Vec<u8>) -> Self {
        self.attributes.insert(name, value);
        self
    }
    
    /// Set the digest value
    pub fn with_digest(mut self, digest: Vec<u8>) -> Self {
        self.digest = digest;
        self
    }
    
    /// Check if the signature is complete and valid
    pub fn is_complete(&self) -> bool {
        match self.signature_type {
            SignatureType::DigestSha256 => !self.digest.is_empty(),
            _ => !self.signature_value.is_empty() && !self.digest.is_empty(),
        }
    }
    
    /// Get the signature algorithm name
    pub fn algorithm_name(&self) -> &'static str {
        match self.signature_type {
            SignatureType::Sha256WithRsa => "SHA256withRSA",
            SignatureType::Sha256WithEcdsa => "SHA256withECDSA", 
            SignatureType::HmacWithSha256 => "HMAC-SHA256",
            SignatureType::DigestSha256 => "SHA256",
        }
    }
    
    /// Validate signature metadata (not cryptographic validation)
    pub fn validate_metadata(&self) -> Result<(), SignatureError> {
        // Check if signature is complete
        if !self.is_complete() {
            return Err(SignatureError::IncompleteSignature);
        }
        
        // Validate certificate chain if present
        for cert in &self.certificate_chain {
            if !cert.is_valid() {
                return Err(SignatureError::InvalidCertificate(cert.name.to_string()));
            }
        }
        
        // Check signing time is reasonable (not too far in the future)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if self.signing_time > now + 300 { // 5 minutes tolerance
            return Err(SignatureError::InvalidSigningTime);
        }
        
        Ok(())
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self::new(SignatureType::DigestSha256)
    }
}

/// Errors that can occur during signature operations
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Signature is incomplete")]
    IncompleteSignature,
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),
    #[error("Invalid signing time")]
    InvalidSigningTime,
    #[error("Unsupported signature type: {0:?}")]
    UnsupportedSignatureType(SignatureType),
    #[error("Key error: {0}")]
    KeyError(String),
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("TLV encoding error: {0}")]
    TlvError(#[from] TlvError),
    #[error("RSA error: {0}")]
    RsaError(#[from] rsa::Error),
    #[error("Invalid digest length: expected {expected}, got {actual}")]
    InvalidDigestLength { expected: usize, actual: usize },
}

/// Cryptographic operations for signature generation and verification
pub struct SignatureEngine {
    /// Default signature type to use
    default_signature_type: SignatureType,
}

impl SignatureEngine {
    /// Create a new signature engine
    pub fn new() -> Self {
        Self {
            default_signature_type: SignatureType::Sha256WithRsa,
        }
    }
    
    /// Create with specific default signature type
    pub fn with_default_type(signature_type: SignatureType) -> Self {
        Self {
            default_signature_type: signature_type,
        }
    }
    
    /// Compute SHA256 digest of Data packet for signing
    pub fn compute_data_digest(&self, data: &Data) -> Result<Vec<u8>, SignatureError> {
        let mut hasher = Sha256::new();
        
        // Add Name
        let name_encoded = data.name.encode().map_err(SignatureError::TlvError)?;
        hasher.update(&name_encoded);
        
        // Add MetaInfo if present
        if let Some(meta_info) = &data.meta_info {
            let meta_info_bytes = self.encode_meta_info_for_signing(meta_info)?;
            hasher.update(&meta_info_bytes);
        }
        
        // Add Content
        hasher.update(&data.content);
        
        // Add SignatureInfo if present (but not SignatureValue)
        if let Some(sig_info) = &data.signature_info {
            let sig_info_bytes = self.encode_signature_info_for_signing(sig_info)?;
            hasher.update(&sig_info_bytes);
        }
        
        Ok(hasher.finalize().to_vec())
    }
    
    /// Prepare raw data for signing (returns the raw bytes to be signed)
    pub fn prepare_data_for_signing(&self, data: &Data) -> Result<Vec<u8>, SignatureError> {
        let mut signing_data = Vec::new();
        
        // Add Name
        let name_encoded = data.name.encode().map_err(SignatureError::TlvError)?;
        signing_data.extend_from_slice(&name_encoded);
        
        // Add MetaInfo if present
        if let Some(meta_info) = &data.meta_info {
            let meta_info_bytes = self.encode_meta_info_for_signing(meta_info)?;
            signing_data.extend_from_slice(&meta_info_bytes);
        }
        
        // Add Content
        signing_data.extend_from_slice(&data.content);
        
        // Add SignatureInfo if present (but not SignatureValue)
        if let Some(sig_info) = &data.signature_info {
            let sig_info_bytes = self.encode_signature_info_for_signing(sig_info)?;
            signing_data.extend_from_slice(&sig_info_bytes);
        }
        
        Ok(signing_data)
    }
    
    /// Generate RSA signature for given data  
    pub fn sign_with_rsa(
        &self,
        data: &[u8],
        private_key: &RsaPrivateKey,
    ) -> Result<Vec<u8>, SignatureError> {
        let mut rng = rand::thread_rng();
        
        // Create signing key - this handles SHA256 hashing internally
        let signing_key = SigningKey::<Sha256>::new(private_key.clone());
        
        // Sign the data (SigningKey handles hashing internally)
        let signature = signing_key.sign_with_rng(&mut rng, data);
        
        Ok(signature.to_bytes().as_ref().to_vec())
    }
    
    /// Verify RSA signature against data
    pub fn verify_rsa_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &RsaPublicKey,
    ) -> Result<bool, SignatureError> {
        // Create verifying key from public key
        let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());
        
        // Parse signature bytes
        let signature = rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|_| SignatureError::VerificationFailed)?;
        
        // Verify the signature
        match verifying_key.verify(data, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    /// Sign a Data packet with RSA private key
    pub fn sign_data_with_rsa(
        &self,
        data: &mut Data,
        private_key: &RsaPrivateKey,
        key_locator: Option<KeyLocator>,
    ) -> Result<(), SignatureError> {
        // Prepare data for signing (same as digest computation but return raw bytes)
        let signing_data = self.prepare_data_for_signing(data)?;
        
        // Generate signature using the raw data (SigningKey handles hashing)
        let signature_value = self.sign_with_rsa(&signing_data, private_key)?;
        
        // Compute digest for storage
        let digest = self.compute_data_digest(data)?;
        
        // Create signature structure
        let mut signature = Signature::new(SignatureType::Sha256WithRsa)
            .with_digest(digest)
            .with_signature_value(signature_value);
            
        if let Some(locator) = key_locator {
            signature = signature.with_key_locator(locator);
        }
        
        // Convert to SignatureInfo and set on data
        let sig_info = self.signature_to_signature_info(&signature)?;
        data.signature_info = Some(sig_info);
        data.signature_value = Some(signature.signature_value);
        
        Ok(())
    }
    
    /// Verify a Data packet signature
    pub fn verify_data_signature(
        &self,
        data: &Data,
        public_key: &RsaPublicKey,
    ) -> Result<bool, SignatureError> {
        // Extract signature information
        let sig_info = data.signature_info.as_ref()
            .ok_or(SignatureError::IncompleteSignature)?;
        let sig_value = data.signature_value.as_ref()
            .ok_or(SignatureError::IncompleteSignature)?;
        
        // Check signature type
        if sig_info.signature_type != SignatureType::Sha256WithRsa as u8 {
            return Err(SignatureError::UnsupportedSignatureType(
                SignatureType::from(sig_info.signature_type)
            ));
        }
        
        // Prepare data for verification (same raw data used for signing)
        let signing_data = self.prepare_data_for_signing(data)?;
        
        // Verify signature
        self.verify_rsa_signature(&signing_data, sig_value, public_key)
    }
    
    /// Convert Signature to SignatureInfo for packet encoding
    fn signature_to_signature_info(
        &self,
        signature: &Signature,
    ) -> Result<crate::packets::SignatureInfo, SignatureError> {
        let mut sig_info = crate::packets::SignatureInfo::new(signature.signature_type as u8);
        
        if let Some(key_locator) = &signature.key_locator {
            sig_info = sig_info.with_key_locator(key_locator.clone());
        }
        
        // Add custom attributes
        for (key, value) in &signature.attributes {
            if let Ok(key_byte) = key.parse::<u8>() {
                sig_info.other_fields.insert(key_byte, value.clone());
            }
        }
        
        Ok(sig_info)
    }
    
    /// Helper function to encode MetaInfo for signing
    fn encode_meta_info_for_signing(
        &self,
        _meta_info: &crate::packets::MetaInfo,
    ) -> Result<Vec<u8>, SignatureError> {
        // For now, return empty - in full implementation this would encode MetaInfo
        Ok(Vec::new())
    }
    
    /// Helper function to encode SignatureInfo for signing
    fn encode_signature_info_for_signing(
        &self,
        _sig_info: &crate::packets::SignatureInfo,
    ) -> Result<Vec<u8>, SignatureError> {
        // For now, return empty - in full implementation this would encode SignatureInfo
        Ok(Vec::new())
    }
}

impl Default for SignatureEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Key generation utilities
pub struct KeyGenerator;

impl KeyGenerator {
    /// Generate a new RSA key pair
    pub fn generate_rsa_keypair(bits: usize) -> Result<RsaPrivateKey, SignatureError> {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, bits).map_err(SignatureError::RsaError)
    }
    
    /// Extract public key from private key
    pub fn extract_public_key(private_key: &RsaPrivateKey) -> RsaPublicKey {
        RsaPublicKey::from(private_key)
    }
    
    /// Generate a key locator name for a public key
    pub fn generate_key_locator_name(public_key: &RsaPublicKey) -> Result<Name, SignatureError> {
        // Create a hash of the public key for the locator
        let key_der = public_key.to_pkcs1_der()
            .map_err(|e| SignatureError::KeyError(e.to_string()))?;
        
        let mut hasher = Sha256::new();
        hasher.update(&key_der);
        let key_hash = hasher.finalize();
        
        // Convert to hex string for name component
        let hex_string = hex::encode(&key_hash[..16]); // Use first 16 bytes
        
        let mut name = Name::new();
        name.append_str("keys");
        name.append_str(&hex_string);
        
        Ok(name)
    }
}

// Add hex dependency helper
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_encode_impl(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

// Replace hex::encode with our implementation
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        super::hex_encode_impl(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::{Data, Name};

    #[test]
    fn test_signature_creation() {
        let signature = Signature::new(SignatureType::Sha256WithRsa)
            .with_key_locator(KeyLocator::Name(Name::from_str("/test/key")))
            .with_signature_value(vec![1, 2, 3, 4])
            .with_digest(vec![0; 32]);
        
        assert_eq!(signature.signature_type, SignatureType::Sha256WithRsa);
        assert!(signature.key_locator.is_some());
        assert_eq!(signature.signature_value, vec![1, 2, 3, 4]);
        assert!(signature.is_complete());
    }

    #[test]
    fn test_signature_types() {
        assert_eq!(SignatureType::from(1), SignatureType::Sha256WithRsa);
        assert_eq!(SignatureType::from(3), SignatureType::Sha256WithEcdsa);
        assert_eq!(SignatureType::from(255), SignatureType::DigestSha256); // Unknown falls back to default
    }

    #[test]
    fn test_certificate_info() {
        let cert_data = vec![1, 2, 3, 4, 5];
        let cert = CertificateInfo::new(Name::from_str("/test/cert"), cert_data.clone());
        
        assert_eq!(cert.certificate_data, cert_data);
        assert!(!cert.fingerprint.is_empty());
        assert!(cert.is_valid()); // Should be valid when created
    }

    #[test]
    fn test_signature_engine_digest() {
        let engine = SignatureEngine::new();
        let data = Data::new(Name::from_str("/test"), b"hello world".to_vec());
        
        let digest = engine.compute_data_digest(&data).unwrap();
        assert_eq!(digest.len(), 32); // SHA256 produces 32 bytes
        
        // Same data should produce same digest
        let digest2 = engine.compute_data_digest(&data).unwrap();
        assert_eq!(digest, digest2);
    }

    #[test]
    fn test_key_generation() {
        let private_key = KeyGenerator::generate_rsa_keypair(1024).unwrap();
        let public_key = KeyGenerator::extract_public_key(&private_key);
        
        // Test signing and verification
        let engine = SignatureEngine::new();
        let test_data = b"test data for signing"; // Raw data instead of digest
        
        let signature = engine.sign_with_rsa(test_data, &private_key).unwrap();
        assert!(!signature.is_empty());
        
        let is_valid = engine.verify_rsa_signature(test_data, &signature, &public_key).unwrap();
        assert!(is_valid);
        
        // Test with wrong signature
        let wrong_signature = vec![0; signature.len()];
        let is_valid = engine.verify_rsa_signature(test_data, &wrong_signature, &public_key).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_data_signing_and_verification() {
        let private_key = KeyGenerator::generate_rsa_keypair(1024).unwrap();
        let public_key = KeyGenerator::extract_public_key(&private_key);
        let engine = SignatureEngine::new();
        
        let mut data = Data::new(Name::from_str("/test/data"), b"test content".to_vec());
        
        // Sign the data
        let key_locator = KeyLocator::Name(Name::from_str("/test/key"));
        engine.sign_data_with_rsa(&mut data, &private_key, Some(key_locator)).unwrap();
        
        // Verify the signature
        assert!(data.signature_info.is_some());
        assert!(data.signature_value.is_some());
        
        let is_valid = engine.verify_data_signature(&data, &public_key).unwrap();
        assert!(is_valid);
        
        // Modify content and verify it fails
        data.content = b"modified content".to_vec();
        let is_valid = engine.verify_data_signature(&data, &public_key).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_incomplete_signature() {
        let incomplete_sig = Signature::new(SignatureType::Sha256WithRsa);
        assert!(!incomplete_sig.is_complete());
        
        assert!(incomplete_sig.validate_metadata().is_err());
    }

    #[test]
    fn test_signature_algorithm_names() {
        assert_eq!(Signature::new(SignatureType::Sha256WithRsa).algorithm_name(), "SHA256withRSA");
        assert_eq!(Signature::new(SignatureType::DigestSha256).algorithm_name(), "SHA256");
    }

    #[test]
    fn test_key_locator_generation() {
        let private_key = KeyGenerator::generate_rsa_keypair(1024).unwrap();
        let public_key = KeyGenerator::extract_public_key(&private_key);
        
        let key_locator_name = KeyGenerator::generate_key_locator_name(&public_key).unwrap();
        assert!(key_locator_name.to_string().starts_with("/keys/"));
        assert!(key_locator_name.len() > 1);
    }

}