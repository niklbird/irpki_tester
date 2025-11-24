// //! RPKI Manifests.
// //!
// //! Manifests list all the files that are currently published by an RPKI CA.
// //! They are defined in RFC 6486.
// //!
// //! This module defines the type [`Manifest`] that represents a decoded
// //! manifest and the type [`ManifestContent`] for the content of a validated
// //! manifest, as well as some helper types for accessing the content.
// //!
// //! [`Manifest`]: struct.Manifest.html
// //! [`ManifestContent`]: struct.ManifestContent.html

// use std::collections::{HashMap, HashSet};
// use bytes::Bytes;
// use chrono::DateTime;
// use log::warn;
// use crate::crypto::{DigestAlgorithm, KeyIdentifier, RpkiSignature, RpkiSignatureAlgorithm, Signer, SigningError};
// use super::cert::{Cert, ResourceCert};
// use super::error::{InspectionError, ValidationError, VerificationError};
// use super::icrl::ICrl;
// use super::manifest::{FileAndHash, FileListIter, ManifestContent, ManifestHash};
// use super::rpkiobj::ObjectMeta;
// use super::x509::{Serial, Time, Validity};


// //------------ Manifest ------------------------------------------------------

// #[derive(Clone, Debug)]
// pub struct PManifest {
//     pub content: ManifestContent,
//     pub meta: ObjectMeta,
//     pub crl: Option<ICrl>,
//     pub raw_inner: Vec<u8>, // The content contained in the signature
//     pub signature: Vec<u8>,
// }

// impl PManifest {
//     pub fn decode_proto(data: &Vec<u8>) -> Result<PManifest, String>{
//         let parsed = cure_asn1::prot::util::decode_mft(data).unwrap();

//         if parsed.manifest_content.is_none() || parsed.meta.is_none(){
//             warn!("Manifest content failed");
//             return Err("Manifest content or meta is missing".to_string());
//         }
//         let raw_inner = parsed.get_signed_data();

//         let info = parsed.meta.unwrap();

//         let not_before = info.not_before.unwrap();
//         let t = DateTime::from_timestamp(not_before.seconds, not_before.nanos.try_into().unwrap()).unwrap();
//         let not_before = Time::new(t);

//         let not_after = info.not_after.unwrap();
//         let t = DateTime::from_timestamp(not_after.seconds, not_after.nanos.try_into().unwrap()).unwrap();
//         let not_after = Time::new(t);

//         if info.ski.is_none(){
//             warn!("SKI Is missing");

//             return Err("SKI is missing".to_string());
//         }        
        
        


//         let ski_vec = info.ski.unwrap(); 
//         let ski_array: [u8; 20] = ski_vec.try_into().expect("Expected a Vec of length 20"); 
//         let kid = KeyIdentifier::from(ski_array);
//         let meta = ObjectMeta{
//             serial_number: info.serial,
//             this_update: not_before,
//             next_update: not_after,
//             sid: Some(kid),
//             signed_object_location: None,
//         };

//         let hll = parsed.manifest_content.as_ref().unwrap().hashes.as_ref().unwrap().hash_list.len();
//         let mut file_list = Vec::with_capacity(hll);

//         if let Some(hash_entries) = &parsed.manifest_content.as_ref().unwrap().hashes {
//             let _ = hash_entries.hash_algorithm; // Currently only sha256 supported anyway
//             for entry in &hash_entries.hash_list {
//                 let file = entry.file_name.clone();
//                 let hash = entry.hash.clone();
//                 file_list.push((file, ManifestHash::new(Bytes::from(hash), DigestAlgorithm::sha256())));
//             }
//         }
        

//         let len = file_list.len();
//         let content = ManifestContent{
//             manifest_number: info.serial.into(),
//             this_update: not_before,
//             next_update: not_after,
//             file_hash_alg: DigestAlgorithm::sha256(),
//             file_list,
//             file_list_c: None,
//             len,
//         };


//         let sig = match parsed.signature{
//             Some(sig) => sig.signature,
//             None => {
//                 warn!("Signature");
//                 return Err("Signature is missing".to_string())},
//         };

//         let mut serials = HashSet::new();
//         let mut revocation_times = HashMap::new();
//         if parsed.manifest_content.as_ref().unwrap().revoced_certs.len() > 0{
//             for cert in &parsed.manifest_content.as_ref().unwrap().revoced_certs{
//                 let serial = cert.serial;
//                 let revocation_time = cert.revocation_time.unwrap();
//                 let t = DateTime::from_timestamp(revocation_time.seconds, revocation_time.nanos.try_into().unwrap()).unwrap();
//                 let revocation_time = Time::new(t);
//                 serials.insert(serial.into());
//                 revocation_times.insert(serial.into(), revocation_time);
//             }
//         }
//         let icrl = ICrl{serials, revocation_times};

//         Ok(PManifest { content, meta, crl: Some(icrl), raw_inner, signature:  sig})
//     }

//     pub fn validate(
//         self,
//         cert: &ResourceCert,
//     ) -> Result<ManifestContent, ValidationError> {
//         let validity = Validity::new(self.meta.this_update, self.meta.next_update);
//         validity.verify().map_err(|_| InspectionError::new("Manifest is invalid"))?;

//         self.verify(cert)?;
//         Ok(self.content)
//     }

//     pub fn verify(&self, cert: &ResourceCert) -> Result<(), VerificationError> {
//         let signature = RpkiSignature::new(
//             RpkiSignatureAlgorithm::default(),
//             self.signature.clone().into(),
//         );
//         cert.subject_public_key_info().verify(&self.raw_inner, &signature)
//             .map_err(Into::into)
//     }

// }

