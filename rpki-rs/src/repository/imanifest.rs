//! RPKI Manifests.
//!
//! Manifests list all the files that are currently published by an RPKI CA.
//! They are defined in RFC 6486.
//!
//! This module defines the type [`Manifest`] that represents a decoded
//! manifest and the type [`ManifestContent`] for the content of a validated
//! manifest, as well as some helper types for accessing the content.
//!
//! [`Manifest`]: struct.Manifest.html
//! [`ManifestContent`]: struct.ManifestContent.html

use std::collections::{HashMap, HashSet};
use std::str::from_utf8;
use std::{borrow, ops};
use bcder::{decode, encode};
use bcder::{
    Captured, Mode, Tag,
};
use crate::repository::crl::CrlEntry;
use crate::util::base64;

use bcder::decode::{DecodeError, IntoSource, Source};
use bcder::encode::{PrimitiveContent, Values};
use bytes::Bytes;
use crate::{oid, uri};
use crate::crypto::DigestAlgorithm;
use super::cert::ResourceCert;
use super::error::{InspectionError, ValidationError};
use super::icrl::ICrl;
use super::isigobj::ISignedObject;
use super::manifest::{FileAndHash, FileListIter, ManifestContent, ManifestHash};
use super::x509::{Serial, Time};


//------------ Manifest ------------------------------------------------------

/// A decoded RPKI manifest.
///
/// This type represents a manifest decoded from a source. In order to get to
/// the manifest’s content, you need to validate it via the `validate`
/// method.
#[derive(Clone, Debug)]
pub struct IManifest {
    pub signed: ISignedObject,
    pub content: IManifestContent,
    pub crl: Option<(uri::Rsync, ICrl, Bytes)>
}

impl IManifest {
    /// Decodes a manifest from a source.
    #[allow(clippy::redundant_closure)]
    pub fn decode<S: IntoSource>(
        source: S,
        strict: bool
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        let signed = ISignedObject::decode_if_type(
            source, &oid::CT_RPKI_IMANIFEST, strict
        )?;
        let content = signed.decode_content(
            |cons| IManifestContent::take_from(cons)
        ).map_err(DecodeError::convert)?;
        let crl = match &content.crl_content{
            Some(v) => {Some(v.clone())},
            None => None,
        };
        Ok(IManifest { signed, content, crl})
    }

    /// Validates the manifest.
    ///
    /// You need to pass in the certificate of the issuing CA. If validation
    /// succeeds, the result will be the EE certificate of the manifest and
    /// the manifest content.
    pub fn validate(
        self,
        cert: &ResourceCert,
        strict: bool,
    ) -> Result<ManifestContent, ValidationError> {
        self.validate_at(cert, strict)
    }

    pub fn validate_at(
        self,
        cert: &ResourceCert,
        strict: bool,
    ) -> Result<ManifestContent, ValidationError> {
        self.content.mft_content.get_validity().verify().map_err(|_| InspectionError::new("Manifest is invalid"))?;
        self.signed.verify(strict, cert.subject_public_key_info())?;
        Ok(self.content.mft_content)
    }

    /// Returns a value encoder for a reference to the manifest.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        self.signed.encode_ref()
    }

    /// Returns a DER encoded Captured for this.
    pub fn to_captured(&self) -> Captured {
        self.encode_ref().to_captured(Mode::Der)
    }

    /// Returns a reference to the EE certificate of this manifest.

    /// Returns a reference to the manifest content.
    pub fn content(&self) -> &ManifestContent {
        &self.content.mft_content
    }
}


//--- Deref, AsRef, and Borrow

impl ops::Deref for IManifest {
    type Target = ManifestContent;

    fn deref(&self) -> &Self::Target {
        &self.content.mft_content
    }
}

impl AsRef<IManifest> for IManifest {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<ManifestContent> for IManifest {
    fn as_ref(&self) -> &ManifestContent {
        &self.content.mft_content
    }
}

impl borrow::Borrow<ManifestContent> for IManifest {
    fn borrow(&self) -> &ManifestContent {
        &self.content.mft_content
    }
}


//--- Deserialize and Serialize

#[cfg(feature = "serde")]
impl serde::Serialize for IManifest {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error> {
        let bytes = self.to_captured().into_bytes();
        let b64 = base64::Serde.encode(&bytes);
        b64.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for IManifest {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        use serde::de;

        let s = String::deserialize(deserializer)?;
        let decoded = base64::Serde.decode(&s).map_err(de::Error::custom)?;
        let bytes = Bytes::from(decoded);
        IManifest::decode(bytes, true).map_err(de::Error::custom)
    }
}


//------------ ManifestContent -----------------------------------------------

/// The content of an RPKI manifest.
#[derive(Clone, Debug)]
pub struct IManifestContent {
    /// The number of this manifest.
    // manifest_number: Serial,

    // /// The time this iteration of the manifest was created.
    // this_update: Time,

    // /// The time the next iteration of the manifest is likely to be created.
    // next_update: Time,

    // /// The digest algorithm used for the file hash.
    // file_hash_alg: DigestAlgorithm,

    // /// The list of files.
    // ///
    // /// This contains the content of the fileList sequence, i.e, not the
    // /// outer sequence object.
    // file_list: Captured,

    // /// The length of the list.
    // len: usize,
    pub mft_content: ManifestContent,

    pub crl_content: Option<(uri::Rsync, ICrl, Bytes)>
}


/// # Creation and Conversion
///
impl IManifestContent {
    pub fn new<I, FH, F, H>(
        manifest_number: Serial,
        this_update: Time,
        next_update: Time,
        file_hash_alg: DigestAlgorithm,
        file_list: Vec<(String, ManifestHash)>,
        file_list_c: Option<Captured>,

    ) -> Self
    where
        I: IntoIterator<Item = FH>,
        FH: AsRef<FileAndHash<F, H>>,
        F: AsRef<[u8]>,
        H: AsRef<[u8]>,
    {
        let len = 0;
        // let mut file_list = Captured::builder(Mode::Der);
        // for item in iter.into_iter() {
        //     file_list.extend(item.as_ref().encode_ref());
        //     len += 1;
        // }
        Self {
            mft_content: ManifestContent{
                manifest_number,
            this_update,
            next_update,
            file_hash_alg,
            file_list: file_list,
            file_list_c,
            len},

            crl_content: None,
        }
    }

}


/// # Data Access
///
impl IManifestContent {
    /// Returns the manifest number.
    pub fn manifest_number(&self) -> Serial {
        self.mft_content.manifest_number
    }

    /// Returns the time when this manifest was created.
    pub fn this_update(&self) -> Time {
        self.mft_content.this_update
    }

    /// Returns the time when the next update to the manifest should appear.
    pub fn next_update(&self) -> Time {
        self.mft_content.next_update
    }

    /// Returns the hash algorithm for the file list entries.
    pub fn file_hash_alg(&self) -> DigestAlgorithm {
        self.mft_content.file_hash_alg
    }

    /// Returns an iterator over the file list.
    // pub fn iter(&self) -> FileListIter {
    //     FileListIter(self.mft_content.file_list.clone())
    // }

    /// Returns an iterator over URL and hash pairs.
    ///
    /// The iterator assumes that all files referred to in the manifest are
    /// relative to the given rsync URI.
    pub fn iter_uris<'a>(
        &'a self,
        base: &'a uri::Rsync
    ) -> impl Iterator<Item = (uri::Rsync, ManifestHash)> + 'a {
        let _ = self.mft_content.file_hash_alg;
        self.mft_content.file_list.iter().map(move |(uri, hash)| {
            (base.join(&uri.as_str().as_ref()).unwrap(), hash.clone())
        })
    }

    /// Returns the length of the file list.
    pub fn len(&self) -> usize {
        self.mft_content.len
    }

    /// Returns whether the file list is empty.
    pub fn is_empty(&self) -> bool {
        self.mft_content.file_list.is_empty()
    }

    /// Returns whether the manifest is stale.
    ///
    /// A manifest is stale if it’s nextUpdate time has passed.
    pub fn is_stale(&self) -> bool {
        self.mft_content.next_update < Time::now()
    }
}

/// # Decoding and Encoding
///
impl IManifestContent {
    /// Takes the content from the beginning of an encoded constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            cons.take_opt_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(0))?;
            let manifest_number = Serial::take_from(cons)?;
            let this_update = Time::take_from(cons)?;
            let next_update = Time::take_from(cons)?;
            let file_hash_alg = DigestAlgorithm::take_oid_from(cons)?;
            if this_update > next_update {
                return Err(cons.content_err(
                    "thisUpdate after nextUpdate"
                ));
            }

            let mut len = 0;
            let file_list_c = cons.take_sequence(|cons| {
                cons.capture(|cons| {
                    while let Some(()) = FileAndHash::skip_opt_in(cons)? {
                        len += 1;
                    }
                    Ok(())
                })
            })?;



            let fliter = FileListIter(file_list_c.clone());

            let file_list = fliter.map(|item| {
                    let (file, hash) = item.into_pair();
                    let f = from_utf8(file.as_ref());
                    if f.is_err() {
                        return Err(cons.content_err("invalid URI in file list"));
                    }
                    Ok((f.unwrap().to_string(), ManifestHash::new(hash, file_hash_alg)))
                }).collect::<Result<Vec<_>, _>>()?;

            let mut serials = HashSet::new();
            let mut revocation_times = HashMap::new();

            let crl_content = cons.take_sequence(|cons| {
                cons.capture(|cons| {
                        while let Some(entry) = CrlEntry::take_opt_from(cons).unwrap() {
                            serials.insert(entry.user_certificate);
                            revocation_times.insert(entry.user_certificate, entry.revocation_date);

                        }
                        Ok(())
                })
            })?;

            let crl_content = crl_content.into_bytes();
            let icrl = ICrl {
                serials,
                revocation_times,
            };

            Ok(Self {
                mft_content: ManifestContent {
                manifest_number,
                this_update,
                next_update,
                file_hash_alg,
                file_list,
                file_list_c: Some(file_list_c),
                len
            },
            crl_content: Some((uri::Rsync::from_string("rsync://example.com/a/b/crl.crl".to_string(), false).unwrap(), icrl, crl_content))
        }
        )
        })
    }


    /// Returns a value encoder for a reference to the content.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            self.mft_content.manifest_number.encode(),
            self.mft_content.this_update.encode_generalized_time(),
            self.mft_content.next_update.encode_generalized_time(),
            self.mft_content.file_hash_alg.encode_oid(),
            encode::sequence(
                &self.mft_content.file_list_c
            )
        ))
    }
}



