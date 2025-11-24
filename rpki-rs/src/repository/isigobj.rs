//! Signed objects.
//
// See RFC 6488 and RFC 5652.

use super::cert::{Cert, ResourceCert};
use super::error::{ValidationError, VerificationError};
use super::x509::Time;
use crate::crypto::{
    Digest, DigestAlgorithm, KeyIdentifier, PublicKey, RpkiSignature, RpkiSignatureAlgorithm, Signer, SigningError
};
use crate::oid;
use bcder::decode::{ContentError, DecodeError, IntoSource, Source};
use bcder::encode::PrimitiveContent;
use bcder::string::OctetStringSource;
use bcder::{decode, encode};
use bcder::{Captured, Mode, OctetString, Oid, Tag};
use bytes::Bytes;
use std::{cmp, fmt, io};

//------------ ISignedObject --------------------------------------------------

/// A signed object.
#[derive(Clone, Debug)]
pub struct ISignedObject {
    //--- From SignedData
    //
    digest_algorithm: DigestAlgorithm,
    content_type: Oid<Bytes>,
    content: OctetString,

    //--- From SignerInfo
    //
    sid: KeyIdentifier,
    signed_attrs: ISignedAttrs,
    signature: RpkiSignature,

    //--- SignedAttributes
    //
    message_digest: MessageDigest,
    signing_time: Option<Time>,
    binary_signing_time: Option<u64>,
}

/// # Data Access
///
impl ISignedObject {
    /// Returns a reference to the object’s content type.
    pub fn content_type(&self) -> &Oid<Bytes> {
        &self.content_type
    }

    /// Returns a reference to the object’s content.
    pub fn content(&self) -> &OctetString {
        &self.content
    }

    /// Decodes the object’s content.
    pub fn decode_content<F, T>(
        &self,
        op: F,
    ) -> Result<T, DecodeError<<OctetStringSource as decode::Source>::Error>>
    where
        F: FnOnce(
            &mut decode::Constructed<OctetStringSource>,
        ) -> Result<T, DecodeError<<OctetStringSource as decode::Source>::Error>>,
    {
        Mode::Der.decode(self.content.clone(), op)
    }

    /// Returns the signing time if available.
    pub fn signing_time(&self) -> Option<Time> {
        self.signing_time
    }

    /// Returns the binary signing time if available.
    pub fn binary_signing_time(&self) -> Option<u64> {
        self.binary_signing_time
    }
}

/// # Decoding, Validation, and Encoding
///
impl ISignedObject {
    /// Decodes a signed object from the given source.
    pub fn decode<S: IntoSource>(
        source: S,
        strict: bool,
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        if strict { Mode::Der } else { Mode::Ber }.decode(source.into_source(), Self::take_from)
    }

    /// Decodes a signed object if it has the correct content type.
    pub fn decode_if_type<S: IntoSource>(
        source: S,
        content_type: &impl PartialEq<Oid>,
        strict: bool,
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        let res = Self::decode(source, strict)?;
        if content_type.ne(res.content_type()) {
            return Err(DecodeError::content(
                "invalid content type",
                Default::default(),
            ));
        }
        Ok(res)
    }

    /// Takes a signed object from an encoded constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            // ContentInfo
            oid::SIGNED_DATA.skip_if(cons)?; // contentType
            cons.take_constructed_if(Tag::CTX_0, |cons| {
                // content
                cons.take_sequence(|cons| {
                    // SignedData
                    cons.skip_u8_if(3)?; // version -- must be 3
                    let digest_algorithm = DigestAlgorithm::take_set_from(cons)?;
                    let (content_type, content) = {
                        cons.take_sequence(|cons| {
                            // encapContentInfo
                            Ok((
                                Oid::take_from(cons)?,
                                cons.take_constructed_if(Tag::CTX_0, OctetString::take_from)?,
                            ))
                        })?
                    };
                    // no crls
                    let (sid, attrs, signature) = {
                        // signerInfos
                        cons.take_set(|cons| {
                            cons.take_sequence(|cons| {
                                cons.skip_u8_if(3)?;
                                let sid = cons.take_value_if(Tag::CTX_0, |content| {
                                    KeyIdentifier::from_content(content)
                                })?;
                                let alg = DigestAlgorithm::take_from(cons)?;
                                if alg != digest_algorithm {
                                    return Err(cons.content_err("digest algorithm mismatch"));
                                }
                                let attrs = ISignedAttrs::take_from(cons)?;
                                if attrs.2 != content_type {                                                                                                                                                            
                                    return Err(cons.content_err(
                                        "content type in signed attributes \
                                        differs",                   
                                    ));
                                }
                                let signature = RpkiSignature::new(
                                    RpkiSignatureAlgorithm::cms_take_from(cons)?,
                                    OctetString::take_from(cons)?.into_bytes(),
                                );
                                // no unsignedAttributes
                                Ok((sid, attrs, signature))
                            })
                        })?
                    };
                    Ok(Self {
                        digest_algorithm,
                        content_type,
                        content,
                        sid,
                        signed_attrs: attrs.0,
                        signature,
                        message_digest: attrs.1,
                        signing_time: attrs.3,
                        binary_signing_time: attrs.4,
                    })
                })
            })
        })
    }

    pub fn process<F>(
        self,
        _: &ResourceCert,
        _: bool,
        _: F,
    ) -> Result<Bytes, ValidationError>
    where
        F: FnOnce(&Cert) -> Result<(), ValidationError>,
    {
        let res = self.content.clone();
        Ok(res.into_bytes())
    }

    /// Verifies the signature of the object against contained certificate.
    ///
    /// This is item 2 of [RFC 6488]’s section 3.
    pub fn verify(&self, _strict: bool, public_key: &PublicKey) -> Result<(), VerificationError> {
        let digest = {
            let mut context = self.digest_algorithm.start();
            self.content.iter().for_each(|x| context.update(x));
            context.finish()
        };
        if digest.as_ref() != self.message_digest.as_ref() {
            return Err(VerificationError::new(
                "message digest mismatch in signed object",
            ));
        }
        let msg = self.signed_attrs.encode_verify();
        public_key.verify(&msg, &self.signature)
            .map_err(Into::into)
    }

    /// Returns a value encoder for a reference to a signed object.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            oid::SIGNED_DATA.encode(), // contentType
            encode::sequence_as(
                Tag::CTX_0, // content
                encode::sequence((
                    3u8.encode(),                       // version
                    self.digest_algorithm.encode_set(), // digestAlgorithms
                    encode::sequence((
                        // encapContentInfo
                        self.content_type.encode_ref(),
                        encode::sequence_as(Tag::CTX_0, self.content.encode_ref()),
                    )),
                    // crl -- omitted
                    encode::set(
                        // signerInfo
                        encode::sequence((
                            // SignerInfo
                            3u8.encode(), // version
                            self.sid.encode_ref_as(Tag::CTX_0),
                            self.digest_algorithm.encode(), // digestAlgorithm
                            self.signed_attrs.encode_ref(), // signedAttrs
                            self.signature.algorithm().cms_encode(),
                            // signatureAlgorithm
                            OctetString::encode_slice(
                                // signature
                                self.signature.value().as_ref(),
                            ),
                            // unsignedAttrs omitted
                        )),
                    ),
                )),
            ),
        ))
    }
}

//------------ SignedAttrs ---------------------------------------------------

/// A private helper type that contains the raw signed attributes content.
///
#[derive(Clone, Debug)]
pub struct ISignedAttrs(Captured);

impl ISignedAttrs {
    pub(crate) fn new(
        content_type: &Oid<impl AsRef<[u8]>>,
        digest: &MessageDigest,
        signing_time: Option<Time>,
        binary_signing_time: Option<u64>,
    ) -> Self {
        // In DER encoding, the values of SET OFs is ordered via the octet
        // string of their DER encoding. Given that all our values are
        // SEQUENCEs, their first octet will always be 30. So we only have to
        // compare the length octets. Unfortunately, two of the values are
        // variable length, so we need to get creative.

        let mut content_type = Some(encode::sequence((
            oid::CONTENT_TYPE.encode(),
            encode::set(content_type.encode_ref()),
        )));
        let mut signing_time = signing_time.map(|time| {
            encode::sequence((
                oid::SIGNING_TIME.encode(),
                encode::set(time.encode_varied()),
            ))
        });
        let mut message_digest = Some(encode::sequence((
            oid::MESSAGE_DIGEST.encode(),
            encode::set(digest.encode_ref()),
        )));
        let mut binary_signing_time = binary_signing_time.map(|time| {
            encode::sequence((
                oid::AA_BINARY_SIGNING_TIME.encode(),
                encode::set(time.encode()),
            ))
        });

        let mut len = [
            (0, StartOfValue::new(&content_type)),
            (1, StartOfValue::new(&signing_time)),
            (2, StartOfValue::new(&message_digest)),
            (3, StartOfValue::new(&binary_signing_time)),
        ];
        len.sort_by_key(|&(_, len)| len.unwrap());

        let mut res = Captured::builder(Mode::Der);
        for &(idx, _) in &len {
            match idx {
                0 => {
                    if let Some(val) = content_type.take() {
                        res.extend(val)
                    }
                }
                1 => {
                    if let Some(val) = signing_time.take() {
                        res.extend(val)
                    }
                }
                2 => {
                    if let Some(val) = message_digest.take() {
                        res.extend(val)
                    }
                }
                3 => {
                    if let Some(val) = binary_signing_time.take() {
                        res.extend(val)
                    }
                }
                _ => unreachable!(),
            }
        }

        ISignedAttrs(res.freeze())
    }

    /// Takes the signed attributes from the beginning of a constructed value.
    ///
    /// Returns the raw signed attrs, the message digest, the content type
    /// object identifier, and the two optional signing times.
    ///
    /// If strict is true, any unknown signed attributes are rejected, if
    /// strict is false they will be ignored.
    #[allow(clippy::type_complexity)]
    fn take_from_with_mode<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        strict: bool,
    ) -> Result<(Self, MessageDigest, Oid<Bytes>, Option<Time>, Option<u64>), DecodeError<S::Error>>
    {
        let mut message_digest = None;
        let mut content_type = None;
        let mut signing_time = None;
        let mut binary_signing_time = None;
        let raw = cons.take_constructed_if(Tag::CTX_0, |cons| {
            cons.capture(|cons| {
                while let Some(()) = cons.take_opt_sequence(|cons| {
                    let oid = Oid::take_from(cons)?;
                    if oid == oid::CONTENT_TYPE {
                        Self::take_content_type(cons, &mut content_type)
                    } else if oid == oid::MESSAGE_DIGEST {
                        Self::take_message_digest(cons, &mut message_digest)
                    } else if oid == oid::SIGNING_TIME {
                        Self::take_signing_time(cons, &mut signing_time)
                    } else if oid == oid::AA_BINARY_SIGNING_TIME {
                        Self::take_bin_signing_time(cons, &mut binary_signing_time)
                    } else if !strict {
                        cons.skip_all()
                    } else {
                        Err(cons.content_err(InvalidSignedAttr::new(oid)))
                    }
                })? {}
                Ok(())
            })
        })?;
        if raw.len() > 0xFFFF {
            return Err(cons.content_err("signed attributes over 65535 bytes not supported"));
        }
        let message_digest = match message_digest {
            Some(some) => MessageDigest(some.into_bytes()),
            None => return Err(cons.content_err("missing message digest in signed attributes")),
        };
        let content_type = match content_type {
            Some(some) => some,
            None => return Err(cons.content_err("missing content type in signed attributes")),
        };
        Ok((
            Self(raw),
            message_digest,
            content_type,
            signing_time,
            binary_signing_time,
        ))
    }

    /// Takes the signed attributes from the beginning of a constructed value.
    ///
    /// Returns the raw signed attrs, the message digest, the content type
    /// object identifier, and the two optional signing times.
    #[allow(clippy::type_complexity)]
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<(Self, MessageDigest, Oid<Bytes>, Option<Time>, Option<u64>), DecodeError<S::Error>>
    {
        Self::take_from_with_mode(cons, true)
    }

    /// Takes the signed attributes from the beginning of a constructed value.
    ///
    /// Note this function should be used for parsing CMS used in RFC6492 and
    /// RFC8181 messages only, as it will ignore any unknown signed attributes.
    /// Unfortunately the profile for the Certificates and CMS used is not
    /// well-defined in these RFCs. So, in this case, we should be more
    /// accepting.
    ///
    /// Returns the raw signed attrs, the message digest, the content type
    /// object identifier, and the two optional signing times.
    #[allow(clippy::type_complexity)]
    pub fn take_from_signed_message<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<(Self, MessageDigest, Oid<Bytes>, Option<Time>, Option<u64>), DecodeError<S::Error>>
    {
        Self::take_from_with_mode(cons, false)
    }

    /// Parses the Content Type attribute.
    ///
    /// This attribute is defined in section 11.1. of RFC 5652. The attribute
    /// value is a SET of exactly one OBJECT IDENTIFIER.
    fn take_content_type<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        content_type: &mut Option<Oid<Bytes>>,
    ) -> Result<(), DecodeError<S::Error>> {
        if content_type.is_some() {
            Err(cons.content_err("duplicate Content Type attribute"))
        } else {
            *content_type = Some(cons.take_set(|cons| Oid::take_from(cons))?);
            Ok(())
        }
    }

    fn take_message_digest<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        message_digest: &mut Option<OctetString>,
    ) -> Result<(), DecodeError<S::Error>> {
        if message_digest.is_some() {
            Err(cons.content_err("duplicate Message Digest attribute"))
        } else {
            *message_digest = Some(cons.take_set(|cons| OctetString::take_from(cons))?);
            Ok(())
        }
    }

    fn take_signing_time<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        signing_time: &mut Option<Time>,
    ) -> Result<(), DecodeError<S::Error>> {
        if signing_time.is_some() {
            Err(cons.content_err("duplicate Signing Time attribute"))
        } else {
            *signing_time = Some(cons.take_set(Time::take_from)?);
            Ok(())
        }
    }

    fn take_bin_signing_time<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        bin_signing_time: &mut Option<u64>,
    ) -> Result<(), DecodeError<S::Error>> {
        if bin_signing_time.is_some() {
            Err(cons.content_err("duplicate Binary Signing Time attribute"))
        } else {
            *bin_signing_time = Some(cons.take_set(|cons| cons.take_u64())?);
            Ok(())
        }
    }

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence_as(Tag::CTX_0, &self.0)
    }

    /// Creates the message for verification.
    pub fn encode_verify(&self) -> Vec<u8> {
        let len = self.0.len();
        let mut res = Vec::with_capacity(len + 4);
        res.push(0x31); // SET
        if len < 128 {
            res.push(len as u8)
        } else if len < 0x10000 {
            res.push(2);
            res.push((len >> 8) as u8);
            res.push(len as u8);
        } else {
            panic!("overly long signed attrs");
        }
        res.extend_from_slice(self.0.as_ref());
        res
    }
}

impl AsRef<[u8]> for ISignedAttrs {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

//------------ MessageDigest -------------------------------------------------

/// A private helper type that contains the message digest attribute.
#[derive(Clone, Debug)]
pub struct MessageDigest(Bytes);

impl MessageDigest {
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        OctetString::encode_slice(self.0.as_ref())
    }
}

impl From<OctetString> for MessageDigest {
    fn from(src: OctetString) -> Self {
        MessageDigest(src.into_bytes())
    }
}

impl From<Digest> for MessageDigest {
    fn from(digest: Digest) -> Self {
        MessageDigest(Bytes::copy_from_slice(digest.as_ref()))
    }
}

impl AsRef<[u8]> for MessageDigest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

//------------ ISignedObjectBuilder -------------------------------------------

#[derive(Clone, Debug)]
pub struct ISignedObjectBuilder {
    /// The digest algorithm to be used for the message digest attribute.
    ///
    /// By default, this will be the default algorithm.
    digest_algorithm: DigestAlgorithm,

    /// The signing time attribute of the signed object.
    ///
    /// This is optional and by default omitted.
    signing_time: Option<Time>,

    /// The binary signing time attribute of the signed object.
    ///
    /// This is optional and by default omitted.
    binary_signing_time: Option<u64>,
}

impl ISignedObjectBuilder {
    pub fn new(
    ) -> Self {
        Self {
            digest_algorithm: DigestAlgorithm::default(),
            signing_time: None,
            binary_signing_time: None,
        }
    }

    pub fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_algorithm
    }

    pub fn set_digest_algorithm(&mut self, algorithm: DigestAlgorithm) {
        self.digest_algorithm = algorithm
    }


    /// Returns the signing time attribute.
    pub fn signing_time(&self) -> Option<Time> {
        self.signing_time
    }

    /// Sets the signing time attribute.
    pub fn set_signing_time(&mut self, signing_time: Option<Time>) {
        self.signing_time = signing_time
    }

    /// Returns the binary signing time attribute.
    pub fn binary_signing_time(&self) -> Option<u64> {
        self.binary_signing_time
    }

    /// Sets the binary signing time attribute.
    pub fn set_binary_signing_time(&mut self, time: Option<u64>) {
        self.binary_signing_time = time
    }

    pub fn finalize<S: Signer>(
        self,
        content_type: Oid<Bytes>,
        content: Bytes,
        signer: &S,
        _: &S::KeyId,
    ) -> Result<ISignedObject, SigningError<S::Error>> {
        // Produce signed attributes.
        let message_digest = self.digest_algorithm.digest(&content).into();
        let signed_attrs = ISignedAttrs::new(
            &content_type,
            &message_digest,
            self.signing_time,
            self.binary_signing_time,
        );

        // Sign signed attributes with a one-off key.
        let (signature, key_info) = signer.sign_one_off(
            RpkiSignatureAlgorithm::default(),
            &signed_attrs.encode_verify(),
        )?;
        let sid = key_info.key_identifier();

        Ok(ISignedObject {
            digest_algorithm: self.digest_algorithm,
            content_type,
            content: OctetString::new(content),
            sid,
            signed_attrs,
            signature,
            message_digest,
            signing_time: self.signing_time,
            binary_signing_time: self.binary_signing_time,
        })
    }
}

//------------ StartOfValue --------------------------------------------------

/// Helper type for ordering signed attributes.
///
/// It keeps the first eight octets of a value which should be enough to
/// cover the length.
#[derive(Clone, Copy, Debug)]
struct StartOfValue {
    res: [u8; 8],
    pos: usize,
}

impl StartOfValue {
    fn new<V: encode::Values>(values: &V) -> Self {
        let mut res = StartOfValue {
            res: [0; 8],
            pos: 0,
        };
        values.write_encoded(Mode::Der, &mut res).unwrap();
        res
    }

    fn unwrap(self) -> [u8; 8] {
        self.res
    }
}

impl io::Write for StartOfValue {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        let slice = &mut self.res[self.pos..];
        let len = cmp::min(slice.len(), buf.len());
        slice[..len].copy_from_slice(&buf[..len]);
        self.pos += len;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

//============ Error Types ===================================================

//------------ InvalidSignedAttr ---------------------------------------------

/// An invalid signed attribute was encountered.
#[derive(Clone, Debug)]
pub(crate) struct InvalidSignedAttr {
    oid: Oid<Bytes>,
}

impl InvalidSignedAttr {
    fn new(oid: Oid<Bytes>) -> Self {
        InvalidSignedAttr { oid }
    }
}

impl From<InvalidSignedAttr> for ContentError {
    fn from(err: InvalidSignedAttr) -> Self {
        ContentError::from_boxed(Box::new(err))
    }
}

impl fmt::Display for InvalidSignedAttr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid extension {}", self.oid)
    }
}

