
use std::collections::{HashMap, HashSet};
use bcder::decode;
use bcder::Mode;
use bcder::decode::{DecodeError, IntoSource, Source};
use super::crl::{CrlEntry, TbsCertList};
use super::x509::{
     Serial, SignedData, Time};


//------------ Crl -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ICrl {
    /// An optional cache of the serial numbers in the CRL.
    pub serials: HashSet<Serial>,
    pub revocation_times: HashMap<Serial, Time>,
} 

///
impl ICrl {
    /// Returns whether the given serial number is on this revocation list.
    pub fn contains(&self, serial: Serial) -> bool {
        self.serials.contains(&serial)
    }
}


/// # Decode, Validate, and Encode
///
impl ICrl {
    /// Parses a source as a certificate revocation list.
    pub fn decode<S: IntoSource>(
        source: S
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        Mode::Der.decode(source, Self::take_from)
    }

    /// Takes an encoded CRL from the beginning of a constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Takes an encoded CRL from the beginning of a constructed value.
    pub fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(Self::from_constructed)
    }

    /// Parses the content of a certificate revocation list.
    pub fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        let signed_data = SignedData::from_constructed(cons)?;
        let tbs = signed_data.data().clone().decode(
            TbsCertList::take_from
        ).map_err(DecodeError::convert)?;
        if tbs.signature != *signed_data.signature().algorithm() {
            return Err(cons.content_err(
                "CRL signature algorithm mismatch"
            ))
        }

        let revoced_certs = tbs.revoked_certs().0.clone();
        let mut serials = HashSet::new();
        let mut revocation_times = HashMap::new();
        Mode::Der.decode(revoced_certs, |cons| {
            while let Some(entry) = CrlEntry::take_opt_from(cons).unwrap() {
                serials.insert(entry.user_certificate);
                revocation_times.insert(entry.user_certificate, entry.revocation_date);

            }
            Ok(false)
        }).unwrap();

        Ok(Self { serials, revocation_times })
    }

}
 


