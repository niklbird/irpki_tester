use bcder::{
    decode::{self, DecodeError, IntoSource, Source},
    string::OctetStringSource,
    Mode, OctetString, Oid, Tag,
};
use bytes::Bytes;

use crate::{
    crypto::KeyIdentifier,
    uri,
};

use super::{
    x509::Time,
}; 

/// A rpki object.
#[derive(Clone, Debug)]
pub struct RpkiObject {
    pub content_type: Oid<Bytes>,
    pub content: OctetString,
    pub meta: ObjectMeta,
}

impl RpkiObject {
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            // ContentInfo
            let id = Oid::take_from(cons)?; // contentType
            let content = cons.take_constructed_if(Tag::CTX_0, OctetString::take_from)?;

            let meta = ObjectMeta::take_from(cons)?;

            Ok(Self {
                content_type: id,
                content,
                meta,
            })
        })
    }

    pub fn decode<S: IntoSource>(
        source: S,
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        Mode::Der.decode(source.into_source(), Self::take_from)
    }

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
}

#[derive(Debug, Clone)]
pub struct ObjectMeta {
    pub serial_number: u64,
    pub this_update: Time,
    pub next_update: Time,
    pub sid: Option<KeyIdentifier>,
    pub signed_object_location: Option<uri::Rsync>,
}

impl ObjectMeta {
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let serial_number = cons.take_u64()?.into();
            let sid = cons.take_value_if(Tag::CTX_0, KeyIdentifier::from_content);
            let sid = match sid {
                Ok(val) => Some(val),
                Err(_) => None,
            };

            let (this_update, next_update) = cons.take_sequence(|cons| {
                let this_update = Time::take_from(cons)?;
                let next_update = Time::take_from(cons)?;
                Ok((this_update, next_update))
            })?;

            // let signed_object_location = take_general_name(cons, uri::Rsync::from_bytes)?;
            // if signed_object_location.is_none() {
            //     return Err(cons.content_err("uri invalid"));
            // }
            // let signed_object_location = signed_object_location.unwrap();

            Ok(Self {
                serial_number,
                this_update,
                next_update,
                sid,
                signed_object_location: None,
            })
        })
    }
}

// mod test {
//     use bcder::Mode;

//     use crate::repository::rpkiobj::RpkiObject;

//     #[test]
//     pub fn test_rpki() {
//         let bytes = include_bytes!("../../example.iroa").to_vec();
//         use bcder::decode::SliceSource;

//         let res = Mode::Der.decode(SliceSource::new(&bytes), RpkiObject::take_from);
//         println!("{:?}", res);
//     }
// }
