use crate::crypto::PublicKey;
use crate::oid;
use bcder::{
    decode::{self, DecodeError, IntoSource, Source},
    Mode, Tag,
};
use super::isigobj::ISignedObject;
use super::roa::RoaIpAddress;
use super::{
    error::ValidationError, resources::{AddressFamily, Asn}, roa::RoaIpAddresses, rpkiobj::ObjectMeta};
use crate::util::base64::Serde;

#[derive(Clone, Debug)]
pub struct IRoa {
    content: IRouteOriginAttestation,
    signed: Option<ISignedObject>
}

impl IRoa {
    pub fn decode<S: IntoSource>(
        source: S,
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {

        let roa = Mode::Der.decode(source.into_source(), IRouteOriginAttestation::take_from)?;
        Ok(IRoa {
            content: roa,
            signed: None,
        })
    }

    pub fn decode_signed<S: IntoSource>(
        source: S,
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        let signed = ISignedObject::decode_if_type(
            source, &oid::IROUTE_ORIGIN_AUTHZ, false
        )?;

        let content = signed.decode_content(
            |cons| IRouteOriginAttestation::take_from(cons)
        ).map_err(DecodeError::convert)?;
       
        Ok(IRoa { content, signed: Some(signed) })
    }

    // pub fn decode_proto(data: &Vec<u8>) -> IRoa {
    //     let parsed = cure_asn1::prot::util::decode_roa(data).unwrap();
    //     let info = parsed.meta.unwrap();

    //     let not_before = info.not_before.unwrap();
    //     let t = DateTime::from_timestamp(not_before.seconds, not_before.nanos.try_into().unwrap()).unwrap();
    //     let not_before = Time::new(t);

    //     let not_after = info.not_after.unwrap();
    //     let t = DateTime::from_timestamp(not_after.seconds, not_after.nanos.try_into().unwrap()).unwrap();
    //     let not_after = Time::new(t);

    //     let meta = ObjectMeta{
    //         serial_number: info.serial,
    //         sid: None,
    //         this_update: not_before,
    //         next_update: not_after,
    //         signed_object_location: None,
    //     };

    //     let mut v4_addrs = vec![];
    //     let mut v6_addrs = vec![];
    //     for ip_and_fam in parsed.ip_and_fam{
    //         for ip in ip_and_fam.ips{
    //             let bs = BitString::new(ip.ip[0], Bytes::from(ip.ip[1..].to_vec()));
    //             let ml;
    //             if ip.ml.is_some(){
    //                 ml = Some(ip.ml.unwrap() as u8);
    //             }
    //             else{
    //                 ml = None;
    //             }
    //             let parsed_ip = RoaIpAddress::new(Prefix::from_bit_string(&bs).unwrap(), ml);
    //             if ip_and_fam.fam == 4{
    //                 v4_addrs.push(parsed_ip);
    //             }
    //             else{
    //                 v6_addrs.push(parsed_ip);

    //             }
    //         }
    //     }


    //     let ro = IRouteOriginAttestation{
    //         as_id: Asn::from(parsed.asn as u32),
    //         v4_addrs,
    //         v6_addrs,
    //         meta: meta,
    //     };

    //     let roa = IRoa{
    //         content: ro,
    //         signed: None,
    //     };
    //     roa
        
    // }

    pub fn process<F>(
        self,
        parent_key: &PublicKey,
        check_crl: F,
    ) -> Result<(ObjectMeta, IRouteOriginAttestation), ValidationError>
    where
        F: FnOnce(u64) -> Result<(), ValidationError>,
    {
        check_crl(self.content.meta.serial_number)?;
        if self.signed.is_some(){
            self.signed.unwrap().verify(false, parent_key)?;
        }
        Ok((self.content.meta.clone(), self.content))
    }

    /// Returns a reference to the content of the ROA object
    pub fn content(&self) -> &IRouteOriginAttestation {
        &self.content
    }
}


#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for IRoa {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de;

        let s = String::deserialize(deserializer)?;
        let decoded = Serde.decode(&s).map_err(de::Error::custom)?;
        let bytes = bytes::Bytes::from(decoded);
        IRoa::decode(bytes).map_err(de::Error::custom)
    }
}

//------------ RouteOriginAttestation ----------------------------------------

#[derive(Clone, Debug)]
pub struct IRouteOriginAttestation {
    as_id: Asn,
    v4_addrs: Vec<RoaIpAddress>,
    v6_addrs: Vec<RoaIpAddress>,
    meta: ObjectMeta,
}

impl IRouteOriginAttestation {
    pub fn as_id(&self) -> Asn {
        self.as_id
    }

    pub fn v4_addrs(&self) -> &Vec<RoaIpAddress> {
        &self.v4_addrs
    }

    pub fn v6_addrs(&self) ->  &Vec<RoaIpAddress> {
        &self.v6_addrs
    }

    /// Returns an iterator over the route origins contained in the ROA.
    #[cfg(feature = "rtr")]
    pub fn iter_origins(&self) -> impl Iterator<Item = crate::rtr::payload::RouteOrigin> + '_ {
        use crate::resources::addr::{MaxLenPrefix, Prefix as PayloadPrefix};
        use crate::rtr::payload::RouteOrigin;

        self.v4_addrs
            .iter()
            .filter_map(move |addr| {
                PayloadPrefix::new(addr.prefix().to_v4().into(), addr.prefix().addr_len())
                    .ok()
                    .and_then(|prefix| MaxLenPrefix::new(prefix, addr.max_length()).ok())
                    .map(|prefix| RouteOrigin::new(prefix, self.as_id))
            })
            .chain(self.v6_addrs.iter().filter_map(move |addr| {
                PayloadPrefix::new(addr.prefix().to_v6().into(), addr.prefix().addr_len())
                    .ok()
                    .and_then(|prefix| MaxLenPrefix::new(prefix, addr.max_length()).ok())
                    .map(|prefix| RouteOrigin::new(prefix, self.as_id))
            }))
    }
}

impl IRouteOriginAttestation {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            // version [0] EXPLICIT INTEGER DEFAULT 0
            cons.take_opt_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(0))?;
            let as_id = Asn::take_from(cons)?;
            let mut v4 = None;
            let mut v6 = None;
            cons.take_sequence(|cons| {
                while let Some(()) = cons.take_opt_sequence(|cons| {
                    match AddressFamily::take_from(cons)? {
                        AddressFamily::Ipv4 => {
                            if v4.is_some() {
                                return Err(
                                    cons.content_err("multiple IPv4 blocks in ROA prefixes")
                                );
                            }
                            v4 = Some(RoaIpAddresses::take_from(cons, AddressFamily::Ipv4)?);
                        }
                        AddressFamily::Ipv6 => {
                            if v6.is_some() {
                                return Err(
                                    cons.content_err("multiple IPv6 blocks in ROA prefixes")
                                );
                            }
                            v6 = Some(RoaIpAddresses::take_from(cons, AddressFamily::Ipv6)?);
                        }
                    }
                    Ok(())
                })? {}
                Ok(())
            })?;
            let meta = ObjectMeta::take_from(cons)?;

            Ok(IRouteOriginAttestation {
                as_id,
                v4_addrs: match v4 {
                    Some(addrs) => addrs.iter().collect(),
                    None => vec![],
                },
                v6_addrs: match v6 {
                    Some(addrs) => addrs.iter().collect(),
                    None => vec![],
                },
                meta

            })
        })
    }

}

