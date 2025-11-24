use cure_asn1::asn1_parser::{Element, Implicit, OctetString, Sequence, TLV};

use super::asn1_objects::ObjectConf;

pub fn create_aspa(conf: ObjectConf) -> Element{
    let providers = vec![TLV::new(2, vec![200]).into(), TLV::new(2, vec![32, 200]).into()];


    let providers = Sequence::new(providers);

    let own_asn = TLV::new(2, vec![42]);
    let version = Implicit::new(0xA0, vec![TLV::new(2, vec![1]).into()]);

    let seq = Sequence::new(vec![version.into(), own_asn.into(), providers.into()]);
    let oc = OctetString::new_el(seq.into());

    let signed = crate::objects::asn1_sigdata::create_signed_data(oc.into(), &conf);

    signed
}