use chrono::Utc;
use cure_asn1::{asn1_parser::{Element, Implicit, Sequence, Set, WriteASN1, TLV}, rpki::rpki::ObjectType};

use super::{
    asn1_certificate::{self},
    asn1_objects::{self, ObjectConf},
};

pub fn create_signed_data(content: Element, conf: &ObjectConf) -> Element {
    let version = create_version();
    let digest_algorithms = create_digest_algorithms();
    let signer_info = create_signer_info(&content, &conf);

    let encap_content_info = create_encap_content_info(content, &conf.typ);
    let certificates = create_certificate(&conf);

    let seq = Sequence::new(vec![version, digest_algorithms, encap_content_info, certificates, signer_info]);

    let content = Implicit::new(160, vec![seq.into()]);
    let content_oid = asn1_objects::tlv_from_oid("1.2.840.113549.1.7.2");

    let signed_data = Sequence::new(vec![content_oid.into(), content.into()]);
    signed_data.into()
}

pub fn create_i_signed_data(content: Element, conf: &ObjectConf) -> Element {
    let version = create_version();
    let digest_algorithms = create_digest_algorithms();
    let signer_info = create_signer_info(&content, &conf);

    let encap_content_info = create_encap_content_info(content, &conf.typ);

    let seq = Sequence::new(vec![version, digest_algorithms, encap_content_info, signer_info]);

    let content = Implicit::new(160, vec![seq.into()]);
    let content_oid = asn1_objects::tlv_from_oid("1.2.840.113549.1.7.2");

    let signed_data = Sequence::new(vec![content_oid.into(), content.into()]);
    signed_data.into()
}


pub fn create_digest_algorithms() -> Element {
    let algorithm = asn1_objects::tlv_from_oid("2.16.840.1.101.3.4.2.1");
    let seq = Sequence::new(vec![algorithm.into()]);
    let set = Set::new(vec![seq.into()]);
    set.into()
}

pub fn create_version() -> Element {
    let version = asn1_objects::in_to_byt(3);
    let tlv = TLV::new(2, version);
    tlv.into()
}

pub fn create_encap_content_info(content: Element, typ: &ObjectType) -> Element {
    let oid;
    if typ == &ObjectType::MFT {
        oid = asn1_objects::tlv_from_oid("1.2.840.113549.1.9.16.1.26");
    } 
    else if typ == &ObjectType::IMFT{
        oid = asn1_objects::tlv_from_oid("1.2.840.113549.1.9.16.1.46");
    }
    
    else if typ == &ObjectType::ROA {
        oid = asn1_objects::tlv_from_oid("1.2.840.113549.1.9.16.1.24");
    } else if typ == &ObjectType::IROA  {
        oid = asn1_objects::tlv_from_oid("1.2.840.113549.1.9.16.1.44");
    } 
    else if typ == &ObjectType::GBR{
        oid = asn1_objects::tlv_from_oid("1.2.840.113549.1.9.16.1.24.35");
    }
    else if typ == &ObjectType::ASA{
        oid = asn1_objects::tlv_from_oid("1.2.840.113549.1.9.16.1.24.49");
    }

    else {
        panic!("Not implemented yet");
    }
    let imp = Implicit::new(160, vec![content]);
    let seq = Sequence::new(vec![oid.into(), imp.into()]);

    seq.into()
}

pub fn create_certificate(conf: &ObjectConf) -> Element {
    let cert = asn1_certificate::create_certificate(conf);
    let imp = Implicit::new(160, vec![cert]);
    imp.into()
}

pub fn create_signer_info(content_to_sign: &Element, conf: &ObjectConf) -> Element {
    let now = Utc::now();

    let signer_info = asn1_objects::create_signer_info(now, &content_to_sign.encode(), conf);
    signer_info
}
