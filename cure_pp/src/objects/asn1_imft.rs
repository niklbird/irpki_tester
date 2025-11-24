#![allow(unused)] 


use super::{
    asn1_objects::{self, ObjectConf},
    asn1_sigdata::{self, create_i_signed_data, create_signed_data},
};
use chrono::Utc;
use cure_asn1::asn1_parser::{Element, OctetString, Sequence, WriteASN1, TLV};
use hex::FromHex;
use sha2::Digest;

pub fn create_hashlist(list: &Vec<(String, Vec<u8>)>) -> Element {
    let mut tlvs = Vec::with_capacity(list.len());
    for val in list {
        // IA5 String (24)
        let name = TLV::new(22, val.0.as_bytes().to_vec());
        // Bit String (3)
        let digest = sha2::Sha256::digest(&val.1);
        let mut base = vec![0];

        // let hash = <[u8; 32]>::from_hex(&digest).unwrap().to_vec();
        base.extend(digest.to_vec());

        let hash = TLV::new(3, base);
        let seq = Sequence::new(vec![name.into(), hash.into()]);
        tlvs.push(seq.into());
    }
    let seq = Sequence::new(tlvs);
    seq.into()
}

pub fn create_imft_content(mft_number: u64, list: &Vec<(String, Vec<u8>)>, conf: &ObjectConf) -> Element {
    let mft_number = asn1_objects::in_to_byt(mft_number);
    let mft_number = TLV::new(2, mft_number).into();

    let hash_oid = "2.16.840.1.101.3.4.2.1";
    let val = cure_asn1::tree_parser::encode_oid_from_string(hash_oid);
    let hash_oid = TLV::new(6, val);

    let meta_info = crate::objects::asn1_objects::create_rpki_meta_information(conf);


    let hashlist = create_hashlist(list);
    let not_bef = asn1_objects::generalized_time_to_tlv(conf.validity.0);
    let not_aft = asn1_objects::generalized_time_to_tlv(conf.validity.1);

    let hash_oid = "2.16.840.1.101.3.4.2.1";
    let val = cure_asn1::tree_parser::encode_oid_from_string(hash_oid);
    let hash_oid = TLV::new(6, val).into();

    let crl_list = Sequence::new(vec![]);

    // let location = asn1_objects::create_location(&conf.signed_object_uri);


    let seq = Sequence::new(vec![mft_number, not_bef, not_aft, hash_oid, hashlist, crl_list.into()]);

    let oc = OctetString::new(seq.encode());
    oc.into()
}

pub fn create_mft_content(mft_number: u64, list: &Vec<(String, Vec<u8>)>, conf: &ObjectConf) -> Element {
    let mft_number = asn1_objects::in_to_byt(mft_number);
    let mft_number = TLV::new(2, mft_number).into();

    let not_bef = asn1_objects::generalized_time_to_tlv(conf.validity.0);
    let not_aft = asn1_objects::generalized_time_to_tlv(conf.validity.1);

    let hash_oid = "2.16.840.1.101.3.4.2.1";
    let val = cure_asn1::tree_parser::encode_oid_from_string(hash_oid);
    let hash_oid = TLV::new(6, val).into();

    let hashlist = create_hashlist(list);



    let seq = Sequence::new(vec![mft_number, not_bef, not_aft, hash_oid, hashlist]);

    let oc = OctetString::new(seq.encode());
    oc.into()
}

pub fn create_imft(mft_number: u64, list: &Vec<(String, Vec<u8>)>, conf: &ObjectConf) -> Element {
    let oid = "1.2.840.113549.1.9.16.1.26";
    let val = cure_asn1::tree_parser::encode_oid_from_string(oid);

    let mft_content = create_imft_content(mft_number, list, conf);

    create_i_signed_data(mft_content, conf)


    // TODO check if encode is correct
    // let signer_infos = asn1_objects::create_i_signer_info(Utc::now(), &mft_content.encode(), conf);

    // let content = Sequence::new(vec![TLV::new(6, val).into(), mft_content, signer_infos]);

    // content.into()
}

pub fn create_manifest(mft_number: u64, content: &Vec<(String, Vec<u8>)>, conf: &ObjectConf) -> Element {
    let content = create_mft_content(mft_number, content, conf);
    let signed_data = create_signed_data(content, conf);

    signed_data
}
