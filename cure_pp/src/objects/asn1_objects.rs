#![allow(unused)] 

use cure_asn1::{asn1_parser::{Element, Implicit, OctetString, Sequence, Set, WriteASN1, TLV}, rpki::rpki::ObjectType};
use chrono::{DateTime, Utc};
use hex::FromHex;
use sha2::Digest;

use crate::repository_util;

#[derive(Debug, Clone, PartialEq)]
pub enum ObjectVersion {
    Default,
    Improved,
    Novel,
}

pub struct ObjectConf {
    pub issuer_name: String,
    pub subject_name: String,
    pub validity: (DateTime<Utc>, DateTime<Utc>),
    pub parent_key_uri: String,
    pub subject_key_uri: String,
    pub issuer_uri: String,
    pub repo_uri: String,
    pub mft_uri: String,
    pub signed_object_uri: String,
    pub notification_uri: String,
    pub crl_distr_point: String,
    pub is_root: bool,
    pub typ: ObjectType,
    pub number: u64,
}

impl ObjectConf {
    pub fn default() -> ObjectConf {
        ObjectConf {
            issuer_name: "issuer".to_string(),
            subject_name: "subject".to_string(),
            validity: (Utc::now(), Utc::now() + chrono::Duration::hours(72)),
            parent_key_uri: "working/key_cache/parent_key.der".to_string(),
            subject_key_uri: "working/key_cache/subject_key.der".to_string(),
            issuer_uri: "issuer_uri".to_string(),
            repo_uri: "repo".to_string(),
            mft_uri: "mft_uri".to_string(),
            signed_object_uri: "sobj_uri".to_string(),
            notification_uri: "notification".to_string(),
            crl_distr_point: "crl".to_string(),
            is_root: false,
            typ: ObjectType::ROA,
            number: 1,
        }
    }
}

pub fn oid_for_typ(typ: &ObjectType) -> String {
    match typ {
        ObjectType::MFT => "1.2.840.113549.1.9.16.1.26".to_string(),
        ObjectType::ROA => "1.2.840.113549.1.9.16.1.24".to_string(),
        ObjectType::IROA => "1.2.840.113549.1.9.16.1.44".to_string(),
        ObjectType::IMFT => "1.2.840.113549.1.9.16.1.46".to_string(),
        ObjectType::GBR => "1.2.840.113549.1.9.16.1.35".to_string(),
        ObjectType::ASA => "1.2.840.113549.1.9.16.1.49".to_string(),

        _ => panic!("Not implemented yet"),
    }
}

pub fn create_signed_attrs(singing_time: DateTime<Utc>, content_to_sign: &Vec<u8>, cert_conf: &ObjectConf) -> Element {
    let content_type = tlv_from_oid("1.2.840.113549.1.9.3");
    let obj_type = tlv_from_oid(&oid_for_typ(&cert_conf.typ));
    let obj_set = Set::new(vec![obj_type.into()]);
    let signed_attrs_contype = Sequence::new(vec![content_type.into(), obj_set.into()]);

    let signing_type = tlv_from_oid("1.2.840.113549.1.9.5");
    let signing_time = utc_to_tlv(singing_time);
    let signing_time_set = Set::new(vec![signing_time.into()]);
    let signed_attrs_signing_time = Sequence::new(vec![signing_type.into(), signing_time_set.into()]);

    // TODO add signing time again
    // let signed_attrs_signing_time = Sequence::new(vec![signing_type]);

    let digest_type = tlv_from_oid("1.2.840.113549.1.9.4");
    let digest = sha2::Sha256::digest(content_to_sign);
    // let hash = <[u8; 32]>::from_hex(digest).unwrap().to_vec();

    let digest = OctetString::new(digest.to_vec());
    let digest_set = Set::new(vec![digest.into()]);
    let signed_attrs_digest = Sequence::new(vec![digest_type.into(), digest_set.into()]);

    let signed_attrs = Implicit::new(
        160,
        vec![
            signed_attrs_contype.into(),
            signed_attrs_signing_time.into(),
            signed_attrs_digest.into(),
        ],
    );
    signed_attrs.into()
}

pub fn create_i_signed_attrs(singing_time: DateTime<Utc>, content_to_sign: &Vec<u8>, cert_conf: &ObjectConf) -> Element {
    let content_type = tlv_from_oid("1.2.840.113549.1.9.3");
    let obj_type = tlv_from_oid(&oid_for_typ(&cert_conf.typ));
    let obj_set = Set::new(vec![obj_type.into()]);
    let signed_attrs_contype = Sequence::new(vec![content_type.into(), obj_set.into()]);

    let signing_type = tlv_from_oid("1.2.840.113549.1.9.5");
    let signing_time = utc_to_tlv(singing_time);
    let signing_time_set = Set::new(vec![signing_time.into()]);
    let signed_attrs_signing_time = Sequence::new(vec![signing_type.into(), signing_time_set.into()]);

    // TODO add signing time again
    // let signed_attrs_signing_time = Sequence::new(vec![signing_type]);

    let digest_type = tlv_from_oid("1.2.840.113549.1.9.4");
    let digest = sha2::Sha256::digest(content_to_sign);
    let hash = <[u8; 32]>::from_hex(digest).unwrap().to_vec();

    let digest = OctetString::new(hash.to_vec());
    let digest_set = Set::new(vec![digest.into()]);
    let signed_attrs_digest = Sequence::new(vec![digest_type.into(), digest_set.into()]);

    let signed_attrs = Implicit::new(
        160,
        vec![
            signed_attrs_signing_time.into(),
        ],
    );
    signed_attrs.into()
}


pub fn adapt_bytes_for_sig(data: Vec<u8>) -> Vec<u8> {
    let data = data[2..].to_vec(); // Remove first two bytes because we need to change them

    let len = data.len();
    let mut res = Vec::with_capacity(len + 4);
    res.push(0x31);
    if len < 128 {
        res.push(len as u8)
    } else if len < 0x10000 {
        res.push(2);
        res.push((len >> 8) as u8);
        res.push(len as u8);
    } else {
        res.push(3);
        res.push((len >> 16) as u8);
        res.push((len >> 8) as u8);
        res.push(len as u8);
    }
    res.extend_from_slice(data.as_ref());
    res
}

pub fn create_signer_info(singing_time: DateTime<Utc>, content_to_sign: &Vec<u8>, cert_conf: &ObjectConf) -> Element {
    let version = TLV::new(2, vec![3]);
    let signing_key = repository_util::read_cert_key(&cert_conf.subject_key_uri);
    let sid = signing_key.get_key_id_raw();
    let sid = TLV::new(128, sid);

    let digest_alg = tlv_from_oid("2.16.840.1.101.3.4.2.1");
    let digest_seq = Sequence::new(vec![digest_alg.into()]);

    let signed_attrs = create_signed_attrs(singing_time, &content_to_sign, cert_conf);

    let sig_alg_oid = tlv_from_oid("1.2.840.113549.1.1.11");
    let param = TLV::new(5, vec![]);
    let sig_alg = Sequence::new(vec![sig_alg_oid.into(), param.into()]);

    let sig_enc = signed_attrs.encode();
    let to_sign = adapt_bytes_for_sig(sig_enc);
    let signature = signing_key.sign(&to_sign).to_vec();
    let signature = OctetString::new(signature);

    let signer_info = Sequence::new(vec![
        version.into(),
        sid.into(),
        digest_seq.into(),
        signed_attrs.into(),
        sig_alg.into(),
        signature.into(),
    ]);

    let set = Set::new(vec![signer_info.into()]);
    set.into()
}

pub fn create_i_signer_info(singing_time: DateTime<Utc>, content_to_sign: &Vec<u8>, cert_conf: &ObjectConf) -> Element {
    let version = TLV::new(2, vec![3]);
    let signing_key = repository_util::read_cert_key(&cert_conf.subject_key_uri);
    let sid = signing_key.get_key_id_raw();
    let sid = TLV::new(128, sid);

    let digest_alg = tlv_from_oid("2.16.840.1.101.3.4.2.1");
    let digest_seq = Sequence::new(vec![digest_alg.into(), sid.into()]);
    let digest_set = Set::new(vec![digest_seq.into()]);

    let signed_attrs = create_i_signed_attrs(singing_time, &content_to_sign, cert_conf);

    let sig_alg_oid = tlv_from_oid("1.2.840.113549.1.1.11");
    let param = TLV::new(5, vec![]);
    let sig_alg = Sequence::new(vec![sig_alg_oid.into(), param.into()]);

    let sig_enc = signed_attrs.encode();
    let to_sign = adapt_bytes_for_sig(sig_enc);
    let signature = signing_key.sign(&to_sign).to_vec();
    let signature = OctetString::new(signature);

    let signer_info = Sequence::new(vec![
        version.into(),
        digest_set.into(),
        signed_attrs.into(),
        sig_alg.into(),
        signature.into(),
    ]);

    // let set = Set::new(vec![signer_info.into()]);
    signer_info.into()
}


pub fn create_rpki_meta_information(conf: &ObjectConf) -> Element {
    let serial = create_serial(conf.number);

    let validity = create_validity(conf.validity.0, conf.validity.1);

    let issuer_bytes = repository_util::read_cert_key(&conf.issuer_uri).get_key_id_raw();
    let issuer_id = create_issuer_id(&issuer_bytes);

    // let storage_uri;
    // if conf.typ == ObjectType::MFT {
    //     storage_uri = format!("rsync://my.server.com/data/my.server.com/repo/{}/{}", conf.ca)
    // } else if conf.typ == ObjectType::ROA {
    //     storage_uri = conf.repo_uri.clone();
    // } else {
    //     panic!("Not implemented yet");
    // }

    let location = create_location(&conf.signed_object_uri);

    let rpki_meta_information = Sequence::new(vec![serial, issuer_id, validity]); // Removed location
    rpki_meta_information.into()
}

pub fn utc_to_tlv(time: DateTime<Utc>) -> Element {
    // Use UTC format: YYYYMMDDHHMMSSZ
    let generalized_time_string = time.format("%y%m%d%H%M%SZ").to_string();
    let time: Vec<u8> = generalized_time_string.as_bytes().to_vec();
    let time = TLV::new(23, time);
    time.into()
}

pub fn generalized_time_to_tlv(time: DateTime<Utc>) -> Element {
    // Use UTC format: YYYYMMDDHHMMSSZ
    let generalized_time_string = time.format("%Y%m%d%H%M%SZ").to_string();
    let time: Vec<u8> = generalized_time_string.as_bytes().to_vec();
    let time = TLV::new(24, time);
    time.into()
}

pub fn create_validity(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Element {
    let not_before = utc_to_tlv(not_before);
    let not_after = utc_to_tlv(not_after);

    let validity = Sequence::new(vec![not_before, not_after]);
    validity.into()
}

pub fn create_issuer_id(aki: &Vec<u8>) -> Element {
    let aki = TLV::new(128, aki.clone());
    aki.into()
}

pub fn create_location(storage_uri: &str) -> Element {
    let storage_uri = storage_uri.as_bytes().to_vec();
    let storage_uri = TLV::new(134, storage_uri);
    storage_uri.into()
}

pub fn create_serial(serial: u64) -> Element {
    let mut res = in_to_byt(serial);

    // let mut res = [0u8; 20];
    // let mut rng = rand::thread_rng();
    // rng.fill(&mut res);
    res[0] &= 0x7F;

    // serial[0] &= 0x7F;
    let serial = TLV::new(2, res.to_vec());
    serial.into()
}

pub fn create_contact_info() {}

pub fn tlv_from_oid(oid: &str) -> Element {
    let val = cure_asn1::tree_parser::encode_oid_from_string(oid);
     TLV::new(6, val).into()
}

pub fn byt_to_in(inp: Vec<u8>) -> u64 {
    let mut result: u64 = 0;
    for byte in inp {
        result = (result << 8) | (byte as u64);
    }
    result
}

// pub fn in_to_byt(inp: u64) -> Vec<u8> {
//     let mut result: Vec<u8> = vec![];
//     let mut temp = inp;
//     while temp > 0 {
//         result.push((temp & 0xFF) as u8);
//         temp >>= 8;
//     }
//     result.reverse();
//     if inp > 0 && result[0] != 0{
//         let new_r = vec![0];
//         new_r.extend_from_slice(other);
//     }
//     result
// }
pub fn in_to_byt(inp: u64) -> Vec<u8> {
    if inp == 0 {
        return vec![0];
    }

    let mut result = vec![];
    let mut temp = inp;

    while temp > 0 {
        result.push((temp & 0xFF) as u8);
        temp >>= 8;
    }

    result.reverse();

    // If the most significant bit is set, prepend a 0x00 byte
    if result[0] & 0x80 != 0 {
        result.insert(0, 0x00);
    }

    result
}