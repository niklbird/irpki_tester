use chrono::{DateTime, Utc};
use cure_asn1::{asn1_parser::{Element, Implicit, OctetString, Sequence, Set, WriteASN1, TLV}, rpki::rpki::ObjectType};
use rand::Rng;

use crate::repository_util;

use super::asn1_objects::{self, in_to_byt, ObjectConf};
use hex::FromHex;

pub fn create_certificate(conf: &ObjectConf) -> Element {
    let v = create_version();
    let sn = create_serial_number(conf.number);
    let sa = create_signature_algorithm();
    let issuer = create_issuer(&conf.issuer_name);
    let validity = create_validity(conf.validity.0, conf.validity.1);
    let subject = create_subject(&conf.subject_name);

    let spki = create_subject_public_key_info(&conf.subject_key_uri);
    let extensions = create_extensions(conf);

    let tbs: Element = Sequence::new(vec![v, sn, sa, issuer, validity, subject, spki, extensions]).into();

    let sig_algo = create_sig_algo();

    let sig = create_signature(tbs.encode(), &conf.parent_key_uri);
    let cert = Sequence::new(vec![tbs, sig_algo, sig]).into();

    cert
}

pub fn create_crl(revocation_list: &Vec<(u64, DateTime<Utc>)>, conf: &ObjectConf) -> Element {
    let sn = TLV::new(2, vec![1]).into();
    let sa = create_signature_algorithm();
    let issuer = create_issuer(&conf.issuer_name);
    let this_update = asn1_objects::utc_to_tlv(conf.validity.0);
    let next_update = asn1_objects::utc_to_tlv(conf.validity.1);
    let rev_list = create_revocation_list(revocation_list);
    let extensions = create_extensions(conf);

    let tbs: Element = Sequence::new(vec![sn, sa, issuer, this_update, next_update, rev_list, extensions]).into();

    let sig_algo = create_sig_algo();

    let sig = create_signature(tbs.encode(), &conf.parent_key_uri);
    let crl = Sequence::new(vec![tbs, sig_algo, sig]).into();
    crl
}

pub fn create_revocation_list(revocation_list: &Vec<(u64, DateTime<Utc>)>) -> Element {
    let mut arr = Vec::with_capacity(revocation_list.len());
    for (num, time) in revocation_list {
        let serial = in_to_byt(*num);
        let serial = TLV::new(2, serial).into();

        let t = asn1_objects::utc_to_tlv(*time);
        let seq = Sequence::new(vec![serial, t]);
        arr.push(seq.into());
    }
    let seq = Sequence::new(arr);
    seq.into()
}

pub fn create_version() -> Element {
    let version = TLV::new(2, vec![2]).into();
    let version = Implicit::new(160, vec![version]).into();
    version
}

pub fn create_serial_number(number: u64) -> Element {
    // Random int
    let mut res = asn1_objects::in_to_byt(number);
    // let mut res = [0u8; 20];
    // let mut rng = rand::thread_rng();
    // rng.fill(&mut res);
    res[0] &= 0x7F;

    // serial[0] &= 0x7F;
    let serial = TLV::new(2, res.to_vec());
    serial.into()
}

pub fn create_signature_algorithm() -> Element {
    let sig_alg_oid = asn1_objects::tlv_from_oid("1.2.840.113549.1.1.11");
    let param = TLV::new(5, vec![]).into();
    let sig_alg = Sequence::new(vec![sig_alg_oid, param]);
    sig_alg.into()
}

pub fn create_issuer(name: &str) -> Element {
    let name = name.as_bytes().to_vec();

    // Printable string
    let name = TLV::new(19, name).into();
    let oid_cn = asn1_objects::tlv_from_oid("2.5.4.3").into();
    let type_and_val = Sequence::new(vec![oid_cn, name]);
    let rdn = Set::new(vec![type_and_val.into()]);
    let issuer = Sequence::new(vec![rdn.into()]);
    issuer.into()
}

pub fn create_validity(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Element {
    asn1_objects::create_validity(not_before, not_after)
}

pub fn create_subject(name: &str) -> Element {
    create_issuer(name)
}

pub fn create_subject_public_key_info(public_key_uri: &str) -> Element {
    let mut new_bits: Vec<u8> = vec![0];

    let public_key = repository_util::read_cert_key(public_key_uri).get_pub_key_bits();
    new_bits.extend(public_key);

    let oid_rsa = asn1_objects::tlv_from_oid("1.2.840.113549.1.1.1").into();
    let param = TLV::new(5, vec![]).into();
    let rsa_alg = Sequence::new(vec![oid_rsa, param]);

    let key = TLV::new(3, new_bits).into();
    let public_key_info = Sequence::new(vec![rsa_alg.into(), key]);
    public_key_info.into()
}

pub fn create_extensions(conf: &ObjectConf) -> Element {
    let bc = ex_basic_constraints();
    let ku = ex_key_usage(conf.typ == ObjectType::CERTCA || conf.typ == ObjectType::CERTROOT);
    let ski = ex_ski(&conf.subject_key_uri);
    let aki = ex_aki(&conf.parent_key_uri);
    let crl = ex_crl_distribution_points(&conf.crl_distr_point);
    let aia = ex_authority_information_access(&conf.issuer_uri);
    let sia = ex_subject_information_access(conf);
    let cp = ex_certificate_policies();
    let ip = ex_ip_blocks(&conf.typ);
    let asb = ex_as_blocks(&conf.typ);

    let extensions;
    if conf.is_root {
        extensions = Sequence::new(vec![bc, ku, ski, sia, cp, ip, asb]).into();
    } else {
        if conf.typ != ObjectType::CERTCA && conf.typ != ObjectType::CERTROOT {
            if conf.typ == ObjectType::MFT {
                extensions = Sequence::new(vec![ski, aki, ku, crl, aia, sia, cp, ip, asb]).into();
            } else if conf.typ == ObjectType::CRL {
                let crl_val = create_crl_number();
                extensions = Sequence::new(vec![aki, crl_val]).into();
            } else {
                extensions = Sequence::new(vec![ski, aki, ku, crl, aia, sia, cp, ip]).into();
            }
        } else {
            extensions = Sequence::new(vec![bc, ski, aki, ku, crl, aia, sia, cp, ip, asb]).into();
        }
    }

    let ex_imp;
    if conf.typ == ObjectType::CRL {
        ex_imp = Implicit::new(160, vec![extensions]);
    } else {
        ex_imp = Implicit::new(163, vec![extensions]);
    }
    ex_imp.into()
}

pub fn ex_basic_constraints() -> Element {
    let value = OctetString::new(vec![48, 3, 1, 1, 255]);
    let oid = asn1_objects::tlv_from_oid("2.5.29.19").into();
    let critical = TLV::new(1, vec![255]).into();

    let basic_constraints = Sequence::new(vec![oid, critical, value.into()]);
    basic_constraints.into()
}

pub fn ex_key_usage(is_ca: bool) -> Element {
    let oid = asn1_objects::tlv_from_oid("2.5.29.15");
    let critical = TLV::new(1, vec![255]).into();

    let value = match is_ca {
        true => OctetString::new(vec![3, 2, 1, 6]),
        false => OctetString::new(vec![3, 2, 7, 128]),
    };
    let key_usage = Sequence::new(vec![oid, critical, value.into()]);
    key_usage.into()
}

pub fn ex_ski(key_uri: &str) -> Element {
    let value = repository_util::read_cert_key(key_uri).get_key_id();
    let key_id = <[u8; 20]>::from_hex(value).unwrap();

    let oid = asn1_objects::tlv_from_oid("2.5.29.14");
    let ski = OctetString::new(key_id.to_vec());
    let val = OctetString::new(ski.encode());
    let ski = Sequence::new(vec![oid, val.into()]);
    ski.into()
}

pub fn ex_aki(key_uri: &str) -> Element {
    let value = repository_util::read_cert_key(key_uri).get_key_id();
    let key_id = <[u8; 20]>::from_hex(value).unwrap();

    let oid = asn1_objects::tlv_from_oid("2.5.29.35");
    let aki = TLV::new(128, key_id.to_vec()).into();
    let seq = Sequence::new(vec![aki]);
    let val = OctetString::new(seq.encode());

    let aki = Sequence::new(vec![oid, val.into()]);
    aki.into()
}

pub fn ex_crl_distribution_points(uri: &str) -> Element {
    let val = TLV::new(134, uri.as_bytes().to_vec().into()).into();
    let imp = Implicit::new(160, vec![Implicit::new(160, vec![val]).into()]);
    let seq = Sequence::new(vec![Sequence::new(vec![imp.into()]).into()]);
    let oc = OctetString::new(seq.encode());
    let oid = asn1_objects::tlv_from_oid("2.5.29.31");
    let distr = Sequence::new(vec![oid, oc.into()]);
    distr.into()
}

pub fn ex_authority_information_access(uri: &str) -> Element {
    let val = TLV::new(134, uri.as_bytes().to_vec()).into();
    // oid of caIssuers
    let oid = asn1_objects::tlv_from_oid("1.3.6.1.5.5.7.48.2");
    let oc = OctetString::new(Sequence::new(vec![Sequence::new(vec![oid, val]).into()]).encode());

    // oid of authorityInformationAccess
    let oid = asn1_objects::tlv_from_oid("1.3.6.1.5.5.7.1.1");
    let aia = Sequence::new(vec![oid, oc.into()]);
    aia.into()
}

pub fn ex_subject_information_access(conf: &ObjectConf) -> Element {
    let oc;
    if conf.typ != ObjectType::CERTCA && conf.typ != ObjectType::CERTROOT {
        let val = TLV::new(134, conf.signed_object_uri.as_bytes().to_vec()).into();
        // oid of caRepo
        let oid = asn1_objects::tlv_from_oid("1.3.6.1.5.5.7.48.11");
        let signed_object_val = Sequence::new(vec![oid, val]);
        let seq = Sequence::new(vec![signed_object_val.into()]);
        oc = OctetString::new(seq.encode());
    } else {
        let val = TLV::new(134, conf.repo_uri.as_bytes().to_vec()).into();
        // oid of caRepo
        let oid = asn1_objects::tlv_from_oid("1.3.6.1.5.5.7.48.5");
        let repo_val = Sequence::new(vec![oid, val]);

        let val = TLV::new(134, conf.mft_uri.as_bytes().to_vec()).into();
        let oid = asn1_objects::tlv_from_oid("1.3.6.1.5.5.7.48.10");
        let mft_val = Sequence::new(vec![oid, val]);

        let val = TLV::new(134, conf.notification_uri.as_bytes().to_vec()).into();
        let oid = asn1_objects::tlv_from_oid("1.3.6.1.5.5.7.48.13");
        let not_val = Sequence::new(vec![oid, val]);

        let val = Sequence::new(vec![repo_val.into(), mft_val.into(), not_val.into()]);

        oc = OctetString::new_el(val.into());
    }

    // oid of subjectInformationAccess
    let oid = asn1_objects::tlv_from_oid("1.3.6.1.5.5.7.1.11");
    let sia = Sequence::new(vec![oid, oc.into()]);
    sia.into()
}

pub fn ex_certificate_policies() -> Element {
    // 300C300A06082B06010505070E02
    let oid = asn1_objects::tlv_from_oid("1.3.6.1.5.5.7.14.2");
    let seq = Sequence::new(vec![oid]);
    let seq = Sequence::new(vec![seq.into()]);

    // let oc = OctetString::new(vec![48, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 14, 2]);
    let oc = OctetString::new_el(seq.into());
    let critical = TLV::new(1, vec![255]).into();
    let oid = asn1_objects::tlv_from_oid("2.5.29.32");
    let seq = Sequence::new(vec![oid, critical, oc.into()]);
    seq.into()
}

pub fn ex_ip_blocks(typ: &ObjectType) -> Element {
    let ipv6 = TLV::new(3, vec![0]).into();
    let sec6 = Sequence::new(vec![ipv6]);
    let oc = OctetString::new(vec![0, 2]);
    let ipv6 = Sequence::new(vec![oc.into(), sec6.into()]);

    let ipv4 = TLV::new(3, vec![0]).into();
    let sec4 = Sequence::new(vec![ipv4]);
    let oc = OctetString::new(vec![0, 1]);
    let ipv4 = Sequence::new(vec![oc.into(), sec4.into()]);

    let seq = Sequence::new(vec![ipv4.into(), ipv6.into()]);

    // A manifest needs everything set to inherit
    let oc;
    if typ == &ObjectType::MFT {
        oc = OctetString::new(vec![
            0x30, 0x10, 0x30, 0x06, 0x04, 0x02, 0x00, 0x01, 0x05, 0x00, 0x30, 0x06, 0x04, 0x02, 0x00, 0x02, 0x05, 0x00,
        ]);
    } else {
        oc = OctetString::new(seq.encode());
    }
    let oid = asn1_objects::tlv_from_oid("1.3.6.1.5.5.7.1.7");

    let critical = TLV::new(1, vec![255]).into();
    let ip = Sequence::new(vec![oid, critical, oc.into()]);
    ip.into()
}

pub fn ex_as_blocks(typ: &ObjectType) -> Element {
    let low = TLV::new(2, vec![0]).into();
    let high = TLV::new(2, in_to_byt(4294967295)).into();
    let seq = Sequence::new(vec![low, high]);
    let seq = Sequence::new(vec![seq.into()]);
    let im = Implicit::new(160, vec![seq.into()]);
    let seq = Sequence::new(vec![im.into()]);

    // A manifest needs everything set to inherit
    let oc;
    if typ == &ObjectType::MFT {
        oc = OctetString::new(vec![0x30, 0x04, 0xA0, 0x02, 0x05, 0x00]);
    } else {
        oc = OctetString::new(seq.encode());
    }

    let oid = asn1_objects::tlv_from_oid("1.3.6.1.5.5.7.1.8");
    let critical = TLV::new(1, vec![255]).into();
    let as_blocks = Sequence::new(vec![oid, critical, oc.into()]);
    as_blocks.into()
}

pub fn create_sig_algo() -> Element {
    let oid = asn1_objects::tlv_from_oid("1.2.840.113549.1.1.11");
    let param = TLV::new(5, vec![]).into();
    let sig_alg = Sequence::new(vec![oid, param]);
    sig_alg.into()
}
pub fn create_signature(content: Vec<u8>, key_uri: &str) -> Element {
    let key = repository_util::read_cert_key(key_uri);
    let mut base_vec = vec![0];
    let sig = key.sign(&content).to_vec();
    base_vec.extend(sig);
    TLV::new(3, base_vec).into()
}

pub fn create_crl_number() -> Element {
    let number = rand::thread_rng().gen_range(1..10000);
    let mut res = in_to_byt(number);
    res[0] &= 0x7F;

    let num = TLV::new(2, res);
    let oc = OctetString::new(num.encode());
    let oid = asn1_objects::tlv_from_oid("2.5.29.20");
    let seq = Sequence::new(vec![oid, oc.into()]);
    seq.into()
}
