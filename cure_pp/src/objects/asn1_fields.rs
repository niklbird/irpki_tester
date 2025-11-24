#![allow(unused)] 
use ::rand::rngs::OsRng;
use chrono::{DateTime, Utc};
use cure_asn1::{
    asn1_parser::{Element, Implicit, OctetString, Sequence, Set, WriteASN1, TLV},
    tree_parser::{encode_oid_from_string, Token, Tree, Types},
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

pub fn construct_duplicate_policy_qualifier_field() -> Vec<u8> {
    let policy_qualifier_oid = encode_oid_from_string("1.3.6.1.5.5.7.2.1");
    let policy_oid = encode_oid_from_string("1.3.6.1.5.5.7.14.2");
    let policy_qualifier = "https://www.arin.net/resources/rpki/cps.html".as_bytes().to_vec();
    let qualifier = TLV::new(22, policy_qualifier);
    let policy_qualifier = Sequence::new(vec![TLV::new(6, policy_qualifier_oid).into(), qualifier.into()]);
    let seq = Sequence::new(vec![policy_qualifier.into()]);

    let seq_out = Sequence::new(vec![TLV::new(6, policy_oid).into(), seq.into()]);

    let seq_out_out = Sequence::new(vec![seq_out.to_el()]);

    seq_out_out.encode()
}

pub fn construct_as_field(min_val: Vec<u8>, max_val: Vec<u8>) -> Vec<u8> {
    let beginning = TLV::new(2, min_val);
    let end = TLV::new(2, max_val).to_el();
    let seq = Sequence::new(vec![beginning.to_el(), end]);

    let sequences = Sequence::new(vec![seq.to_el()]);

    let imp = Implicit::new(160, vec![sequences.to_el()]).to_el();
    Sequence::new(vec![imp]).to_tlv().data
}

// ROA IP Addresses
pub fn construct_ip_field(ip: Vec<u8>, maxlength: Option<u32>, family: u8) -> Vec<u8> {
    let mut seq_vec = vec![TLV::new(3, ip).into()];
    if maxlength.is_some() {
        let ml = TLV::new(2, vec![maxlength.unwrap() as u8]);
        seq_vec.push(ml.into());
    }
    let ip_seq = Sequence::new(seq_vec);
    let ips_seq = Sequence::new(vec![ip_seq.into()]);

    let os = OctetString::new(vec![128, family]);

    let out_seq = Sequence::new(vec![os.into(), ips_seq.into()]);
    let out_ips_seq = Sequence::new(vec![out_seq.into()]);
    out_ips_seq.to_tlv().data
}

fn construct_f(ip_values: Vec<(Vec<u8>, Option<Vec<u8>>)>, family: Vec<u8>) -> Element {
    let mut ip_v = vec![];
    for ip in ip_values {
        let out;
        if ip.1.is_some() {
            let bs1 = TLV::new(3, ip.0).into();
            let bs2 = TLV::new(3, ip.1.unwrap()).into();
            let seq = Sequence::new(vec![bs1, bs2]);
            out = seq.into();
        } else {
            out = TLV::new(3, ip.0).into();
        }
        ip_v.push(out);
    }

    let ip_seq = Sequence::new(ip_v);
    let fam = OctetString::new(family);
    let ips_seq = Sequence::new(vec![fam.into(), ip_seq.into()]);
    ips_seq.into()
}

// IPs can be given as a prefix or as two IPs (min / max)
pub fn construct_cert_ip_field(
    ips_v4: Option<Vec<(Vec<u8>, Option<Vec<u8>>)>>,
    ips_v6: Option<Vec<(Vec<u8>, Option<Vec<u8>>)>>,
) -> Vec<u8> {
    let mut out_ips = vec![];
    if ips_v4.is_some() {
        let ips = construct_f(ips_v4.unwrap(), vec![0, 1]);
        out_ips.push(ips);
    }
    if ips_v6.is_some() {
        let ips = construct_f(ips_v6.unwrap(), vec![0, 2]);
        out_ips.push(ips);
    }
    Sequence::new(out_ips).to_tlv().encode()
}

pub fn construct_cert_validty_field(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> (Vec<u8>, Vec<u8>) {
    let now = Utc::now();
    let twenty_four_hours_ago = now - chrono::Duration::hours(24);
    // Use GeneralizedTime format: YYYYMMDDHHMMSSZ
    let generalized_time_string = not_before.format("%y%m%d%H%M%SZ").to_string();
    let not_before: Vec<u8> = generalized_time_string.as_bytes().to_vec();

    let in_three_days = now + chrono::Duration::days(90);
    // Use GeneralizedTime format: YYYYMMDDHHMMSSZ
    let generalized_time_string = not_after.format("%y%m%d%H%M%SZ").to_string();
    let not_after: Vec<u8> = generalized_time_string.as_bytes().to_vec();

    (not_before, not_after)
}

pub fn create_crl_list(values: Vec<(Vec<u8>, DateTime<Utc>)>) -> Vec<u8> {
    let mut out = vec![];
    for v in values {
        let generalized_time_string = v.1.format("%y%m%d%H%M%SZ").to_string();
        let tv: Vec<u8> = generalized_time_string.as_bytes().to_vec();
        let extoid = vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];

        let ext = Sequence::new(vec![TLV::new(6, extoid).into(), TLV::new(4, vec![1, 3, 4]).into()]);
        let extensions = Sequence::new(vec![ext.into()]);
        let seq = Sequence::new(vec![TLV::new(2, v.0).into(), TLV::new(23, tv).into(), extensions.into()]);
        out.push(seq.into());
    }
    Sequence::new(out).to_tlv().data
}

pub fn construct_ecdsa_signature() -> (Vec<u8>, Vec<u8>) {
    let ecdsawithsha256_oid = vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

    let mut v1 = vec![127 as u8; 33];
    let mut v2 = vec![127 as u8; 33];

    v1[0] = 0x0;
    v2[0] = 0x0;

    v1[1] = 0xA0;
    v2[1] = 0xA9;

    let seq = Sequence::new(vec![TLV::new(2, v1).into(), TLV::new(2, v2).into()]);
    return (ecdsawithsha256_oid, seq.encode());
}

pub fn create_revocation(serial: Vec<u8>) -> Vec<u8> {
    let now = Utc::now();
    let generalized_time_string = now.format("%y%m%d%H%M%SZ").to_string();
    let tv: Vec<u8> = generalized_time_string.as_bytes().to_vec();
    let seq = Sequence::new(vec![TLV::new(2, serial).into(), TLV::new(23, tv).into()]);
    let rev = Sequence::new(vec![seq.into()]);
    rev.to_tlv().data
}

pub fn create_ecdsa_signature(tree: &mut Tree) {
    let data = tree.get_data_by_label("signerSignedAttributesField").unwrap();
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

    let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
    let signature: Signature = signing_key.sign(&res);
    println!("Signature length: {}", signature.to_bytes().len());

    // Verification
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    let verifying_key = VerifyingKey::from(&signing_key); // Serialize with `::to_encoded_point()`

    let public_key_bytes = verifying_key.to_encoded_point(false).to_bytes().to_vec();
    println!("Public key bytes: {:?}", public_key_bytes.len());

    let mut pkb = vec![0];
    pkb.extend(public_key_bytes);
    // Now set the values

    let oid = vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    let oid_paras = vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    let alg = Sequence::new(vec![TLV::new(6, oid).into(), TLV::new(6, oid_paras).into()]).into();
    let ski = TLV::new(3, pkb).into();

    let field = Sequence::new(vec![alg, ski]).to_tlv().data;
    tree.set_data_by_label("subjectPublicKeyInfoField", field, true, true);

    let sigbytes = signature.to_bytes().to_vec();
    let sig_b1 = sigbytes[0..signature.to_bytes().len() / 2].to_vec();
    let sig_b2 = sigbytes[signature.to_bytes().len() / 2..signature.to_bytes().len()].to_vec();

    let mut sb1 = vec![0];
    sb1.extend(sig_b1);
    let mut sb2 = vec![0];
    sb2.extend(sig_b2);

    let sigfield = Sequence::new(vec![TLV::new(2, sb1).into(), TLV::new(2, sb2).into()]).to_tlv().encode();
    tree.set_data_by_label("signerSignature", sigfield, true, true);
    tree.fix_sizes(true);

    assert!(verifying_key.verify(&res, &signature).is_ok());
}

pub fn construct_subject_alt_name() -> TLV {
    let val = TLV::new(0x82, vec![0x2A, 0x2E, 0x6C, 0x61, 0x70, 0x6F, 0x2E, 0x69, 0x74]).into();

    let seq = Sequence::new(vec![val]);
    let oc = OctetString::new(seq.encode());

    let id = TLV::new(6, vec![0x55, 0x1D, 0x11]);

    let seq = Sequence::new(vec![id.into(), oc.into()]);

    return seq.to_tlv();
}

pub fn construct_subject_alt_name_i(ind: usize) -> TLV {
    let val = TLV::new(0x82, vec![0x2A, 0x2E, 0x6C, 0x61, 0x70, 0x6F, 0x2E, 0x69, 0x74]).into();

    let seq = Sequence::new(vec![val]);
    let oc = OctetString::new(seq.encode());
    let mut v = vec![0x55, 0x1D, 0x11, (ind % 128) as u8];
    // convert ind usize to vec of u8
    if ind > 127 {
        v.push((ind / 128) as u8);
    }

    let id = TLV::new(6, v);
    let seq = Sequence::new(vec![id.into(), oc.into()]);

    println!("Subject alt name: {:?}", base64::encode(seq.to_tlv().encode()));
    return seq.to_tlv();
}

pub fn construct_subject_alt_name_critical() -> TLV {
    let val = TLV::new(0x82, vec![0x2A, 0x2E, 0x6C, 0x61, 0x70, 0x6F, 0x2E, 0x69, 0x74]).into();

    let seq = Sequence::new(vec![val]);
    let oc = OctetString::new(seq.encode());

    let id = TLV::new(6, vec![0x55, 0x1D, 0x11]).into();
    let critical = TLV::new(1, vec![255]).into();

    let seq = Sequence::new(vec![id, critical, oc.into()]);

    println!("Subject alt name: {:?}", base64::encode(seq.to_tlv().encode()));
    return seq.to_tlv();
}

pub fn construct_subject_alt_name_critical_faulty() -> TLV {
    let val = TLV::new(0x82, vec![0x2A, 0x2E, 0x6C, 0x61, 0x70, 0x6F, 0x2E, 0x69, 0x74]).into();

    let seq = Sequence::new(vec![val]);
    let oc = OctetString::new(seq.encode());

    let id = TLV::new(6, vec![0x55, 0x1D]);
    let critical = TLV::new(1, vec![255]);

    let seq = Sequence::new(vec![id.into(), critical.into(), oc.into()]);

    println!("Subject alt name: {:?}", base64::encode(seq.to_tlv().encode()));
    return seq.to_tlv();
}

pub fn construct_subject_alt_name_custom(critical: bool, correct_oid: bool, internal_correct: bool) -> TLV {
    let val;
    if internal_correct {
        val = TLV::new(0x82, vec![0x2A, 0x2E, 0x6C, 0x61, 0x70, 0x6F, 0x2E, 0x69, 0x74]).into();
    } else {
        val = TLV::new(0x46, vec![0x2A, 0x2E, 0x6C, 0x61, 0x70, 0x6F, 0x2E, 0x69, 0x74]).into();
    }

    let seq = Sequence::new(vec![val]);
    let oc = OctetString::new(seq.encode());

    let id;
    if correct_oid {
        id = TLV::new(6, vec![0x55, 0x1D, 0x11]);
    } else {
        id = TLV::new(6, vec![0x55, 0x1D]);
    }
    let critical_field = TLV::new(1, vec![255]);

    let seq;
    if critical {
        seq = Sequence::new(vec![id.into(), critical_field.into(), oc.into()]);
    } else {
        seq = Sequence::new(vec![id.into(), oc.into()]);
    }

    return seq.to_tlv();
}

pub fn construct_subject_alt_name_non_critical_faulty() -> TLV {
    let val = TLV::new(0x82, vec![0x2A, 0x2E, 0x6C, 0x61, 0x70, 0x6F, 0x2E, 0x69, 0x74]).into();

    let seq = Sequence::new(vec![val]);
    let oc = OctetString::new(seq.encode());

    let critical = TLV::new(1, vec![0]);

    let id = TLV::new(6, vec![0x55, 0x1D, 0x12, 0x44]);

    let seq = Sequence::new(vec![id.into(), critical.into(), oc.into()]);

    return seq.to_tlv();
}

pub fn construct_name_constraints() -> TLV {
    // let val = TLV::new(0x82, vec![0x2A, 0x2E, 0x6C, 0x61, 0x70, 0x6F, 0x2E, 0x69, 0x74]);

    let seq = Sequence::new(vec![]);
    let oc = OctetString::new(seq.encode());
    let oid = encode_oid_from_string("2.5.29.30");
    let id = TLV::new(6, oid).into();
    let critical = TLV::new(1, vec![255]);

    let seq = Sequence::new(vec![id, oc.into()]);

    println!("name_constraints: {:?}", base64::encode(seq.to_tlv().encode()));
    return seq.to_tlv();
}

// pub fn create_signing_time(tree: &mut Tree) {
//     let now = Utc::now();
//     // 06 09 2A 8f6 48 86 F7 0D 01 09 05
//     let generalized_time_string = now.format("%y%m%d%H%M%SZ").to_string();
//     let tv: Vec<u8> = generalized_time_string.as_bytes().to_vec();
//     let extoid = vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05];

//     let set = Set::new(vec![TLV::new(23, tv)]);

//     let ext = Sequence::new(vec![TLV::new(6, extoid), set.to_tlv()]);

//     let pid = tree.get_node_by_label("signerSignedAttributesField").unwrap().id;
//     let mut max = 0;
//     for id in tree.tokens{
//         if id.0 > max {
//             max = id.0;
//         }
//     }
//     let new_id = max + 1;

//     let token = Token::new(Types::Sequence, ext.length, ext.data, pid, new_id);
//     tree.tokens.insert(new_id, token);
//     tree.labels.insert(new_id, "signingTimeAttribute".to_string());
//     tree.tokens.insert(id, )
//     let mut tok = tree.tokens.get_mut(&id).unwrap();

//     tok.children.push(ext.to_tlv());

//     // Set the value
// }
