use cure_asn1::asn1_parser::{Element, OctetString, Sequence, TLV};
use rand_distr::num_traits::ToPrimitive;
use sha2::Digest;
pub struct RoaConf {
    // IP, maxlength
    pub ipv4: Vec<(Vec<u8>, Option<u32>)>,
    pub ipv6: Vec<(Vec<u8>, Option<u32>)>,
    pub asn: u64,
}

use crate::objects::asn1_sigdata;

use super::asn1_objects::{ObjectConf, ObjectVersion};

pub fn construct_ip_field(conf: &RoaConf) -> Element {
    let mut out_ips_seq = vec![];

    let arr = vec![&conf.ipv4, &conf.ipv6];
    for i in 0..arr.len() {
        let v = arr[i];
        if v.len() == 0 {
            continue;
        }

        let mut ips = vec![];

        for val in v {
            let mut base_vec = vec![0];
            base_vec.extend(val.0.clone());
            let mut seq_vec = vec![TLV::new(3, base_vec).into()];
            if val.1.is_some() {
                let ml = TLV::new(2, vec![val.1.unwrap() as u8]).into();
                seq_vec.push(ml);
            }
            let ip_seq = Sequence::new(seq_vec);
            ips.push(ip_seq.into());
        }
        let ips_seq = Sequence::new(ips);

        // i + 1 == IP family identifier
        let os = OctetString::new(vec![0, (i + 1).try_into().unwrap()]);

        let out_seq = Sequence::new(vec![os.into(), ips_seq.into()]);

        out_ips_seq.push(out_seq.into());
    }
    let out_ips_seq = Sequence::new(out_ips_seq);
    out_ips_seq.into()
}

pub fn construct_content(conf: &RoaConf, oconf: Option<&ObjectConf>) -> Element {
    let ip_field = construct_ip_field(conf);

    let d = if conf.asn < 128 {
        vec![conf.asn as u8]
    } else {
        vec![(conf.asn >> 8) as u8, conf.asn as u8]
    };

    let as_field = TLV::new(2, d);

    let econtent_inner: Element;

    if oconf.is_some(){
        let meta_info = crate::objects::asn1_objects::create_rpki_meta_information(oconf.unwrap());
        econtent_inner = Sequence::new(vec![as_field.into(), ip_field, meta_info]).into();
    }
    else{
        let seq = Sequence::new(vec![as_field.into(), ip_field]);
        let oc = OctetString::new_el(seq.into());
        econtent_inner = oc.into();

    }
    
    return econtent_inner;
}

pub fn create_iroa(roa_string: &str, conf: &ObjectConf) -> Element {
    let (ip, asid) = roa_string_to_content(roa_string);

    let roa_conf = RoaConf {
        ipv4: vec![(ip, None)],
        ipv6: vec![],
        asn: asid,
    };

    // let oid = "1.2.840.113549.1.9.16.1.24";
    // let val = cure_asn1::tree_parser::encode_oid_from_string(oid);

    let econtent = construct_content(&roa_conf, Some(conf));

    // let meta_info = crate::objects::asn1_objects::create_rpki_meta_information(conf);

    // econtent.add_child(meta_info);

    // if cfg!(feature="no_ee") && !cfg!(feature="no_roa_sig"){
    //     // let con = OctetString::new_el(econtent.into());
    //     // let econtent_imp = Implicit::new(160, vec![con.into()]).into();

    //     // let content = Sequence::new(vec![TLV::new(6, val).into(), econtent_imp]);
    
    //     return asn1_sigdata::create_i_signed_data(econtent, conf).into();
    // }
    
    return econtent.into();
}

pub fn roa_string_to_content(roa_string: &str) -> (Vec<u8>, u64) {
    // TODO add IPv6
    // Example ROA String: 1.2.3.0/24 => AS3212
    let mut s: Vec<&str> = roa_string.split(" ").collect();
    let ip_s = s[0];
    let ip_v: Vec<&str> = ip_s.split("/").collect();
    let ip_octets: Vec<&str> = ip_v[0].split(".").collect();
    let pref = ip_v[1].parse::<u8>().unwrap();

    let mut ip_addr = vec![];
    for val in ip_octets {
        ip_addr.push(val.parse::<u8>().unwrap());
    }

    if s[2].starts_with("AS") {
        s[2] = &s[2][2..];
    }
    let as_s = s[2].parse::<u64>().unwrap();
    // Calculate the subnet mask based on the prefix length
    let mut mask = 0xFFFFFFFFu32; // 32-bit mask
    mask <<= (32 - pref) as u32;

    // Apply the subnet mask to the IP address
    let ip_u32 = ((ip_addr[0] as u32) << 24) | ((ip_addr[1] as u32) << 16) | ((ip_addr[2] as u32) << 8) | (ip_addr[3] as u32);

    let final_ip_u32 = ip_u32 & mask;

    let final_ip = [
        (final_ip_u32 >> 24) as u8,
        (final_ip_u32 >> 16) as u8,
        (final_ip_u32 >> 8) as u8,
        final_ip_u32 as u8,
    ];

    let mut output_ip = vec![];
    for i in 0..final_ip.len() {
        if i.to_f32().unwrap() >= pref.to_f32().unwrap() / 8.0 {
            continue;
        }
        let val = final_ip[i];
        output_ip.push(val);
    }

    (output_ip, as_s)
}

pub fn roa_name(roa_string: &str, impr: &ObjectVersion) -> String {
    let name = hex::encode(sha2::Sha256::digest(roa_string.as_bytes()));
    if impr == &ObjectVersion::Novel {
        format!("{}.proa", &name[..name.len() / 2])
    } 
    else if impr == &ObjectVersion::Improved {
        format!("{}.iroa", &name[..name.len() / 2])
    } 
    else {
        format!("{}.roa", &name[..name.len() / 2])
    }
}

pub fn construct_roa_content(roa_string: &str) -> Element {
    let (ip, asid) = roa_string_to_content(roa_string);

    let roa_conf = RoaConf {
        ipv4: vec![(ip, None)],
        ipv6: vec![],
        asn: asid,
    };
    let econtent = construct_content(&roa_conf, None);
    econtent
}


pub fn create_roa(roa_string: &str, conf: &ObjectConf, impr: ObjectVersion) -> Element {
    let roa;

    if impr == ObjectVersion::Default {
        let content = construct_roa_content(roa_string);
        roa = asn1_sigdata::create_signed_data(content, conf);
    } else if impr == ObjectVersion::Novel {
        // let content = construct_roa_content(roa_string);
        roa = create_iroa(roa_string, conf)
    } else {
        panic!("TODO");
    }

    roa
}
