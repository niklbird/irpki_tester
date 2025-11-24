use chrono::DateTime;
use chrono::Utc;
/// Convert a DER Encoded ASN.1 X.509 Certificate into a Protofbuf equivalent
/// 
/// 
/// 
/// 

use prost::Message;
use crate::research::prot::converter::asn1::asn1_pdu::length::Types;
use crate::research::prot::converter::asn1::asn1_pdu::Pdu;
use crate::research::prot::converter::asn1::asn1_pdu::ValueElement;
use crate::research::prot::converter::asn1::asn1_universal_types::BitString;
use crate::research::prot::converter::asn1::asn1_universal_types::GeneralizedTime;
use crate::research::prot::converter::asn1::asn1_universal_types::UtcTime;
use crate::research::prot::converter::asn1::x509_certificate::ExtensionSequence;
use crate::research::prot::converter::x509_certificate::Extension;
use crate::research::prot::converter::asn1::asn1_universal_types::Boolean;
use crate::research::prot::converter::x509_certificate::RawExtension;
use crate::research::prot::converter::x509_certificate::Extensions;
use crate::research::prot::converter::asn1::asn1_universal_types::Integer;
use crate::research::prot::converter::asn1::asn1_pdu::Identifier;
use crate::research::prot::converter::asn1::asn1_pdu::TagNumber;
use crate::research::prot::converter::asn1::asn1_pdu::Length;
use crate::research::prot::converter::asn1::asn1_pdu::Value;
use crate::research::prot::converter;
use crate::research::prot::converter::asn1::asn1_universal_types::BmpString;
use crate::research::prot::converter::asn1::asn1_universal_types::Null;
use crate::research::prot::converter::asn1::asn1_universal_types::PrintableString;
use crate::research::prot::converter::asn1::asn1_universal_types::Sequence;
use crate::research::prot::converter::asn1::asn1_universal_types::TeletexString;
use crate::research::prot::converter::asn1::asn1_universal_types::UniversalTypes;
use crate::research::prot::converter::asn1::asn1_universal_types::universal_types;
use crate::research::prot::converter::asn1::asn1_universal_types::Set;
use crate::research::prot::converter::asn1::asn1_universal_types::Ia5String;
use crate::research::prot::converter::asn1::asn1_universal_types::Utf8String;
use crate::research::prot::converter::asn1::asn1_universal_types::Implicit;
use crate::research::prot::converter::asn1::asn1_universal_types::Tlv;
use crate::research::prot::ffi;
use prost_types::Timestamp;


use crate::rpki::rpki::RpkiObject;
use crate::tree_parser::decode_oid_to_string;
use crate::research::prot::converter::asn1::x509_certificate;
use crate::research::prot::converter::asn1::asn1_universal_types::ObjectIdentifier;
use crate::research::prot::converter::asn1::asn1_universal_types::OctetString;
use std::io::Read;


// use prost_build;


fn create_pdu(tag: u8, content: &Vec<u8>, len: Vec<u8>) -> Pdu{
    let new_tag = match tag{
        48 | 49 => tag - 32,
        _ => tag,
    };

    let encoding = match tag{
        48 | 49 => 1, // constructed
        _ => 0, // primitive
    };
    

    let class = tag >> 6;
    let new_tag = new_tag & 0b00011111;

    Pdu{
        id: Some(Identifier{id_class: Some(class as i32), encoding: Some(encoding), tag_num: Some(TagNumber{low_tag_num: Some(new_tag as i32), high_tag_num: None})}),
        len: Some(Length{types: Some(Types::LengthOverride(len))}),
        val: Some(Value{val_array: vec![
            ValueElement{pdu: None, val_bits: Some(content.clone())}
            ]}),
    }
}

// fn datetime_to_timechoice(value: &DateTime<Utc>) -> TimeChoice{
//     let timestamp_nb = Timestamp{
//         seconds: value.timestamp() as i64,
//         nanos: value.timestamp_subsec_nanos() as i32,
//     };

//     let utime_nb = UtcTime{
//         time_stamp: Some(timestamp_nb),
//     };

//     let tc_nb = TimeChoice{
//         utc_time: Some(utime_nb),
//         generalized_time: None,
//     };

//     tc_nb
// }


pub fn der_bytes_to_proto(tag: u8, len: Vec<u8>, content: &Vec<u8>) -> Pdu{
    create_pdu(tag, content, len)
}

pub fn rnd_seed() -> u64{
    let rnd_int = {
        // Read 4 bytes from the OS RNG (/dev/urandom on Unix)
        let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
        let mut buf = [0u8; 4];
        f.read_exact(&mut buf).expect("read /dev/urandom");
        // Map into i32 range (0..=i32::MAX)
        let v = u32::from_ne_bytes(buf);
        (v % (i32::MAX as u32)) as u64
    };
    rnd_int
}




pub fn mutate_rpki_object_with_proto(content: &Vec<u8>) -> Vec<u8>{
    // let proto_bytes = der_to_proto(&content);    
    let amount_mutations = 5;
    let seed = rnd_seed();
    
    let mutated = ffi::mutate_pb_to_der(&content, seed, amount_mutations);
    if mutated.is_err(){
        for _ in 0..10{
            let seed = rnd_seed();
    
            let mutated = ffi::mutate_pb_to_der(&content, seed, amount_mutations);
            if mutated.is_ok(){
                return mutated.unwrap();
            }
        }

        println!("Mutation via FFI failed, returning original content");
        return content.clone();
    }
    return mutated.unwrap();
}

pub fn mutate_proto_object(content: &Vec<u8>) -> Vec<u8>{
        let amount_mutations = 5;
    let seed = rnd_seed();
    
    let mutated = ffi::mutate_pb(&content, seed, amount_mutations);
    if mutated.is_err(){
        for _ in 0..10{
            let seed = rnd_seed();
    
            let mutated = ffi::mutate_pb(&content, seed, amount_mutations);
            if mutated.is_ok(){
                return mutated.unwrap();
            }
        }

        println!("Mutation via FFI failed here, returning original content");
        return content.clone();
    }
    return mutated.unwrap();

}


pub fn convert_to_proto(tree: &RpkiObject) -> Vec<u8> {
    let b = tree.content.encode();
    let proto_bytes = der_to_proto(&b);
    return proto_bytes;
} 


#[derive(Debug)]
pub enum OidError {
    Empty,
    IncompleteArc,
    FirstTooLarge,
    SmallOutOfRange,
    ArcOverflow,
}

// fn decode_base128_arcs(content: &Vec<u8>) -> Result<Vec<u64>, OidError> {
//     if content.is_empty() { return Err(OidError::Empty); }
//     let mut arcs = Vec::new();
//     let mut val: u64 = 0;
//     let mut have = false;

//     for &b in content {
//         val = (val << 7) | (b & 0x7f) as u64;
//         have = true;
//         if (b & 0x80) == 0 {
//             arcs.push(val);
//             val = 0;
//             have = false;
//         }
//     }
//     if have { return Err(OidError::IncompleteArc); }
//     Ok(arcs)
// }

fn decode_arc(encoded: &Vec<u8>) -> Vec<u32>{
    let first_byte = encoded[0];
    let first = first_byte / 40;
    let second = first_byte % 40;
    let mut oid = vec![first as u32, second as u32];

    // Decode the rest of the bytes
    let mut value = 0u32;

    for &byte in &encoded[1..] {
        if byte & 0x80 != 0 {
            // Continuation byte
            value = (value << 7) | (byte & 0x7F) as u32;
        } else {
            // Last byte of the component
            value = (value << 7) | byte as u32;
            oid.push(value);
            value = 0;
        }
    }

    oid

}

pub fn der_oid_content_to_proto(content: &Vec<u8>) -> Result<ObjectIdentifier, OidError> {
    let u = decode_oid_to_string(&content);
    let mut arcs = vec![];
    for part in u.split("."){
        let v = part.parse::<u32>().unwrap();
        arcs.push(v);
    }


    let arcs = decode_arc(content);

    let root = arcs.get(0).ok_or(OidError::Empty).ok().unwrap();


    // let (root_enum, small_opt, first_rest): (RootNode, Option<i32>, u32) = if n0 < 40 {
    //     (RootNode::RnVal0, Some(n0 as i32), /*a1*/ 0)
    // } else if n0 < 80 {
    //     let a1 = (n0 - 40) as i32;
    //     (RootNode::RnVal1, Some(a1), 0)
    // } else {
    //     // root=2; the *first* arc to go into subidentifier is (n0 - 80)
    //     (RootNode::RnVal2, None, (n0 - 80) as u32)
    // };

    // // Build the remaining subidentifiers
    // let mut sub = Vec::with_capacity(arcs.len()); // safe upper bound

    // if matches!(root_enum, RootNode::RnVal2) {
    //     sub.push(first_rest); // include a1 for root=2
    // }

    // // append a2.. from DER list arcs[1..]
    // for &v in arcs.iter().skip(1) {
    //     if v > u32::MAX  { return Err(OidError::ArcOverflow); }
    //     sub.push(v as u32);
    // }

    // // For root 0/1, small must be 0..=39 (enum ensures this, but validate anyway)
    // if let Some(si) = small_opt {
    //     let raw = si as i32;
    //     if !(0..=39).contains(&raw) {
    //         return Err(OidError::SmallOutOfRange);
    //     }
    // }

    // Ok(ObjectIdentifier {
    //     root: Some(root_enum as i32),
    //     small_identifier: small_opt.map(|x| x as i32),
    //     subidentifier: sub,
    // });
    let mut rest = vec![];


    let (small, start_idx) = if root == &0 {
        (Some(arcs[1] as i32), 2)
    } else if root == &1 {
        (Some(arcs[1] as i32), 2)
    } else {

        (None, 2) // Y = n0 - 80 but omitted in your schema
    };

    if let Some(si) = small {
        if si > 39 { return Err(OidError::SmallOutOfRange); }
    }

    // Remaining arcs are arcs[1..], but if root==2 you might want to
    // treat (n0 - 80) as the "second arc" logically; your schema stores
    // only *subsequent* arcs in subidentifier, so we just push arcs[1..].
    for &a in &arcs[start_idx..] {
        if a > u32::MAX { return Err(OidError::ArcOverflow); }
        rest.push(a as u32);
    }

    // There seems to be a bug in the tooling of Google? Will need to check, but for some reason I need to append the first arc in the end if there is no small identifier
    if *root > 1 {
        rest.push(arcs[1] as u32);

    }

    Ok(ObjectIdentifier {root: Some(*root as i32), small_identifier: small, subidentifier: rest })
}

pub fn map_cert_extensions(tree: &RpkiObject) -> Extensions{
    // ExtensionSequence

    let extensions = tree.get_encoded_extensions().unwrap();

    let mut proto_extensions = Vec::new();
    for extension in extensions{
        let oid = der_oid_content_to_proto(&extension.0); //ObjectIdentifier { root: None, small_identifier: None, subidentifier: extension.0 };

        let cont = OctetString{val: Some(extension.2)};

        let raw = RawExtension{
            extn_id: None,
            pdu: None,
            extn_value: Some(cont),
        };

       let ext = Extension{
            extn_id: oid.ok(),
            critical: Some(Boolean{val: Some(extension.1)}),
            raw_extension: Some(raw),
            types: None,
       };

        proto_extensions.push(ext);
    }
    let seq = ExtensionSequence{
        extension: None,
        extensions: proto_extensions.clone(),
    };

    // let seq = ExtensionSequence{
    //     extension: None,
    //     extensions: vec![],
    // };

    let ex = Extensions{
        pdu: None, 
        value: Some(seq),
    };
    
    ex
}
 




#[cfg(feature = "proto")] // if you’re gating generation; otherwise remove this line
pub mod asn1 {
    // Sibling modules inside the same parent: 
    pub mod asn1_universal_types {
        include!(concat!(env!("OUT_DIR"), "/asn1_universal_types.rs"));
    }
    pub mod x509_certificate {
        include!(concat!(env!("OUT_DIR"), "/x509_certificate.rs"));
    }
    pub mod asn1_pdu {
        include!(concat!(env!("OUT_DIR"), "/asn1_pdu.rs"));
    }
}

// pub fn compile_proto() {
//         let mut cfg = prost_build::Config::new();
//     cfg.compile_protos(&["protos/object.proto"], &["protos"])?;
// }


use chrono::TimeZone;

// Convert DER encoded ASN.1 data to protobuf UniversalTypes
pub fn der_to_proto(data: &Vec<u8>) -> Vec<u8>{
    let (proto, _) = compile_der_to_proto(data);

    let mut buffer = Vec::new();
    proto.encode(&mut buffer).unwrap();

    buffer
}


pub fn compile_der_to_proto(data: &Vec<u8>) -> (UniversalTypes, usize){
    let tag = data[0];
    let (len, len_bytes) = asn1_parser::parse_length(&data[1..]).unwrap();
    let sub_data = data[1 + len_bytes .. 1 + len_bytes + len].to_vec();
    let total_len = 1 + len_bytes + len;

    match tag{
        0x30 | 0x31 => { // SET or SEQUENCE
            let mut index = 0;
            let mut values = Vec::new();
            while index < sub_data.len(){
                let (child_len, child_len_bytes) = asn1_parser::parse_length(&sub_data[index + 1..]).unwrap();
                let total_child_len = 1 + child_len_bytes + child_len;
                let child_data = sub_data[index .. index + total_child_len].to_vec();

                let (child_proto, _) = compile_der_to_proto(&child_data);
                values.push(child_proto);

                index += total_child_len;
            }

            if tag == 0x30{
                let mut seq = Sequence::default();
                seq.val = values;
                return (UniversalTypes{
                    r#type: Some(universal_types::Type::Sequence(seq)),
                }, total_len);
            }
            else{
                let mut seq = Set::default();
                seq.val = values;
                return (UniversalTypes{
                    r#type: Some(universal_types::Type::Set(seq)),
                }, total_len);

            }
            
        },
        0x01 => { // BOOLEAN
            let mut boolean = Boolean::default();
            boolean.val = Some(sub_data[0] != 0);

            return (UniversalTypes{
                r#type: Some(universal_types::Type::BoolVal(boolean)),
            }, total_len);
        },
        0x02 => { // INTEGER
            let mut integer = Integer::default();
            integer.val = Some(sub_data);

            return (UniversalTypes{
                r#type: Some(universal_types::Type::IntVal(integer)),
            }, total_len);
        },
        0x03 => { // BIT STRING
            let mut bit_string = BitString::default();
            let bits_data = sub_data[1..len].to_vec();
            bit_string.unused_bits = Some(sub_data[0] as i32);
            bit_string.val = Some(bits_data);

            return (UniversalTypes{
                r#type: Some(universal_types::Type::BitString(bit_string)),
            }, total_len);
        },
        0x04 => { // OCTET STRING
            let mut octet_string = OctetString::default();
            octet_string.val = Some(sub_data[0..len].to_vec());

            return (UniversalTypes{
                r#type: Some(universal_types::Type::OctetString(octet_string)),
            }, total_len);
        },
        0x05 => { // NULL
            return (UniversalTypes{
                r#type: Some(universal_types::Type::NullVal( Null {} )),
            }, total_len);
        },
        0x06 => { // OBJECT IDENTIFIER
            let oid = converter::der_oid_content_to_proto(&sub_data).unwrap();

            return (UniversalTypes{
                r#type: Some(universal_types::Type::ObjectId(oid)),
            }, total_len);
        },
        0x0C => { // UTF8String
            let mut string = Utf8String::default();
            string.val = Some(String::from_utf8(sub_data).unwrap());

            return (UniversalTypes{
                r#type: Some(universal_types::Type::Utf8String(string)),
            }, total_len);
        },
        0x13 => { // PrintableString
            let mut string = PrintableString::default();
            string.val = Some(String::from_utf8(sub_data).unwrap());

            return (UniversalTypes{
                r#type: Some(universal_types::Type::PrintableString(string)),
            }, total_len);
        },
        0x14 => { // T61String
            let mut string = TeletexString::default();
            string.val = Some(String::from_utf8(sub_data).unwrap());

            return (UniversalTypes{
                r#type: Some(universal_types::Type::TeletexString(string)),
            }, total_len);
        },
        0x16 => { // IA5String
            let mut string = Ia5String::default();
            string.val = Some(String::from_utf8(sub_data).unwrap());

            return (UniversalTypes{
                r#type: Some(universal_types::Type::Ia5String(string)),
            }, total_len);
        },
        0x1D => { // DER PrintableString
            let mut string = BmpString::default();
            string.val = Some(String::from_utf8(sub_data).unwrap());

            return (UniversalTypes{
                r#type: Some(universal_types::Type::BmpString(string)),
            }, total_len);
        },
        0x17 => { // UTCTime
            let ts = format_timestamp(&sub_data); 

            let string = UtcTime { time_stamp: ts };

            return (UniversalTypes{
                r#type: Some(universal_types::Type::UtcTime(string)),
            }, total_len);
        },
        0x18 => { // GeneralizedTime
            let ts = format_timestamp(&sub_data);

            let string = GeneralizedTime { time_stamp: ts };

            return (UniversalTypes{
                r#type: Some(universal_types::Type::GeneralizedTime(string)),
            }, total_len);
        },
        160 .. 166 => {
            let mut imp = Implicit::default();
            let mut values = vec![];
            let mut abs_len = 0;
            loop{
                let (el, el_len) = compile_der_to_proto(&sub_data[abs_len .. ].to_vec());
                values.push(el);
                abs_len += el_len;
                if abs_len >= len{
                    break;
                }
            }
            imp.val = values;
            imp.tag = Some(tag as u32);
            imp.len = Some(len as u32);
            return (UniversalTypes{
                r#type: Some(universal_types::Type::Implicit(imp)),
            }, total_len);
            // Other types not implemented yet
        },
        128 => { 
            let mut tlv = Tlv::default();
            tlv.tag = Some(tag as u32);
            tlv.len = Some(data[1..1 + len_bytes].to_vec());
            tlv.val = Some(sub_data[.. len].to_vec());
            return (UniversalTypes{
                r#type: Some(universal_types::Type::Tlv(tlv)),
            }, total_len);
        }
        _ => {
            panic!("Unsupported tag: {}", tag);
        }
    }
}

    fn format_timestamp(timestamp: &Vec<u8>) -> Option<Timestamp> {
        let timestamp = String::from_utf8(timestamp.clone()).ok()?;

        if timestamp.len() != 13 || !timestamp.ends_with('Z') {
            return None; // Invalid format
        }
 
        let year = 2000 + timestamp[0..2].parse::<i32>().ok()?; // Assuming 21st century
        let month = timestamp[2..4].parse::<u32>().ok()?;
        let day = timestamp[4..6].parse::<u32>().ok()?;
        let hour = timestamp[6..8].parse::<u32>().ok()?;
        let minute = timestamp[8..10].parse::<u32>().ok()?;
        let second = timestamp[10..12].parse::<u32>().ok()?;

        let naive_dt = DateTime::from_timestamp(
            Utc.with_ymd_and_hms(year, month, day, hour, minute, second).single()?.timestamp(),
            0,
        )?;

        let value = naive_dt.to_utc();
        let timestamp_nb = Timestamp{
            seconds: value.timestamp() as i64,
            nanos: value.timestamp_subsec_nanos() as i32,
        };

        Some(timestamp_nb)
    }


use crate::asn1_parser;

