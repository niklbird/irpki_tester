// use chrono::TimeZone;
// use chrono::Utc;
// use prost::Message;
// use chrono::NaiveDateTime;
// use prost_types::Timestamp;

// // Convert DER encoded ASN.1 data to protobuf UniversalTypes
// pub fn der_to_proto(data: &Vec<u8>) -> Vec<u8>{
//     let (proto, _) = compile_der_to_proto(data);

//     let mut buffer = Vec::new();
//     proto.encode(&mut buffer).unwrap();

//     buffer
// }

// pub fn compile_der_to_proto(data: &Vec<u8>) -> (UniversalTypes, usize){
//     let tag = data[0];
//     let (len, len_bytes) = asn1_parser::parse_length(&data[1..]).unwrap();
//     let sub_data = data[1 + len_bytes .. 1 + len_bytes + len].to_vec();
//     let total_len = 1 + len_bytes + len;

//     match tag{
//         0x30 | 0x31 => { // SET or SEQUENCE
//             let mut index = 0;
//             let mut values = Vec::new();
//             while index < sub_data.len(){
//                 let (child_len, child_len_bytes) = asn1_parser::parse_length(&sub_data[index + 1..]).unwrap();
//                 let total_child_len = 1 + child_len_bytes + child_len;
//                 let child_data = sub_data[index .. index + total_child_len].to_vec();

//                 let (child_proto, _) = compile_der_to_proto(&child_data);
//                 values.push(child_proto);

//                 index += total_child_len;
//             }

//             if tag == 0x30{
//                 let mut seq = Sequence::default();
//                 seq.val = values;
//                 return (UniversalTypes{
//                     r#type: Some(universal_types::Type::Sequence(seq)),
//                 }, total_len);
//             }
//             else{
//                 let mut seq = Set::default();
//                 seq.val = values;
//                 return (UniversalTypes{
//                     r#type: Some(universal_types::Type::Set(seq)),
//                 }, total_len);

//             }
            
//         },
//         0x01 => { // BOOLEAN
//             let mut boolean = Boolean::default();
//             boolean.val = Some(sub_data[0] != 0);

//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::BoolVal(boolean)),
//             }, total_len);
//         },
//         0x02 => { // INTEGER
//             let mut integer = Integer::default();
//             integer.val = Some(sub_data);

//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::IntVal(integer)),
//             }, total_len);
//         },
//         0x03 => { // BIT STRING
//             let mut bit_string = BitString::default();
//             let bits_data = sub_data[1..len].to_vec();
//             bit_string.unused_bits = Some(sub_data[0] as i32);
//             bit_string.val = Some(bits_data);

//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::BitString(bit_string)),
//             }, total_len);
//         },
//         0x04 => { // OCTET STRING
//             let mut octet_string = OctetString::default();
//             octet_string.val = Some(sub_data[0..len].to_vec());

//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::OctetString(octet_string)),
//             }, total_len);
//         },
//         0x05 => { // NULL
//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::NullVal( Null {} )),
//             }, total_len);
//         },
//         0x06 => { // OBJECT IDENTIFIER
//             let oid = converter::der_oid_content_to_proto(&sub_data).unwrap();

//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::ObjectId(oid)),
//             }, total_len);
//         },
//         0x0C => { // UTF8String
//             let mut string = Utf8String::default();
//             string.val = Some(String::from_utf8(sub_data).unwrap());

//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::Utf8String(string)),
//             }, total_len);
//         },
//         0x13 => { // PrintableString
//             let mut string = PrintableString::default();
//             string.val = Some(String::from_utf8(sub_data).unwrap());

//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::PrintableString(string)),
//             }, total_len);
//         },
//         0x14 => { // T61String
//             let mut string = TeletexString::default();
//             string.val = Some(String::from_utf8(sub_data).unwrap());

//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::TeletexString(string)),
//             }, total_len);
//         },
//         0x16 => { // IA5String
//             let mut string = Ia5String::default();
//             string.val = Some(String::from_utf8(sub_data).unwrap());

//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::Ia5String(string)),
//             }, total_len);
//         },
//         0x1D => { // DER PrintableString
//             let mut string = BmpString::default();
//             string.val = Some(String::from_utf8(sub_data).unwrap());

//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::BmpString(string)),
//             }, total_len);
//         },
//         0x17 => { // UTCTime
//             let ts = format_timestamp(&sub_data); 

//             let string = UtcTime { time_stamp: ts };

//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::UtcTime(string)),
//             }, total_len);
//         },
//         0x18 => { // GeneralizedTime
//             let ts = format_timestamp(&sub_data);

//             let string = crate::prot::converter::asn1::asn1_universal_types::GeneralizedTime { time_stamp: ts };

//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::GeneralizedTime(string)),
//             }, total_len);
//         },
//         160 .. 166 => {
//             let mut imp = Implicit::default();
//             let mut values = vec![];
//             let mut abs_len = 0;
//             loop{
//                 let (el, el_len) = compile_der_to_proto(&sub_data[abs_len .. ].to_vec());
//                 values.push(el);
//                 abs_len += el_len;
//                 if abs_len >= len{
//                     break;
//                 }
//             }
//             imp.val = values;
//             imp.tag = Some(tag as u32);
//             imp.len = Some(len as u32);
//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::Implicit(imp)),
//             }, total_len);
//             // Other types not implemented yet
//         },
//         128 => { 
//             let mut tlv = Tlv::default();
//             tlv.tag = Some(tag as u32);
//             tlv.len = Some(data[1..1 + len_bytes].to_vec());
//             tlv.val = Some(sub_data[.. len].to_vec());
//             return (UniversalTypes{
//                 r#type: Some(universal_types::Type::Tlv(tlv)),
//             }, total_len);
//         }
//         _ => {
//             panic!("Unsupported tag: {}", tag);
//         }
//     }
// }

//     fn format_timestamp(timestamp: &Vec<u8>) -> Option<Timestamp> {
//         let timestamp = String::from_utf8(timestamp.clone()).ok()?;

//         if timestamp.len() != 13 || !timestamp.ends_with('Z') {
//             return None; // Invalid format
//         }
 
//         let year = 2000 + timestamp[0..2].parse::<i32>().ok()?; // Assuming 21st century
//         let month = timestamp[2..4].parse::<u32>().ok()?;
//         let day = timestamp[4..6].parse::<u32>().ok()?;
//         let hour = timestamp[6..8].parse::<u32>().ok()?;
//         let minute = timestamp[8..10].parse::<u32>().ok()?;
//         let second = timestamp[10..12].parse::<u32>().ok()?;

//         let naive_dt = NaiveDateTime::from_timestamp_opt(
//             Utc.with_ymd_and_hms(year, month, day, hour, minute, second).single()?.timestamp(),
//             0,
//         )?;

//         let value = naive_dt.and_utc();
//         let timestamp_nb = Timestamp{
//             seconds: value.timestamp() as i64,
//             nanos: value.timestamp_subsec_nanos() as i32,
//         };

//         Some(timestamp_nb)
//     }


// use crate::asn1_parser;
// use crate::prot::converter;
// use crate::prot::converter::asn1::asn1_universal_types::BitString;
// use crate::prot::converter::asn1::asn1_universal_types::BmpString;
// use crate::prot::converter::asn1::asn1_universal_types::Integer;
// use crate::prot::converter::asn1::asn1_universal_types::Null;
// use crate::prot::converter::asn1::asn1_universal_types::OctetString;
// use crate::prot::converter::asn1::asn1_universal_types::PrintableString;
// use crate::prot::converter::asn1::asn1_universal_types::Sequence;
// use crate::prot::converter::asn1::asn1_universal_types::TeletexString;
// use crate::prot::converter::asn1::asn1_universal_types::UniversalTypes;
// use crate::prot::converter::asn1::asn1_universal_types::universal_types;
// use crate::prot::converter::asn1::asn1_universal_types::Set;
// use crate::prot::converter::asn1::asn1_universal_types::Boolean;
// use crate::prot::converter::asn1::asn1_universal_types::Ia5String;
// use crate::prot::converter::asn1::asn1_universal_types::UtcTime;
// use crate::prot::converter::asn1::asn1_universal_types::Utf8String;
// use crate::prot::converter::asn1::asn1_universal_types::Implicit;
// use crate::prot::converter::asn1::asn1_universal_types::Tlv;
