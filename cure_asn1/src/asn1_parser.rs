use std::fmt;
use base64::{prelude::BASE64_STANDARD, Engine};

pub fn is_nested(tag: u8) -> bool {
    if tag == 4 || tag == 4 + 32 {
        // OctetString
        return true;
    } else if tag == 48 || tag == 48 + 32 {
        // Sequence
        return true;
    } else if tag == 49 || tag == 49 + 32 {
        // Set
        return true;
    } else if tag >= 160 && tag <= 166 {
        // Implicit
        return true;
    } else {
        return false;
    }
}

pub fn create_element(tag: u8, length: usize, data: &[u8], children: Option<Vec<Element>>) -> Element {
    let total_len = 1 + encode_asn1_length(length).len() + length;

    match tag {
        4 | 36 => {
            let value;
            if children.is_some() && children.as_ref().unwrap().len() == 1{
                value = Some(Box::new(children.unwrap()[0].clone()));
            } else {
                value = None;
            }
            Element::OctetString(OctetString {
                tag,
                length,
                value,
                total_len,
                data: data.to_vec(),
            })
        }
        48 | 80 => Element::Sequence(Sequence {
            tag,
            length,
            value: children.unwrap_or_default(),
            total_len,
            data: data.to_vec(),
        }),
        49 | 81 => Element::Set(Set {
            tag,
            length,
            value: children.unwrap_or_default(),
            total_len,
            data: data.to_vec(),
        }),
        160..=166 => Element::Implicit(Implicit {
            tag,
            length,
            value: children.unwrap_or_default(),
            total_len,
        }),
        _ => Element::TLV(TLV {
            tag,
            length,
            value: data.to_vec(),
            total_len,
            data: data.to_vec(),
        }),
    }
}

fn tag_is_constructed(tag: u8) -> bool {
    tag & 0b0010_0000 != 0
}


pub fn proc_nested(data: &[u8], cursor: usize, length: Option<usize>) -> Result<(Vec<u8>, usize, Vec<Element>), ASN1Error> {
    let mut content: Vec<u8> = Vec::new();
    let mut elements: Vec<Element> = Vec::new();

    let mut cursor = cursor;

    let start_cursor = cursor;
    while cursor + 2 < data.len() {
        let tag = data[cursor];
        let constructed = tag_is_constructed(tag);

        content.push(tag);

        cursor += 1;
        if is_nested(tag) {
            // 128 (0x80) => undefined length
            if data[cursor] == 128 {
                cursor += 1;
                let nested = proc_nested(&data, cursor, None);
                if nested.is_ok() {
                    let (new_content, new_cursor, children) = nested.unwrap();

                    let len = encode_asn1_length(new_content.len());
                    content.extend(len);

                    // De-construct constructed OctetStrings -> They are not required for DER
                    if constructed && tag == 36{
                        elements.extend(children);
                    }
                    else{
                        elements.push(create_element(tag, new_content.len(), &new_content, Some(children)));
                    }

                    content.extend(new_content);

                    cursor = new_cursor;
                }
                // Special case for OctetString, as here we only attempt inference, might also be a non-nested type
                else if tag == 4 || tag == 36 {
                    let first_occurrence = data[cursor..].windows(2).position(|window| window == [0, 0]);

                    if first_occurrence.is_none() {
                        return Err(ASN1Error {
                            message: "No end of content marker found".to_string(),
                        });
                    }

                    let mut first_occurrence = first_occurrence.unwrap();

                    // Check if BER encoded content of field ends with 00.
                    let mut count = 2;
                    for &byte in &data[cursor + first_occurrence + 2..] {
                        if byte == 0 {
                            count += 1;
                        } else {
                            break;
                        }
                    }
                    // This checks if the amount of 0x00 encountered is odd.
                    if count % 2 != 0 {
                        //If it is, then the field content ended with a 0x00, which needs to be skipped.
                        first_occurrence += 1;
                    }

                    let len = first_occurrence;

                    if data.len() < cursor + len {
                        return Err(ASN1Error {
                            message: "Length longer than Data1".to_string(),
                        });
                    }

                    content.extend(encode_asn1_length(first_occurrence));
                    content.extend(&data[cursor..cursor + len]);

                    elements.push(create_element(tag, first_occurrence, &data[cursor..cursor + len].to_vec(), None));

                    // +2 for the 0x00 0x00
                    cursor += len + 2;
                } else {
                    return Err(nested.err().unwrap());
                }
            } else {
                let (len, len_size) = parse_length(&data[cursor..])?;

                content.extend(&data[cursor..cursor + len_size]);
                cursor += len_size;

                if len == 0 {
                    elements.push(create_element(tag, len, &[], None));
                } else {
                    let nested = proc_nested(&data, cursor, Some(len));

                    // Special treatment for Octetstrings as they are trying to be inferred
                    if (tag == 4 || tag == 36)
                        && (nested.is_err() || nested.as_ref().unwrap().0.len() != len || nested.as_ref().unwrap().0.len() == 20)
                    {
                        if data.len() < cursor + len {
                            return Err(ASN1Error {
                                message: "Length longer than Data2".to_string(),
                            });
                        }
                        content.extend(&data[cursor..cursor + len]);

                        elements.push(create_element(tag, len, &data[cursor..cursor + len].to_vec(), None));

                        cursor += len;
                    } else if nested.is_ok() {
                        let (new_content, new_cursor, children) = nested?;

                        elements.push(create_element(tag, new_content.len(), &new_content, Some(children)));

                        content.extend(new_content);

                        cursor = new_cursor;
                    } else {
                        return Err(nested.err().unwrap());
                    }
                }
            }
        } else {
            if data[cursor] == 128 {
                cursor += 1;
                let first_occurrence = data[cursor..].windows(2).position(|window| window == [0, 0]);

                if first_occurrence.is_none() {
                    return Err(ASN1Error {
                        message: "No end of content marker found".to_string(),
                    });
                }

                let mut first_occurrence = first_occurrence.unwrap();

                // Check if BER encoded content of field ends with 00.
                let mut count = 2;
                for &byte in &data[cursor + first_occurrence + 2..] {
                    if byte == 0 {
                        count += 1;
                    } else {
                        break;
                    }
                }
                // This checks if the amount of 0x00 encountered is odd.
                if count % 2 != 0 {
                    //If it is, then the field content ended with a 0x00, which needs to be skipped.
                    first_occurrence += 1;
                }

                let len = first_occurrence;

                if data.len() < cursor + len {
                    return Err(ASN1Error {
                        message: "Length longer than Data3".to_string(),
                    });
                }

                content.extend(encode_asn1_length(first_occurrence));
                content.extend(&data[cursor..cursor + len]);

                elements.push(create_element(tag, first_occurrence, &data[cursor..cursor + len].to_vec(), None));

                // +2 for the 0x00 0x00
                cursor += len + 2;
            } else {
                let (len, len_size) = parse_length(&data[cursor..])?;
                if data.len() < cursor + len_size + len {
                    return Err(ASN1Error {
                        message: "Length longer than Data4".to_string(),
                    });
                }

                content.extend(&data[cursor..cursor + len_size]);
                cursor += len_size;
                content.extend(&data[cursor..cursor + len]);

                elements.push(create_element(tag, len, &data[cursor..cursor + len].to_vec(), None));

                cursor += len;
            }
        }
        if cursor >= data.len()
            || length.is_some() && cursor - start_cursor >= length.unwrap()
            || length.is_none() && data[cursor] == 0 && data[cursor + 1] == 0
        {
            if cursor < data.len() && length.is_none() && data[cursor] == 0 && data[cursor + 1] == 0 {
                cursor += 2;
            }
            return Ok((content, cursor, elements));
        }
    }
    return Err(ASN1Error {
        message: "No end of content marker found".to_string(),
    });
}

pub fn convert_ber_to_der(data: &Vec<u8>) -> Result<Vec<u8>, ASN1Error> {
    let (der, _, _) = proc_nested(data, 0, None)?;
    Ok(der)
}

pub fn parse_asn1_object(data: &Vec<u8>) -> Result<(Vec<u8>, Element), ASN1Error> {
    let (der, _, el) = proc_nested(data, 0, None)?;

    Ok((der, el[0].clone()))
}

pub fn parse_asn1_object_slim(data: &Vec<u8>) -> Result<Element, ASN1Error> {
    if data.len() == 0{
        return Err(ASN1Error::new("Data was empty".to_string()));
    }
    let (_, _, el) = proc_nested(data, 0, None)?;
    if data.len() == 0 || el.len() == 0 || el[0].get_child_amount() == 0{
        println!("Error with data {}", BASE64_STANDARD.encode(data));
        return Err(ASN1Error::new("Error".to_string()));
    }

    Ok(el[0].clone())
}

pub fn parse_length(data: &[u8]) -> Result<(usize, usize), ASN1Error> {
    let first_byte = data[0];
    let mut length: usize = 0;
    let length_bytes;

    // Short form -> Only one size bytes
    if first_byte & 0x80 == 0 {
        length = first_byte as usize;
        length_bytes = 1;
    } else {
        // Long Form: the number of length octets is specified in the lower 7 bits of the first byte
        let num_length_octets = (first_byte & 0x7F) as usize;

        if num_length_octets > 15 {
            return Err(ASN1Error {
                message: format!("Length longer than 8 octets: {:?}", data),
            });
        }

        for i in 0..num_length_octets {
            length <<= 8;
            if 1 + i >= data.len() {
                return Err(ASN1Error {
                    message: "Length longer than Data5".to_string(),
                });
            }
            length |= data[1 + i] as usize;
        }
        length_bytes = num_length_octets + 1;
    }
    return Ok((length, length_bytes));
}

#[derive(Debug)]
pub struct ASN1Error {
    pub message: String,
}

impl ASN1Error {
    pub fn new(message: String) -> ASN1Error {
        ASN1Error { message }
    }
}

impl fmt::Display for ASN1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

pub trait WriteASN1 {
    fn encode(&self) -> Vec<u8>;
}

pub fn encode_asn1_length(length: usize) -> Vec<u8> {
    if length <= 127 {
        vec![length as u8]
    } else {
        let mut length_bytes = Vec::new();
        let mut remaining_length = length;

        while remaining_length > 0 {
            let byte = (remaining_length & 0xFF) as u8;
            length_bytes.insert(0, byte);
            remaining_length >>= 8;
        }
        let num_length_bytes = length_bytes.len();
        let first_byte = 0x80 | (num_length_bytes as u8);

        let mut result = vec![first_byte];
        result.extend(length_bytes);
        result
    }
}

#[derive(Clone, Debug)]
pub enum Element {
    Sequence(Sequence),
    Set(Set),
    TLV(TLV),
    OctetString(OctetString),
    Implicit(Implicit),
}


// Implement `From` for each ASN.1 type
impl From<TLV> for Element {
    fn from(tlv: TLV) -> Self {
        Element::TLV(tlv)
    }
}

impl From<Sequence> for Element {
    fn from(seq: Sequence) -> Self {
        Element::Sequence(seq)
    }
}

impl From<Set> for Element {
    fn from(set: Set) -> Self {
        Element::Set(set)
    }
}

impl From<OctetString> for Element {
    fn from(octet_string: OctetString) -> Self {
        Element::OctetString(octet_string)
    }
}

impl From<Implicit> for Element {
    fn from(implicit: Implicit) -> Self {
        Element::Implicit(implicit)
    }
}


impl Element {
    pub fn get_len(&self) -> usize {
        match self {
            Element::Sequence(seq) => seq.total_len,
            Element::Set(set) => set.total_len,
            Element::TLV(tlv) => tlv.total_len,
            Element::OctetString(octet_string) => octet_string.total_len,
            Element::Implicit(implicit) => implicit.total_len,
        }
    }

    pub fn get_tag(&self) -> u8 {
        match self {
            Element::Sequence(seq) => seq.tag,
            Element::Set(set) => set.tag,
            Element::TLV(tlv) => tlv.tag,
            Element::OctetString(octet_string) => octet_string.tag,
            Element::Implicit(implicit) => implicit.tag,
        }
    }

    pub fn get_data(&self) -> Vec<u8>{
        match self {
            Element::Sequence(seq) => seq.data.clone(),
            Element::Set(set) => set.data.clone(),
            Element::TLV(tlv) => tlv.data.clone(),
            Element::OctetString(octet_string) => octet_string.data.clone(),
            Element::Implicit(imp) => imp.value[0].get_data(),
        }
    }

    pub fn get_child_amount(&self) -> usize{
        match self {
            Element::Sequence(seq) => seq.value.len(),
            Element::Set(set) => set.value.len(),
            Element::TLV(_) => 0,
            Element::OctetString(oc) => oc.value.is_some().then(|| 1).unwrap_or(0),
            Element::Implicit(imp) => imp.value.len(),
        }
    }

    pub fn encode_content(&self) -> Vec<u8>{
        match self {
            Element::Sequence(seq) => seq.encode_content(),
            Element::Set(set) => set.encode_content(),
            Element::TLV(tlv) => tlv.value.clone(),
            Element::OctetString(octet_string) => octet_string.data.clone(),
            Element::Implicit(imp) => imp.value[0].get_data(),
        }
    }

    pub fn add_child(&mut self, child: Element){
        match self {
            Element::Sequence(seq) => seq.value.push(child),
            Element::Set(set) => set.value.push(child),
            Element::TLV(_) => println!("Cannot add child to TLV"),
            Element::OctetString(_) => println!("Cannot add child to OctetString"),
            Element::Implicit(imp) => imp.value.push(child),
        }
    }
}

impl WriteASN1 for Element {
    fn encode(&self) -> Vec<u8> {
        match self {
            Element::Sequence(seq) => seq.encode(),
            Element::Set(set) => set.encode(),
            Element::TLV(tlv) => tlv.encode(),
            Element::OctetString(octet_string) => octet_string.encode(),
            Element::Implicit(implicit) => implicit.encode(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TLV {
    pub tag: u8,
    pub length: usize,
    pub value: Vec<u8>,
    pub total_len: usize,
    pub data: Vec<u8>,
}

impl TLV {
    pub fn new(tag: u8, value: Vec<u8>) -> TLV {
        let len = value.len();
        let total_len = 1 + encode_asn1_length(len).len() + len;

        TLV {
            tag,
            length: len,
            value: value.clone(),
            total_len,
            data: value,
        }
    }

    /// Turns Value into Element
    pub fn to_el(self) -> Element{
        Element::TLV(self)
    }
}

impl WriteASN1 for TLV {
    fn encode(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();
        encoded.push(self.tag);
        encoded.append(&mut encode_asn1_length(self.length));
        encoded.append(&mut self.value.clone());
        encoded
    }
}

#[derive(Clone, Debug)]
pub struct Set {
    pub tag: u8,
    pub length: usize,
    pub value: Vec<Element>,
    pub total_len: usize,
    pub data: Vec<u8>,
}

impl Set {
    pub fn new(values: Vec<Element>) -> Set {
        let mut length = 0;
        let mut data = vec![];

        for v in &values {
            length += v.get_len();

            data.extend(v.encode());
        }

        let total_len = 1 + encode_asn1_length(length).len() + length;

        Set {
            tag: 49,
            length,
            value: values,
            total_len,
            data,
        }
    }

    pub fn encode_content(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();
        for item in self.value.clone() {
            encoded.append(&mut item.encode());
        }
        encoded
    }

    pub fn to_tlv(&self) -> TLV {
        TLV {
            tag: self.tag,
            length: self.length,
            value: self.encode_content(),
            total_len: self.total_len,
            data: self.data.clone(),
        }
    }

    pub fn to_el(self) -> Element{
        Element::Set(self)
    }

}

impl WriteASN1 for Set {
    fn encode(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();
        encoded.push(self.tag);
        encoded.append(&mut encode_asn1_length(self.length));
        for item in self.value.clone() {
            encoded.append(&mut item.encode());
        }
        encoded
    }
}

#[derive(Clone, Debug)]
pub struct Sequence {
    pub tag: u8,
    pub length: usize,
    pub value: Vec<Element>,
    pub total_len: usize,
    pub data: Vec<u8>,
}

impl Sequence {
    pub fn new(values: Vec<Element>) -> Sequence {
        let mut length = 0;
        let mut data = vec![];

        for v in &values {
            length += v.get_len();

            data.extend(v.encode());
        }

        let total_len = 1 + encode_asn1_length(length).len() + length;

        Sequence {
            tag: 48,
            length,
            value: values,
            total_len,
            data,
        }
    }
    pub fn encode_content(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();

        for item in self.value.clone() {
            encoded.append(&mut item.encode());
        }
        encoded
    }

    pub fn to_tlv(&self) -> TLV {
        TLV {
            tag: self.tag,
            length: self.length,
            value: self.encode_content(),
            total_len: self.total_len,
            data: self.data.clone(),
        }
    }

    pub fn to_el(self) -> Element{
        Element::Sequence(self)
    }
}

impl WriteASN1 for Sequence {
    fn encode(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();
        encoded.push(self.tag);
        encoded.append(&mut encode_asn1_length(self.length));
        for item in self.value.clone() {
            encoded.append(&mut item.encode());
        }
        encoded
    }
}

#[derive(Clone, Debug)]
pub struct OctetString {
    pub tag: u8,
    pub length: usize,
    pub value: Option<Box<Element>>,
    pub total_len: usize,
    pub data: Vec<u8>,
}

impl OctetString {
    pub fn new(value: Vec<u8>) -> OctetString {
        let len = value.len();
        let total_len = 1 + encode_asn1_length(len).len() + len;

        OctetString {
            tag: 4,
            length: len,
            value: None,
            total_len,
            data: value,
        }
    }

    pub fn new_el(value: Element) -> OctetString {
        let len = value.get_len();
        let total_len = 1 + encode_asn1_length(len).len() + len;

        OctetString {
            tag: 4,
            length: len,
            value: Some(Box::new(value)),
            total_len,
            data: vec![],
        }
    }

    pub fn to_tlv(&self) -> TLV {
        TLV {
            tag: self.tag,
            length: self.length,
            value: self.data.clone(),
            total_len: self.total_len,
            data: self.data.clone(),
        }
    }

    pub fn to_el(self) -> Element{
        Element::OctetString(self)
    }
}

impl WriteASN1 for OctetString {
    fn encode(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();
        encoded.push(self.tag);
        encoded.extend(encode_asn1_length(self.length));
        if self.value.is_some() {
            encoded.extend(self.value.as_ref().unwrap().encode());
        } else {
            encoded.extend(self.data.clone());
        }
        encoded
    }
}

#[derive(Clone, Debug)]
pub struct Implicit {
    pub tag: u8,
    pub length: usize,
    pub value: Vec<Element>,
    pub total_len: usize,
}

impl Implicit {
    pub fn new(tag: u8, value: Vec<Element>) -> Implicit {
        let mut total_length = 0;

        for e in &value {
            total_length += e.get_len();
        }
        let len = total_length;
        let total_len = 1 + encode_asn1_length(len).len() + len;

        Implicit {
            tag,
            length: len,
            value: value,
            total_len,
        }
    }

    pub fn to_tlv(&self) -> TLV {
        let mut new_v = vec![];
        for v in &self.value {
            new_v.extend(v.encode());
        }
        TLV {
            tag: self.tag,
            length: self.length,
            value: new_v,
            total_len: self.total_len,
            data: vec![],
        }
    }

    pub fn to_el(self) -> Element{
        Element::Implicit(self)
    }
}

impl WriteASN1 for Implicit {
    fn encode(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();
        encoded.push(self.tag);
        encoded.append(&mut encode_asn1_length(self.length));

        for item in self.value.clone() {
            encoded.append(&mut item.encode());
        }
        encoded
    }
}
