use cure_asn1::asn1_parser::{Element, OctetString};

use super::{asn1_objects::ObjectConf, asn1_sigdata};

pub fn create_ghostbuster(conf: ObjectConf) -> Element{
    let s = "BEGIN:VCARD
    VERSION:3.0
    ADR:;;Example Address;Frankfurt;Hessen;60486;DE
    EMAIL:example@example.com
    FN:John Doe
    N:;;;;
    ORG:GU
    TEL:+49 12345678912
    END:VCARD";

    let content = OctetString::new(s.as_bytes().to_vec());
    asn1_sigdata::create_signed_data(content.to_el(), &conf)

}



