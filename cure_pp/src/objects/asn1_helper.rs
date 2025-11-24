#![allow(unused)] 

use cure_asn1::{asn1_parser::WriteASN1, rpki::rpki::{ObjectType, RpkiObject}};


use super::{
    asn1_aspa, asn1_certificate, asn1_ghostbuster, asn1_imft, asn1_iroa, asn1_objects::{ObjectConf, ObjectVersion}
};

pub struct RoaConf {
    // IP, maxlength
    pub ipv4: Vec<(Vec<u8>, Option<u32>)>,
    pub ipv6: Vec<(Vec<u8>, Option<u32>)>,
    pub asn: u64,
}

pub fn create_object(typ: &ObjectType) -> Vec<u8> {
    let mut conf = ObjectConf::default();
    conf.typ = typ.clone();
    let v = ObjectVersion::Default;

    if typ == &ObjectType::ROA {
        let roa_string = "10.0.1.0/24 => AS34";
        asn1_iroa::create_roa(roa_string, &conf, v).encode()
    } else if typ == &ObjectType::MFT {
        let ve = vec![("test.obj".to_string(), vec![1,2,3,4,5,6,7,8])];

        asn1_imft::create_manifest(1, &ve, &conf).encode()
    } else if typ == &ObjectType::CERTCA {
        asn1_certificate::create_certificate(&conf).encode()
    } else if typ == &ObjectType::CERTROOT {
        conf.is_root = true;
        asn1_certificate::create_certificate(&conf).encode()
    } else if typ == &ObjectType::CRL {
        let ve = vec![];

        asn1_certificate::create_crl(&ve, &conf).encode()
    } else if typ == &ObjectType::IROA{
        let roa_string = "10.0.1.0/24 => AS33";

        asn1_iroa::create_iroa(roa_string, &conf).encode()

    }else if typ == &ObjectType::IMFT{
        let ve = vec![];

        asn1_imft::create_imft(1, &ve, &conf).encode()
    }
    else if typ == &ObjectType::GBR{
        asn1_ghostbuster::create_ghostbuster(conf).encode()
    }
    else if typ == &ObjectType::ASA{
        asn1_aspa::create_aspa(conf).encode()
    }
        else {
        vec![]
    }
}


pub fn convert_object_to_i(input_obj: &RpkiObject, crl_o: Option<&RpkiObject>) -> RpkiObject{
    let mut conf = ObjectConf::default();
    let typ = ObjectType::from_string(&input_obj.typ);
    conf.typ = typ.clone();
    let v = ObjectVersion::Default;

    match typ{
        ObjectType::ROA => {            
            let roa_string = "10.0.1.0/24 => AS33";

            let mut parsed = cure_asn1::rpki::rpki::parse_rpki_object(&asn1_iroa::create_iroa(roa_string, &conf).encode(), &ObjectType::IROA).unwrap();

            let ip_data = input_obj.content.get_raw_by_label("ipAddrBlocks").unwrap();
            parsed.content.set_data_by_label("ipAddrBlocks", ip_data, true, true);

            let asn = input_obj.content.get_raw_by_label("asID").unwrap();
            parsed.content.set_data_by_label("asID", asn, true, true);

            parsed.content.fix_sizes(true);
            return parsed;

        },
        ObjectType::MFT => {
            let mut parsed = cure_asn1::rpki::rpki::parse_rpki_object(&asn1_imft::create_imft(1, &vec![], &conf).encode(), &ObjectType::IMFT).unwrap();

            let entries = input_obj.get_mft_entries_raw();
            println!("Entries {}", entries.len());
            parsed.set_mft_entries_raw(entries);

            if let Some(crl) = crl_o{
                let entries = crl.get_crl_entries_raw();
                parsed.set_crl_entries_raw(entries);
            }
            return parsed;

        }
        _ => {return input_obj.to_owned();}
    }

}

pub fn create_roa(as_id: u64) -> Vec<u8> {
    let mut conf = ObjectConf::default();
    conf.typ = ObjectType::ROA;
    let v = ObjectVersion::Default;

    let roa_string = format!("10.0.0.0/24 => AS{}", as_id);
    asn1_iroa::create_roa(&roa_string, &conf, v).encode()
}
