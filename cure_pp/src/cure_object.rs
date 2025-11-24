use crate::{
    cure_repo::FixingLevel, objects::{asn1_fields, asn1_helper}, repository_util::{self, read_cert_key, ObjectKey, RepoConfig}
};
use chrono::Utc;
use cure_asn1::{asn1_parser::Element, rpki::rpki::ObjectType, rpki::rpki_utils::byt_to_in};
use cure_asn1::mutator;
use cure_asn1::{
    asn1_parser::{Sequence, TLV},
    tree_parser::Tree,
};

use rand::prelude::SliceRandom;
use rand::Rng;
use serde::Deserializer;
use serde::{
    de::{self, Visitor},
    Deserialize, Serialize, Serializer,
};
use sha2::Digest;
use std::{
    fmt, vec
};

use crate::repository_util::random_fname;
use crate::repository_util::load_random_key;

#[derive(Clone)]
pub struct CureObject {
    pub op_type: ObjectType,
    pub parent_key: ObjectKey,
    pub child_key: ObjectKey,
    pub tree: Tree,
    pub name: String,
    pub prev_hash: Option<Vec<u8>>,
}

impl CureObject{
    pub fn _default() -> CureObject{
        let key = read_cert_key("/tmp/default.key");
        CureObject { op_type: ObjectType::UNKNOWN, parent_key:key.clone(), child_key: key, tree: Tree::new(""), name: "".to_string(), prev_hash: None}
    }
}

impl Serialize for CureObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let tuple = (
            &self.op_type,
            &self.parent_key.file_uri,
            &self.child_key.file_uri,
            &self.tree,
            &self.name,
        );
        tuple.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CureObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CureObjectVisitor;

        impl<'de> Visitor<'de> for CureObjectVisitor {
            type Value = CureObject;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a tuple representing a CureObject")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<CureObject, V::Error>
            where
                V: de::SeqAccess<'de>,
            {
                let op_type = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let parent_key_t = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let parent_key = repository_util::read_cert_key(parent_key_t);
                let child_key_t = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let child_key = repository_util::read_cert_key(child_key_t);

                let tree = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(3, &self))?;
                let name = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(4, &self))?;

                Ok(CureObject {
                    op_type,
                    parent_key,
                    child_key,
                    tree,
                    name,
                    prev_hash: None,
                })
            }
        }

        deserializer.deserialize_tuple(6, CureObjectVisitor)
    }
}

impl CureObject {
    pub fn new(op_type: ObjectType, parent_key: ObjectKey, child_key: ObjectKey, tree: Tree, name: String) -> Self {
        Self {
            op_type,
            parent_key,
            child_key,
            tree,
            name,
            prev_hash: None,
        }
    }

    pub fn get_ski_b64(&self) -> String {
        let aki = self.tree.get_data_by_label("subjectPublicKeyInfoField").unwrap();
        let aki_b64 = base64::encode(&aki);
        aki_b64
    }

    pub fn random_asn(&mut self) -> i32 {
        if self.tree.get_data_by_label("asID").is_some() && !self.tree.node_manipulated_by_label("asID") {
            let asid = rand::thread_rng().gen_range(0..10000);
            let d = if asid < 128 {
                vec![asid as u8]
            } else {
                vec![(asid >> 8) as u8, asid as u8]
            };

            self.tree.set_data_by_label("asID", d, true, false);
            return asid;
        }
        return 0;
    }

    pub fn get_asn(&self) -> u64 {
        if self.tree.get_raw_by_label("asID").is_some() && !self.tree.node_manipulated_by_label("asID") {
            let data = self.tree.get_raw_by_label("asID").unwrap();
            return byt_to_in(&data);
            // if data.len() == 1 {
            //     return Some(data[0] as i32);
            // } else if data.len() == 2 {
            //     return Some(((data[0] as i32) << 8) | (data[1] as i32));
            // }
        }
        return 0;
        // None
    }

    pub fn specific_asn(&mut self, asn: u32) {
        if self.tree.get_data_by_label("asID").is_some() && !self.tree.node_manipulated_by_label("asID") {
            let d = if asn < 128 {
                vec![asn as u8]
            } else {
                vec![(asn >> 8) as u8, asn as u8]
            };
            self.tree.set_data_by_label("asID", d, true, false);
        }
    }

    pub fn ca_matching_asn(&mut self, ca_number: i32) {
        if self.tree.get_data_by_label("asID").is_some() && !self.tree.node_manipulated_by_label("asID") {
            let d = if ca_number < 128 {
                vec![ca_number as u8]
            } else {
                vec![(ca_number >> 8) as u8, ca_number as u8]
            };

            self.tree.set_data_by_label("asID", d, true, false);
        }
    }

    pub fn token_mutation(&mut self) {
        self.tree.mutate();
    }

    pub fn splice_mutation(&mut self, other_tree: &Tree) {
        let likelihoods = vec![1, 1, 1, 1, 1, 2, 2, 3];
        let amount_splice = likelihoods.choose(&mut rand::thread_rng()).unwrap();

        let random_s = rand::thread_rng().gen_range(0..2);
        let random_splice = random_s == 0;

        mutator::splice_tree(&mut self.tree, other_tree, *amount_splice, random_splice);
    }

    pub fn fix_digest(&mut self) {
        if self.tree.node_manipulated_by_label("messageDigest") {
            return;
        }
        if self.tree.get_node_by_label("encapsulatedContent").is_none() {
            return;
        }

        let data = self.tree.encode_node(self.tree.get_node_by_label("encapsulatedContent").unwrap());

        let hash = sha2::Sha256::digest(&*data);
        // let hash = <[u8; 32]>::from_hex(hash).unwrap().to_vec();
        self.tree.set_data_by_label("messageDigest", hash.to_vec(), true, false);
    }

    pub fn fix_ski(&mut self) {
        if self.tree.node_manipulated_by_label("subjectKeyIdentifier") {
            return;
        }

        let sub_key_id = self.child_key.get_key_id_raw();

        self.tree.set_data_by_label("subjectKeyIdentifier", sub_key_id.clone(), true, false);
    }

    pub fn fix_aki(&mut self) {
        if self.tree.node_manipulated_by_label("authorityKeyIdentifier") {
            return;
        }

        let par_key_id = self.parent_key.get_key_id_raw();
        self.tree
            .set_data_by_label("authorityKeyIdentifier", par_key_id.clone(), true, false);
    }

    pub fn fix_names(&mut self) {
        // Fix issuer name and subject name
        if !self.tree.node_manipulated_by_label("issuerName") {
            self.tree
                .set_data_by_label("issuerName", self.parent_key.get_key_id().as_bytes().to_vec(), true, false);
        }

        if !self.tree.node_manipulated_by_label("subjectName") {
            self.tree
                .set_data_by_label("subjectName", self.child_key.get_key_id().as_bytes().to_vec(), true, false);
        }
    }

    pub fn fix_sid(&mut self) {
        let sub_key_id = self.child_key.get_key_id_raw();
        if !self.tree.node_manipulated_by_label("signerIdentifier") {
            self.tree.set_data_by_label("signerIdentifier", sub_key_id.clone(), true, false);
        }
    }

    pub fn fix_subject_key(&mut self) {
        let mut new_bits: Vec<u8> = vec![0];
        new_bits.extend(self.child_key.get_pub_key_bits());

        if !self.tree.node_manipulated_by_label("subjectPublicKey") {
            self.tree.set_data_by_label("subjectPublicKey", new_bits, true, false);
        }
    }

    pub fn fix_validty(&mut self) {
        let now = Utc::now();
        let twenty_four_hours_ago = now - chrono::Duration::hours(24);
        let utc_time_string = twenty_four_hours_ago.format("%y%m%d%H%M%SZ").to_string();
        let not_before: Vec<u8> = utc_time_string.as_bytes().to_vec();

        let in_three_days = now + chrono::Duration::days(90);
        let utc_time_string = in_three_days.format("%y%m%d%H%M%SZ").to_string();
        let not_after: Vec<u8> = utc_time_string.as_bytes().to_vec();
        if !self.tree.node_manipulated_by_label("notBefore") {
            self.tree.set_data_by_label("notBefore", not_before, true, false);
        }

        if !self.tree.node_manipulated_by_label("notAfter") {
            self.tree.set_data_by_label("notAfter", not_after, true, false);
        }
    }

    pub fn fix_mft_validity(&mut self) {
        let now = Utc::now();
        let twenty_four_hours_ago = now - chrono::Duration::hours(24);
        // Use GeneralizedTime format: YYYYMMDDHHMMSSZ
        let generalized_time_string = twenty_four_hours_ago.format("%Y%m%d%H%M%SZ").to_string();
        let not_before: Vec<u8> = generalized_time_string.as_bytes().to_vec();

        let in_three_days = now + chrono::Duration::days(90);
        // Use GeneralizedTime format: YYYYMMDDHHMMSSZ
        let generalized_time_string = in_three_days.format("%Y%m%d%H%M%SZ").to_string();
        let not_after: Vec<u8> = generalized_time_string.as_bytes().to_vec();

        if !self.tree.node_manipulated_by_label("thisUpdate") {
            self.tree.set_data_by_label("thisUpdate", not_before, true, false);
        }

        if !self.tree.node_manipulated_by_label("nextUpdate") {
            self.tree.set_data_by_label("nextUpdate", not_after, true, false);
        }
    }

    pub fn fix_crl_location(&mut self, conf: &RepoConfig) {
        let storage_base_uri;
        let cert_key_uri;
        if self.op_type == ObjectType::CERTCA || self.op_type == ObjectType::CERTROOT {
            storage_base_uri = "rsync://".to_string() + &conf.domain + "/" + &conf.base_repo_dir + &conf.ca_tree[&conf.ca_name] + "/";
            cert_key_uri = conf.base_key_dir_l.clone() + &conf.ca_tree[&conf.ca_name] + "_cer.der";
        } else {
            storage_base_uri = "rsync://".to_string() + &conf.domain + "/" + &conf.base_repo_dir + &conf.ca_name + "/";
            cert_key_uri = conf.base_key_dir_l.clone() + &conf.ca_name + "_cer.der";
        }
        let filename = repository_util::get_filename_crl_mft(&cert_key_uri);
        let crl_uri = storage_base_uri.clone() + &filename + ".crl";

        if !self.tree.node_manipulated_by_label("crlDistributionPoint") {
            self.tree
                .set_data_by_label("crlDistributionPoint", crl_uri.as_bytes().to_vec(), true, false);
        }
    }

    pub fn fix_authority_location(&mut self, conf: &RepoConfig) {
        let parent_repo = conf.ca_tree.get(&conf.ca_name);
        if parent_repo.is_none(){
            return;
        }
        let parent_repo = parent_repo.unwrap();
        let storage_uri = "rsync://".to_string() + &conf.domain + "/" + &conf.base_repo_dir + &parent_repo + "/" + &conf.ca_name + ".cer";
        if !self.tree.node_manipulated_by_label("caIssuersURI") {
            self.tree
                .set_data_by_label("caIssuersURI", storage_uri.as_bytes().to_vec(), true, false);
        }
    }

    pub fn fix_signed_object_location(&mut self, conf: &RepoConfig) {
        let storage_uri = "rsync://".to_string() + &conf.domain + "/" + &conf.base_repo_dir + &conf.ca_name + "/" + &self.name;

        if !self.tree.node_manipulated_by_label("signedObjectURI") {
            self.tree
                .set_data_by_label("signedObjectURI", storage_uri.as_bytes().to_vec(), true, false);
        }
    }

    pub fn fix_ca_repository(&mut self, conf: &RepoConfig) {
        let storage_uri = "rsync://".to_string() + &conf.domain + "/" + &conf.base_repo_dir + &conf.ca_name + "/";

        if !self.tree.node_manipulated_by_label("caRepositoryURI") {
            self.tree
                .set_data_by_label("caRepositoryURI", storage_uri.as_bytes().to_vec(), true, false);
        }
    }

    pub fn fix_manifest_uri(&mut self, conf: &RepoConfig) {
        let cert_key_path = conf.base_key_dir.clone() + &conf.ca_name + "_cer.der";

        let suffix = if conf.irpki{".imft"} else{".mft"};
        let storage_uri = "rsync://".to_string()
            + &conf.domain
            + "/"
            + &conf.base_repo_dir
            + &conf.ca_name
            + "/"
            + &repository_util::get_filename_crl_mft(&cert_key_path)
            + suffix;

        if !self.tree.node_manipulated_by_label("rpkiManifestURI") {
            self.tree
                .set_data_by_label("rpkiManifestURI", storage_uri.as_bytes().to_vec(), true, false);
        }
    }

    fn in_to_byt(inp: u64) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        let mut temp = inp;
        while temp > 0 {
            result.push((temp & 0xFF) as u8);
            temp >>= 8;
        }
        result.reverse();
        result
    }

    pub fn fix_manifest_number(&mut self) {
        if self.tree.node_manipulated_by_label("manifestNumber") {
            return;
        }

        let data = self.tree.get_raw_by_label("manifestNumber");
        if data.is_none() {
            return;
        }

        // Get current unix timestampe
        let timestamp = Utc::now().timestamp();

        let new_data = Self::in_to_byt(timestamp.abs() as u64); // Use timestamp to ensure increase

        if !self.tree.set_data_by_label("manifestNumber", new_data, true, false) {
            eprintln!("Setting didnt work");
        }
    }

    pub fn fix_notification_uri(&mut self, conf: &RepoConfig) {
        // let extension = if crate::rrdp_proto() { "bin" } else { "xml" }; TODO
        let extension = "xml";
        let storage_uri = format!("https://{}/{}notification.{}", &conf.domain, &conf.base_rrdp_dir, extension); // todo

        if !self.tree.node_manipulated_by_label("rpkiNotifyURI") {
            self.tree
                .set_data_by_label("rpkiNotifyURI", storage_uri.as_bytes().to_vec(), true, false);
        }
    }

    pub fn fix_signer_signature(&mut self, initial_run: bool) {
        if self.tree.get_node_by_label("signerSignedAttributesField").is_none() {
            return;
        }
        let data = self.tree.encode_node(self.tree.get_node_by_label("signerSignedAttributesField").unwrap());
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

        // Store the previous hash that was signed -> Idea: Don't sign if nothing changed
        let child_key_id = self.child_key.get_key_id().as_bytes().to_vec();
        if self.tree.additional_info.contains_key("signerSignature")
            && self.tree.additional_info.get("signerSignature").unwrap() == &res
            && *self.tree.additional_info.get("childKey").unwrap_or(&vec![]) == child_key_id
            && !initial_run
        {
            return;
        }

        let sig;
        if self.op_type == ObjectType::IMFT || self.op_type == ObjectType::IROA {
            sig = self.parent_key.sign(&res).to_vec();

        }
        else{   
            sig = self.child_key.sign(&res).to_vec();
        } 

        if !self.tree.node_manipulated_by_label("signerSignature") {
            self.tree.additional_info.insert("signerSignature".to_string(), res.clone());
            self.tree.additional_info.insert("childKey".to_string(), child_key_id.clone());

            self.tree.set_data_by_label("signerSignature", sig, true, false);
        }
    }

    pub fn fix_certificate_signature(&mut self, initial_run: bool) {
        if self.tree.get_node_by_label("certificate").is_none() || !self.tree.get_node_by_label("certificate").unwrap().tainted {
            return;
        }

        // Store the previous hash that was signed -> Idea: Don't sign if nothing changed
        let data = self.tree.encode_node(&self.tree.get_node_by_label("certificate").unwrap());

        let parent_key_id = self.parent_key.get_key_id().as_bytes().to_vec();
        if self.tree.additional_info.contains_key("certificateSignature")
            && self.tree.additional_info.get("certificateSignature").unwrap() == &data
            && *self.tree.additional_info.get("parentKey").unwrap_or(&vec![]) == parent_key_id
            && !initial_run
        {
            return;
        }

        let sig = self.parent_key.sign(&data).to_vec();

        let mut sig_bits: Vec<u8> = vec![0];
        sig_bits.extend(sig);

        if !self.tree.node_manipulated_by_label("certificateSignature") {
            self.tree.additional_info.insert("certificateSignature".to_string(), data.clone());
            self.tree.additional_info.insert("parentKey".to_string(), parent_key_id.clone());
            self.tree.set_data_by_label("certificateSignature", sig_bits, true, false);
        }
    }

    // pub fn change_ips(&mut self) {
    //     if self.tree.get_node_by_label("certificate").is_none() {
    //         return;
    //     }

    //     self.tree.set_data_by_label(
    //         "ipAddrBlocksSequence",
    //         vec![48, 21, 4, 2, 0, 2, 48, 15, 3, 6, 0, 32, 1, 5, 6, 3, 3, 5, 0, 38, 5, 156, 192],
    //         true,
    //         false,
    //     );
    // }

    // pub fn find_specific_file(root_dir: &str, target_filename: &str) -> Option<String> {
    //     for entry in WalkDir::new(root_dir).into_iter().filter_map(|e| e.ok()) {
    //         let path = entry.path();
    //         if path.is_file() && path.file_name().unwrap().to_str() == Some(target_filename) {
    //             return Some(path.to_string_lossy().into_owned());
    //         }
    //     }

    //     None
    // }

    pub fn fix_ifields(&mut self, conf: &RepoConfig, hashlist: Option<Element>){
        if self.op_type == ObjectType::IMFT && hashlist.is_some() {
            self.fix_hash_list(hashlist.unwrap());
            self.fix_manifest_number();
            self.tree.fix_sizes(true);
        }



        if self.op_type == ObjectType::IMFT || self.op_type == ObjectType::IROA{
            self.fix_signed_object_location(conf);
        }


        self.tree.fix_sizes(true);
     

    }


    pub fn fix_fields(&mut self, level: &FixingLevel, conf: &RepoConfig, hashlist: Option<Element>) {
        if hashlist.is_none() && self.prev_hash.is_some(){
            // Optimization: Dont recompute anything if nothing changed
            let hash = self.get_hash();
            if hash.to_vec() == *self.prev_hash.as_ref().unwrap(){
                return;
            }
        }


        if (self.op_type == ObjectType::MFT || self.op_type == ObjectType::IMFT) && hashlist.is_some() {
            let hl = hashlist.unwrap();
            // If we have more than 50, we need to encode hashlist. We lose the child structure but save a lot of time.
            if hl.get_child_amount() < 50 || !conf.fuzzing //|| crate::roa_proto()
            {
                self.fix_hash_list(hl);
            }
            else{
                self.fix_hash_list_fast(hl.encode_content());
            }
            // self.fix_hash_list_old(hashlist.unwrap().encode());
            self.fix_manifest_number();
            self.tree.fix_sizes(true);
        }

        if self.op_type == ObjectType::ROA || self.op_type == ObjectType::MFT || self.op_type == ObjectType::ASA || self.op_type == ObjectType::GBR {
            self.fix_signed_object_location(conf);
        } else if self.op_type == ObjectType::CERTCA || self.op_type == ObjectType::CERTROOT {
            self.fix_ca_repository(conf);

            self.fix_manifest_uri(conf);
        }

        if self.op_type == ObjectType::MFT || self.op_type == ObjectType::ROA || self.op_type == ObjectType::ASA || self.op_type == ObjectType::GBR {
            self.fix_crl_location(conf);
        }

        // This is only necessary in initial run
        if level.score() > 0 {
            self.fix_sid();

            self.fix_names();

            if (self.op_type == ObjectType::MFT || self.op_type == ObjectType::IMFT) && level.score() > 1 {
                self.fix_mft_validity();
                self.tree.fix_sizes(true);
            }

            if level.score() > 1 {
                self.fix_validty();
            }
        
            self.fix_aki();

            if self.op_type != ObjectType::CRL && self.op_type != ObjectType::MFT && self.op_type != ObjectType::ROA && self.op_type != ObjectType::ASA && self.op_type != ObjectType::IROA{
                self.fix_crl_location(conf);
            }

            if self.op_type != ObjectType::CRL {
                self.fix_ski();
                self.fix_subject_key();
            }

            if self.op_type == ObjectType::MFT || self.op_type == ObjectType::CERTCA || self.op_type == ObjectType::ROA {
                self.fix_authority_location(conf);
            }

            if self.op_type != ObjectType::CRL && self.op_type != ObjectType::MFT && self.op_type != ObjectType::ROA {
                // self.change_ips();
            }

            if self.op_type == ObjectType::ROA || self.op_type == ObjectType::MFT || self.op_type == ObjectType::ASA || self.op_type == ObjectType::GBR {
                self.fix_signed_object_location(conf);
            } else if self.op_type == ObjectType::CERTCA || self.op_type == ObjectType::CERTROOT {
                self.fix_notification_uri(conf);
            }
        }

        if self.op_type == ObjectType::ROA || self.op_type == ObjectType::IMFT ||  self.op_type == ObjectType::MFT ||
         self.op_type == ObjectType::ASA || self.op_type == ObjectType::GBR || (self.op_type == ObjectType::IROA //&& crate::no_ee()
        ) 
         {
            self.tree.fix_sizes(true);
            self.fix_digest();
        }

        // After potentially changing some fields -> Fix their sizes
        self.tree.fix_sizes(true);

        self.fix_signer_signature(level == &FixingLevel::Full);

        self.fix_certificate_signature(level == &FixingLevel::Full);

        self.prev_hash = Some(self.get_hash());
        self.tree.remove_taint();
    }

    pub fn fix_hash_list(&mut self, hashlist: Element) {
        if self.op_type != ObjectType::MFT && self.op_type != ObjectType::IMFT {
            println!("ERROR: Fixing Hash List only necessary in Manifest");
        }

        if self.tree.node_manipulated_by_label("manifestHashes") {
            return;
        }
        if !self.tree.set_element_by_label("manifestHashes", hashlist, true, false) {
            println!("Couldnt find manifestHashes");
        }
    }

    pub fn fix_hash_list_fast(&mut self, hashlist: Vec<u8>) {
        if self.op_type != ObjectType::MFT && self.op_type != ObjectType::IMFT {
            println!("ERROR: Fixing Hash List only necessary in Manifest");
        }

        if self.tree.node_manipulated_by_label("manifestHashes") {
            return;
        }
        if !self.tree.set_data_by_label("manifestHashes", hashlist, true, false) {
            println!("Couldnt find manifestHashes");
        }
    }

    pub fn get_hash(&self) -> Vec<u8> {

        let data = self.tree.encode();
        let hash = sha2::Sha256::digest(&*data);
        // let hash = <[u8; 32]>::from_hex(hash).unwrap().to_vec();

        hash.to_vec()
    }

    pub fn asn1_name_and_hash(&self) -> Element {
        let name_tlv = TLV::new(22, self.name.as_bytes().to_vec());

        let hash_v = self.get_hash();

        let mut bs = vec![0];
        bs.extend(hash_v);

        let hash_tlv = TLV::new(3, bs);

        let seq = Sequence::new(vec![name_tlv.into(), hash_tlv.into()]);
        seq.into()
    }
}

pub fn new_object(conf: &RepoConfig, typ: &ObjectType) -> CureObject {
    if typ == &ObjectType::MFT {
        let mft = asn1_helper::create_object(&ObjectType::MFT);
        let mft_tree = cure_asn1::tree_parser::parse_tree(&mft, "mft").unwrap();
        let mft_key_dir = conf.base_key_dir_l.clone() + &conf.ca_name + "_mft.der";
        let subject_key_mft = repository_util::read_cert_key(&mft_key_dir);

        let key_uri = conf.base_key_dir_l.clone() + &conf.ca_name + "_cer.der";
        let mft_uri = repository_util::get_filename_crl_mft(&key_uri) + ".mft";
        let parent_key_mft = repository_util::read_cert_key(&key_uri);

        let fmft = CureObject::new(ObjectType::MFT, parent_key_mft, subject_key_mft, mft_tree, mft_uri);

        // fmft.tree.additional_info.insert("havoc".to_string(), vec![5]);
        return fmft;
    } else if typ == &ObjectType::CRL {
        // let crl = fs::read(folder.to_string() + "example.crl").unwrap();
        let crl = asn1_helper::create_object(&ObjectType::CRL);

        let crl_tree = cure_asn1::tree_parser::parse_tree(&crl, "crl").unwrap();
        let crl_key_dir = conf.base_key_dir_l.clone() + &conf.ca_name + "_crl.der";
        let subject_key_crl = repository_util::read_cert_key(&crl_key_dir);

        let key_uri = conf.base_key_dir_l.clone() + &conf.ca_name + "_cer.der";
        let crl_uri = repository_util::get_filename_crl_mft(&key_uri) + ".crl";
        let parent_key_crl = repository_util::read_cert_key(&key_uri);

        let fcrl = CureObject::new(ObjectType::CRL, parent_key_crl, subject_key_crl, crl_tree, crl_uri);
        return fcrl;
    } else if typ == &ObjectType::CERTCA || typ == &ObjectType::CERTROOT{

        let cert;
        if conf.ca_name == "ta" || typ == &ObjectType::CERTROOT{
            cert = asn1_helper::create_object(&ObjectType::CERTROOT);
        } else {
            cert = asn1_helper::create_object(&ObjectType::CERTCA);
        }
        let mut cert_tree = cure_asn1::tree_parser::parse_tree(&cert, "cert").unwrap();

        // Make the certificate cover all IPv4 and all IPv6 addresses
        let pref = vec![0];
        let ips_v4 = vec![(pref, None)];
        let ip_field = asn1_fields::construct_cert_ip_field(Some(ips_v4.clone()), Some(ips_v4));
        cert_tree.set_data_by_label("ipAddrBlocksOctetString", ip_field.clone(), true, true);

        let parent_name = conf.ca_tree.get(&conf.ca_name).unwrap().to_string();
        let parent_key = repository_util::read_cert_key(&(conf.base_key_dir_l.clone() + &parent_name + "_cer.der"));

        let key_uri = conf.base_key_dir_l.clone() + &conf.ca_name + "_cer.der";
        let subject_key_cert = repository_util::read_cert_key(&key_uri);

        let fcer = CureObject::new(
            ObjectType::CERTCA,
            parent_key,
            subject_key_cert,
            cert_tree,
            conf.ca_name.clone() + &".cer".to_string(),
        );

        // fcer.fix_fields(&FixingLevel::Full, &conf, None);

        return fcer;
    } else if typ == &ObjectType::ROA {
        let roa = asn1_helper::create_object(&ObjectType::ROA);
        let roa_tree = cure_asn1::tree_parser::parse_tree(&roa, "roa").unwrap();
        let parent_key_roa = load_random_key(conf).0;
        let subject_key_roa = load_random_key(conf).1;

        let froa = CureObject::new(ObjectType::ROA, parent_key_roa, subject_key_roa, roa_tree, random_fname() + ".roa");
        // froa.fix_fields(&FixingLevel::Full, conf, None);
        return froa;
    } else if typ == &ObjectType::ASA {
        let aspa = asn1_helper::create_object(&ObjectType::ASA);
        let aspa_tree = cure_asn1::tree_parser::parse_tree(&aspa, "asa").unwrap();
        let parent_key_aspa = load_random_key(conf).0;
        let subject_key_aspa = load_random_key(conf).1;

        let faspa = CureObject::new(ObjectType::ASA, parent_key_aspa, subject_key_aspa, aspa_tree, random_fname() + ".asa");
        return faspa;
    } else if typ == &ObjectType::GBR {
        let gbr = asn1_helper::create_object(&ObjectType::GBR);
        let gbr_tree = cure_asn1::tree_parser::parse_tree(&gbr, "gbr").unwrap();
        let parent_key_gbr = load_random_key(conf).0;
        let subject_key_gbr = load_random_key(conf).1;

        let fgbr = CureObject::new(ObjectType::GBR, parent_key_gbr, subject_key_gbr, gbr_tree, random_fname() + ".gbr");
        return fgbr;
    }
    else if typ == &ObjectType::IROA{
        let roa = asn1_helper::create_object(&ObjectType::IROA);
        let suffix = if cfg!(feature="roa_proto"){"iroa"} else if cfg!(feature="no_roa_sig") {"rroa"} else {"sroa"};

        let roa_tree = cure_asn1::tree_parser::parse_tree(&roa, suffix).unwrap();
        let parent_key_roa = load_random_key(conf).0;
        let subject_key_roa = load_random_key(conf).1;

        let name = format!("{}.{}", random_fname(), suffix);
        let mut froa = CureObject::new(ObjectType::IROA, parent_key_roa, subject_key_roa, roa_tree, name);
        froa.tree.fix_sizes(false);
        froa.fix_ifields(conf, None);

        // println!("Created IROA with name {:?}", froa.tree);
        return froa;
    }
    else if typ == &ObjectType::IMFT{
        let mft = asn1_helper::create_object(&ObjectType::IMFT);
        let mft_tree = cure_asn1::tree_parser::parse_tree(&mft, "imft").unwrap();
        let key_uri = conf.base_key_dir_l.clone() + &conf.ca_name + "_cer.der";
        // let mut suffix = if cfg!(feature="roa_proto") {".pmft"} else {".smft"};
        // if cfg!(feature="no_crl")
        //     {
        //     if cfg!(feature="roa_proto"){
        //         suffix = ".imft";
        //     } else {
        //         suffix = ".cmft";
        //     }
        // }
        let suffix = ".imft";

        let mft_uri = format!("{}{}", repository_util::get_filename_crl_mft(&key_uri), suffix);
        let mut fmft = CureObject::new(ObjectType::IMFT, load_random_key(conf).0, load_random_key(conf).1, mft_tree, mft_uri);
        fmft.fix_ifields(conf, None);

        return fmft;

    }

    panic!();
}

#[cfg(feature = "research")]
pub fn convert_proto_to_der(content: &Vec<u8>) -> Vec<u8>{
    cure_asn1::prot::ffi::encode_proto_to_der(content).unwrap_or_default()
}