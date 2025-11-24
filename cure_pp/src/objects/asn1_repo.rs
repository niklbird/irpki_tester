#![allow(unused)] 

use chrono::{DateTime, Utc};
use cure_asn1::{asn1_parser::WriteASN1, rpki::rpki::ObjectType};
use rand::{Rng, RngCore};
use uuid::Uuid;

use super::{
    asn1_certificate, asn1_imft, asn1_iroa,
    asn1_objects::{ObjectConf, ObjectVersion},
};
use crate::repository_util::{self, create_tal, read_cert_key, remove_folder_content};
use cure_asn1::rpki::rrdp::{create_notification, create_snapshot, get_hash};
use std::{collections::HashMap, fs, path::Path};

pub struct TreeNode {
    pub name: String,
    pub children: Vec<TreeNode>,
    pub parent: String,
    pub grandparent: String,
}

pub struct RepoStructure {
    pub root: String,
    pub tree: HashMap<String, Vec<String>>,
}

impl RepoStructure {
    pub fn extract_parent_tree(&self) -> HashMap<String, String> {
        let mut tree = HashMap::new();
        for (parent, children) in &self.tree {
            for child in children {
                tree.insert(child.to_string(), parent.to_string());
            }
        }
        // Root is self-signed -> Its own parent
        tree.insert(self.root.to_string(), self.root.to_string());
        tree
    }
}

pub struct RepoObject {
    pub name: String,
    pub file_uri: String,
    pub rsync_uri: String,
    pub typ: ObjectType,
    pub conf: ObjectConf,
    pub content: Vec<u8>,
}

impl RepoObject {
    pub fn new(name: &str, parent_ca_name: &str, typ: ObjectType, conf: ObjectConf, content: Vec<u8>) -> RepoObject {
        let file_uri = format!("data/my.server.com/repo/{}/{}", parent_ca_name, name);
        let rsync_uri = format!("rsync://my.server.com/data/my.server.com/repo/{}/{}", parent_ca_name, name);
        RepoObject {
            name: name.to_string(),
            file_uri,
            rsync_uri,
            typ,
            conf,
            content,
        }
    }

    pub fn get_mft_fingerprint(&self) -> (String, Vec<u8>) {
        (self.name.clone(), self.content.clone())
    }
}

pub struct CertificateAuthority {
    pub name: String,
    pub parent_name: String,
    pub children: Vec<CertificateAuthority>,
    pub mft: RepoObject,
    pub crl: RepoObject,
    pub cert: RepoObject,
    pub payloads: Vec<RepoObject>,
}

impl CertificateAuthority {
    pub fn get_all_files(&self) -> Vec<(String, String, Vec<u8>)> {
        let mut files = vec![];
        files.push((self.mft.file_uri.clone(), self.mft.rsync_uri.clone(), self.mft.content.clone()));
        files.push((self.crl.file_uri.clone(), self.crl.rsync_uri.clone(), self.crl.content.clone()));
        files.push((self.cert.file_uri.clone(), self.cert.rsync_uri.clone(), self.cert.content.clone()));

        for payload in &self.payloads {
            files.push((payload.file_uri.clone(), payload.rsync_uri.clone(), payload.content.clone()));
        }

        for child in &self.children {
            files.extend(child.get_all_files());
        }

        files
    }

    pub fn add_roa(&mut self, roa_string: &str) {
        let impr = ObjectVersion::Novel;
        let roa = create_roa(&self.name, &self.parent_name, roa_string, impr.clone());
        self.payloads.push(roa);

        let new_mft = create_mft(&self.name, &self.parent_name, &ObjectType::MFT, 1, &self.get_all_fingerprints(), impr);
        self.mft = new_mft;
    }

    pub fn get_all_fingerprints(&self) -> Vec<(String, Vec<u8>)> {
        let mut fingerprints = vec![];
        fingerprints.push(self.crl.get_mft_fingerprint());
        for payload in &self.payloads {
            fingerprints.push(payload.get_mft_fingerprint());
        }

        for child in &self.children {
            fingerprints.push(child.cert.get_mft_fingerprint());
        }

        fingerprints
    }
}

pub fn base_conf(name: &str, parent_name: &str, grandparent_name: &str, typ: &ObjectType) -> ObjectConf {
    let key_uri;
    let parent_key_uri;
    let base_key_uri = "working/key_cache/";
    let conf = repository_util::create_default_config();

    if typ == &ObjectType::CERTCA {
        key_uri = format!("{}{}.der", base_key_uri, name);
        parent_key_uri = format!("{}{}.der", base_key_uri, parent_name);
    } else if typ == &ObjectType::CRL {
        key_uri = format!("{}{}_crl.der", base_key_uri, parent_name);
        parent_key_uri = format!("{}{}.der", base_key_uri, parent_name);
    } else if typ == &ObjectType::MFT {
        key_uri = format!("{}{}_mft.der", base_key_uri, parent_name);
        parent_key_uri = format!("{}{}.der", base_key_uri, parent_name);
    } else {
        // Random int between 0 and 10000
        let random_int = rand::random::<u64>() % 10000;
        key_uri = format!("{}{}_pl.der", base_key_uri,random_int);
        parent_key_uri = format!("{}{}.der", base_key_uri, parent_name);
    }

    let subject_name = read_cert_key(&key_uri).get_key_id();

    let issuer_name = read_cert_key(&parent_key_uri).get_key_id();

    let subject_fingerprint = read_cert_key(&key_uri).get_key_id();
    let issuer_uri = format!(
        "rsync://my.server.com/{}/{}/{}.cer",
        conf.base_repo_dir, grandparent_name, parent_name
    );
    let repo_uri = format!("rsync://my.server.com/{}/{}/", conf.base_repo_dir, name);
    let mft_uri = format!("rsync://my.server.com/{}/{}/{}.mft", conf.base_repo_dir, name, subject_fingerprint);
    let notification_uri = format!("https://my.server.com/{}", &conf.base_rrdp_dir);

    let crl_distr_point;
    if typ == &ObjectType::CERTCA {
        crl_distr_point = format!("rsync://my.server.com/{}/{}/{}.crl", conf.base_repo_dir, parent_name, issuer_name);
    } else {
        crl_distr_point = format!("rsync://my.server.com/data/my.server.com/repo/{}/{}.crl", name, issuer_name);
    }

    let random_int: u64 = rand::random::<u32>().into();
    ObjectConf {
        issuer_name,
        subject_name,
        validity: (Utc::now(), Utc::now() + chrono::Duration::hours(72)),
        parent_key_uri,
        subject_key_uri: key_uri,
        issuer_uri,
        repo_uri,
        mft_uri,
        signed_object_uri: "".to_string(),
        notification_uri,
        crl_distr_point,
        is_root: false,
        typ: *typ,
        number: random_int,
    }
}

pub fn cert_conf_from_name(name: &str, parent_name: &str, grandparent_name: &str, is_root: bool, typ: &ObjectType) -> ObjectConf {
    let mut conf = base_conf(name, parent_name, grandparent_name, typ);
    conf.is_root = is_root;
    conf.typ = ObjectType::CERTCA;
    conf
}

pub fn mft_conf_from_name(parent_name: &str, grandparent_name: &str, typ: &ObjectType) -> ObjectConf {
    let mut conf = base_conf(parent_name, parent_name, grandparent_name, typ);

    let signed_object_uri = format!(
        "rsync://my.server.com/data/my.server.com/repo/{}/{}.mft",
        parent_name, &conf.issuer_name
    );
    conf.signed_object_uri = signed_object_uri;
    conf.typ = ObjectType::MFT;
    conf
}

pub fn crl_conf_from_name(parent_name: &str, grandparent_name: &str, typ: &ObjectType) -> ObjectConf {
    let conf = base_conf(parent_name, parent_name, grandparent_name, typ);
    conf
}

pub fn roa_conf_from_name(parent_name: &str, grandparent_name: &str, roa_string: &str, typ: &ObjectType, impr: &ObjectVersion) -> ObjectConf {
    let mut conf = base_conf(parent_name, parent_name, grandparent_name, typ);

    conf.signed_object_uri = format!(
        "rsync://my.server.com/data/my.server.com/repo/{}/{}",
        parent_name,
        &asn1_iroa::roa_name(roa_string, impr)
    );
    conf
}

pub fn create_ca_cert(name: &str, parent_name: &str, grandparent_name: &str, is_root: bool, typ: &ObjectType) -> RepoObject {
    let cert_conf = cert_conf_from_name(name, parent_name, grandparent_name, is_root, typ);
    let obj = asn1_certificate::create_certificate(&cert_conf);

    let name = format!("{}.cer", name);
    let cert = RepoObject::new(&name, parent_name, *typ, cert_conf, obj.encode());
    cert
}

pub fn create_mft(
    parent_name: &str,
    grandparent_name: &str,
    typ: &ObjectType,
    mft_number: u64,
    hashlist: &Vec<(String, Vec<u8>)>,
    impr: ObjectVersion,
) -> RepoObject {
    let mft_conf = mft_conf_from_name(parent_name, grandparent_name, typ);
    let obj = asn1_imft::create_manifest(mft_number, hashlist, &mft_conf);

    let name = format!("{}.mft", mft_conf.issuer_name);

    let mft = RepoObject::new(&name, parent_name, *typ, mft_conf, obj.encode());

    mft
}

pub fn create_crl(parent_name: &str, grandparent_name: &str, typ: &ObjectType, revocation_list: &Vec<(u64, DateTime<Utc>)>) -> RepoObject {
    let crl_conf = crl_conf_from_name(parent_name, grandparent_name, typ);
    let obj = asn1_certificate::create_crl(revocation_list, &crl_conf);

    let name = format!("{}.crl", crl_conf.issuer_name);

    let crl = RepoObject::new(&name, parent_name, *typ, crl_conf, obj.encode());

    crl
}

pub fn create_roa(parent_name: &str, grandparent_name: &str, roa_string: &str, impr: ObjectVersion) -> RepoObject {
    let roa_conf = roa_conf_from_name(parent_name, grandparent_name, roa_string, &ObjectType::ROA, &impr);
    let obj = asn1_iroa::create_roa(roa_string, &roa_conf, impr.clone());

    let name = asn1_iroa::roa_name(roa_string, &impr);

    let roa = RepoObject::new(&name, parent_name, ObjectType::ROA, roa_conf, obj.encode());

    roa
}

pub fn ca_from_name(
    name: &str,
    parent_name: &str,
    grandparent_name: &str,
    is_root: bool,
    child_fingerprints: Vec<(String, Vec<u8>)>,
    impr: ObjectVersion,
) -> CertificateAuthority {
    let cert = create_ca_cert(name, parent_name, grandparent_name, is_root, &ObjectType::CERTCA);
    let crl = create_crl(name, parent_name, &ObjectType::CRL, &vec![]);

    let crl_fingerprint = (crl.name.clone(), crl.content.clone());
    let mut fingerprints = vec![crl_fingerprint];
    fingerprints.extend(child_fingerprints);
    let mft = create_mft(name, parent_name, &ObjectType::MFT, 1, &fingerprints, impr);

    CertificateAuthority {
        name: name.to_string(),
        parent_name: parent_name.to_string(),
        children: vec![],
        mft,
        crl,
        cert,
        payloads: vec![],
    }
}

pub fn create_ca_rec(name: &str, structure: &RepoStructure, parent_tree: &HashMap<String, String>) -> CertificateAuthority {
    let parent_name = parent_tree.get(name).unwrap();

    let mut children = vec![];
    let mut child_fingerprints = vec![];

    if structure.tree.contains_key(name) {
        for child_name in structure.tree.get(name).unwrap() {
            let child_ca = create_ca_rec(child_name, structure, parent_tree);
            child_fingerprints.push((format!("{}.cer", child_name), child_ca.cert.content.clone()));
            children.push(child_ca);
        }
    }

    let impr = ObjectVersion::Novel;

    let mut ca = ca_from_name(
        name,
        parent_name,
        parent_tree.get(parent_name).unwrap(),
        name == structure.root,
        child_fingerprints,
        impr,
    );

    ca.children = children;
    ca
}

pub fn create_repository_from_conf(conf: &RepoStructure) -> CertificateAuthority {
    let parent_tree = conf.extract_parent_tree();
    let root_ca = create_ca_rec(&conf.root, conf, &parent_tree);
    root_ca
}

pub fn create_default_rep_conf() -> RepoStructure {
    let mut tree = HashMap::new();
    tree.insert("ta".to_string(), vec!["newca".to_string()]);
    let conf = RepoStructure {
        root: "ta".to_string(),
        tree,
    };
    conf
}

pub fn write_default_repo() {
    let conf = create_default_rep_conf();
    let root = create_repository_from_conf(&conf);
    write_to_disc(root);
}

pub fn create_default_repository() -> CertificateAuthority {
    let conf = create_default_rep_conf();
    create_repository_from_conf(&conf)
}


pub fn generate_random_bytes() -> String {
        let mut bytes = [0; 8];
        rsa::rand_core::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }
    

pub fn write_rrdp(files: Vec<(String, Vec<u8>)>) {
    remove_folder_content("data/my.server.com/rrdp/");

    fs::create_dir_all("data/my.server.com/rrdp").unwrap();

    let serial = 1;

    let mut rng = rand::thread_rng();
    let random_int: u128 = rng.gen_range(0..u128::MAX);
    let session_id = Uuid::from_u128(random_int).to_string();
    let random = generate_random_bytes();

    let base_uri = "https://my.server.com/data/my.server.com/rrdp/";
    let base_uri_l = "data/my.server.com/rrdp/";
    let snapshot_uri = format!("{}{}/{}/{}/snapshot.xml", &base_uri, &session_id, random, serial.to_string(),);
    let notification_uri_l = format!("{}notification.xml", &base_uri_l);
    let snapshot_uri_folder = format!("{}{}/{}/{}/", base_uri_l, session_id.to_string(), random, serial.to_string(),);

    fs::create_dir_all(&snapshot_uri_folder).unwrap();

    let snapshot_uri_l = format!("{}snapshot.xml", snapshot_uri_folder);

    let snap = create_snapshot(serial, &session_id, files).unwrap();
    let snap_hash = get_hash(&snap);
    let notif = create_notification(serial, &session_id, (&snapshot_uri, &snap_hash), None).unwrap();

    fs::write(snapshot_uri_l, snap).unwrap();

    println!("Writing notification to: {}", notification_uri_l);
    fs::write(notification_uri_l, notif).unwrap();
}

// pub fn create_tal_with_key(keydata: &str) {
//     let httpsuri = "https://my.server.com/data/repo/ta/ta.cer";
//     let rsyncuri = "rsync://my.server.com/data/repo/ta/ta.cer";

//     let tal_uri = "data/my.server.com/tal/ta.tal";

//     let mut final_string: String = "".to_owned();
//     final_string.push_str(httpsuri);
//     final_string.push_str("\n");
//     final_string.push_str(rsyncuri);
//     final_string.push_str("\n\n");
//     final_string.push_str(keydata);
//     final_string.push_str("\n");

//     let parent = Path::new(tal_uri).parent().unwrap();
//     fs::create_dir_all(parent).unwrap();
//     fs::write(tal_uri, &final_string).unwrap();
// }

pub fn write_to_disc(root: CertificateAuthority) {
    let parent_uri = root.cert.conf.parent_key_uri.clone();
    let spki = asn1_certificate::create_subject_public_key_info(&parent_uri);
    let parent_key = base64::encode(&spki.encode());

    let repo_conf = repository_util::create_default_config();
    create_tal(&repo_conf, &parent_key);

    let files = root.get_all_files();
    for (file_uri, _, content) in &files {
        let parent = Path::new(file_uri).parent().unwrap();
        fs::create_dir_all(parent).unwrap_or_default();
        fs::write(file_uri, content).unwrap();
    }
    let new_vec: Vec<(String, Vec<u8>)> = files.into_iter().map(|(_, first, last)| (first, last)).collect();
    write_rrdp(new_vec);
}
