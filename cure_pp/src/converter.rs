
use std::{collections::HashMap, fs, path::Path};


use cure_asn1::{prot::parsing::{proto_from_mft, proto_from_roa, CertificateAuthorityDelta, DeltaFile, ObjectEntry, UpdatedObject}, rpki::ObjectType, rrdp::{RRDPEntry, XMLSnapshot}, rrdp_xml, tree_parser::Tree};
use rand::{thread_rng, Rng};

use crate::{cure_object::{new_object, CureObject}, cure_repo::{new_repo, CureRepository}, objects::{asn1_fields, asn1_helper}, repository_util::create_tal};
use prost::Message;
use super::repository_util::{self, RepoConfig};
use rayon::{prelude::*, ThreadPoolBuilder};
use hex::FromHex;
 
fn uri_to_local_https(uri: &str) -> String{
    let rrdp_uri = uri 
        .replace("_", "__")
        .replace("/", "_")
        .replace(":", "_") // Was : => =
        .replace("https___", "")
        .replace("rsync___", "");

    rrdp_uri 
} 


/// Map Notification file to Snapshotfile
pub fn notify_snapshot_mapping(uri: &str) -> HashMap<String, String>{
    let mut map = HashMap::new();
    for file in fs::read_dir(uri).unwrap() {
        let f = file.unwrap();
        let p = f.path();
        let p  = p.to_str().unwrap();

        let f = f.file_name();
        let f = f.to_str().unwrap();
        if f.ends_with(".xml") {
            let content = fs::read_to_string(p).unwrap();
            if !content.contains("notification"){
                continue;
            }
            let notification_option = cure_asn1::rrdp::parse_notification(&content);
            if let Some(notification) = notification_option {
                let snapshot = uri_to_local_https(&notification.snapshot_uri.unwrap().uri);
                let own_uri_s = f.split("_").collect::<Vec<&str>>();
                let own_uri = own_uri_s[..own_uri_s.len() - 1].join("_");
                
                map.insert(snapshot, own_uri);
            }   
        }
    }
    map
}

pub fn read_folder(uri: &str, proto: bool){
    // if proto{
    //     crate::set_no_crl(true);
    //     crate::set_no_ee(true);
    //     crate::set_no_roa_sig(true);
    //     crate::set_roa_proto(true);
    //     crate::set_rrdp_proto(true);
    // }
    // TODO
    let snapshot_mapping = notify_snapshot_mapping(uri);

    let conf = &repository_util::RepoConfig::default();
    repository_util::clear_repo(conf);

    let entries: Vec<_> = fs::read_dir(uri)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();

    let conf = &repository_util::RepoConfig::default();
    repository_util::clear_repo(conf);

    let pool = ThreadPoolBuilder::new()
    .num_threads(5) // Limit to 4 threads
    .build()
    .unwrap();

    pool.install(|| 
    entries
        .into_par_iter()
        .filter(|f| {
            f.path()
                .to_str()
                .map(|p| p.ends_with(".xml"))
                .unwrap_or(false)
        })
        .for_each(|f| {
            let p = f.path();
            let p = p.to_str().unwrap();
            if p.ends_with(".xml") {
                let content = fs::read_to_string(p).unwrap();
                let snapshot_option = cure_asn1::rrdp::parse_snapshot(&content);
                if let Some(snapshot) = snapshot_option {
                    handle_snapshot(snapshot, f.file_name().to_str().unwrap(), &snapshot_mapping);
                    println!("Finished handling snapshot {}", p);
                }
        }}));
    
        println!("Creating bootstrap");
    create_bootstrap_repo(uri);
}



/// Create a repository that combines all root CA certificates -> This allows us to request all repos through a single TAL
pub fn create_bootstrap_repo(uri: &str){
    let conf = repository_util::RepoConfig::default();
    let mut base_repo =  new_repo(&conf, &cure_asn1::rpki::ObjectType::UNKNOWN, true);

    if cfg!(feature="no_crl"){
        let new_name = base_repo.manifest.name.split(".").collect::<Vec<&str>>()[0].to_string() + ".imft";
        base_repo.manifest.name = new_name;
    }

    let mut counter = 0;
    for file in fs::read_dir(uri).unwrap() {
        let file = file.unwrap();
        let f = file.path();
        let f = f.to_str().unwrap();

        if f.ends_with(".cer") {
            let data = fs::read(f).unwrap();

            let parsed = cure_asn1::rpki::parse_rpki_object(&data, &ObjectType::CERTCA).unwrap();

            let subj = parsed.get_cert_subjectname().unwrap();

            let sub_key = repository_util::read_cert_key(&format!("working/key_cache/{}.der", subj));
            let iss_key = base_repo.certificate.child_key.clone();

            let notification_uri = parsed.get_cert_notification_uri().unwrap();
            let loc = uri_to_local_https(&notification_uri);
            let c = loc.split("_").collect::<Vec<&str>>();

            let new_uri = c[..c.len() - 1].join("_"); // Remove "Notification.xml"

            let not_ext = match cfg!(feature="rrdp_proto"){
                true => ".bin",
                false => ".xml",
            };
            let rrdp = format!("https://{}/{}{}/notification{}", &base_repo.conf.domain, &base_repo.conf.base_rrdp_dir, &new_uri, not_ext);

            let mut new_cert = new_object(&conf, &ObjectType::CERTCA);

            let mft_ext = match cfg!(feature="no_crl"){
                true => ".imft",
                false => ".mft"
            };

            let mft_uri = format!("rsync://{}/{}{}/{}{}", base_repo.conf.domain, base_repo.conf.base_repo_dir, subj, subj, mft_ext);
            let repo_uri = format!("rsync://{}/{}{}/", base_repo.conf.domain, base_repo.conf.base_repo_dir, subj);

            new_cert.name = format!("{}.cer", &counter.to_string());
            new_cert.parent_key = iss_key;
            new_cert.child_key = sub_key;
            new_cert.tree.set_data_by_label("rpkiNotifyURI", rrdp.as_bytes().to_vec(), true, true);

            new_cert.tree.set_data_by_label("rpkiManifestURI", mft_uri.as_bytes().to_vec(), true, true);
            new_cert.tree.set_data_by_label("caRepositoryURI", repo_uri.as_bytes().to_vec(), true, true);


            base_repo.payloads.push(new_cert);
            counter += 1;
        }
    }

    base_repo.fix_all_objects(true);

    create_tal(&base_repo.conf, &base_repo.certificate.get_ski_b64());


    let full_serialized = base_repo.serialize(None, false, true, cfg!(feature="rrdp_proto"));
    let conf = repository_util::RepoConfig::default();

    let objs;
    if cfg!(feature="rrdp_proto"){
        objs = CureRepository::create_snap_notification_proto_objs(&full_serialized, &conf);
    }
    else{
        objs =  CureRepository::create_shapshot_notification_objs(&full_serialized, &conf);
    }
    
    let cert_data = base_repo.certificate.tree.encode();
    let cert_uri = format!("{}{}/{}", &base_repo.conf.base_repo_dir_l, &base_repo.conf.ca_name, &base_repo.certificate.name);

    fs::write(cert_uri, cert_data).unwrap(); // Need to write this cert to disc as it is the root certificate -> Its directly downloaded by RPs outside Snapshot
    fs::create_dir_all(Path::new(&objs[0].0).parent().unwrap()).unwrap();

    for obj in objs{
        fs::write(obj.0, obj.1).unwrap();
    }


}

pub fn extract_ca_tree(uri: &str){
    let mut map = HashMap::new();

    for file in fs::read_dir(uri).unwrap() {
        let f = file.unwrap().path();
        let f = f.to_str().unwrap();
    
        if f.ends_with(".xml") && f.contains("rrdp.ripe.net_172322cf-c642-4e6f-806c-bd2375d8001a_106554_snapshot-f7e99c5ab2553c9e5ed135dc6a2996618009362f29bd3a6f43585e700c8c167a.xml") {
            let content = fs::read_to_string(f).unwrap();
            let snapshot_option = cure_asn1::rrdp::parse_snapshot(&content);

            if let Some(snapshot) = snapshot_option {
                for entry in snapshot.entries{
                    if entry.uri.ends_with(".cer"){
                        let parsed = cure_asn1::rpki::parse_rpki_object(&entry.data, &ObjectType::CERTCA).unwrap();

                        let subject = parsed.get_cert_subjectname().unwrap();
                        let issuer = parsed.get_cert_issuername().unwrap();

                        map.entry(issuer).or_insert(vec![]).push(subject);

                    }
                }
            }
        }
    }

    let mut reverse_map = HashMap::new();

    for (key, value) in map.iter() {
        reverse_map.entry(key.clone()).or_insert(vec![]);
        for val in value{

            if val == key{
                continue;
            }

            reverse_map.entry(val.clone()).or_insert(vec![]).push(key.clone());
        }
    }

    for (key, value) in reverse_map.iter() {

        if value.is_empty(){
            println!("Key withoutparent  {}", key);
        }

    }


}




fn handle_snapshot(snapshot: XMLSnapshot, snapshot_name: &str, snap_map: &HashMap<String, String>){
    let default_conf = RepoConfig::default();
    let mut manifest = vec![];
    let mut all_entries = HashMap::new();
    for entr in snapshot.entries{
        if entr.uri.ends_with(".mft") {
            manifest.push(entr.clone());
        }
        else{
            all_entries.insert(entr.uri.clone(), entr.clone());
        }
    }
    
    let mut all_repos = vec![];
    for mft in manifest{
        let mut parsed_mft = cure_asn1::rpki::parse_rpki_object(&mft.data, &ObjectType::MFT).unwrap();

        let s: Vec<&str> = mft.uri.split('/').collect();
        let base_uri = s[..s.len()-1].join("/");

        let mut repo = CureRepository::_default();
        repo.conf.ca_name = parsed_mft.get_cert_issuername().unwrap();
        repo.conf.ca_tree.insert(repo.conf.ca_name.clone(), repo.conf.ca_name.clone()); //= parsed_mft.get_cert_issuername().unwrap();
        
        let name = snap_map.get(snapshot_name);
        if name.is_none(){
            println!("Was none {}", snapshot_name);
            println!("snap_map  {:?}", snap_map);
            continue;
        }
        repo.conf.base_rrdp_dir = format!("{}{}/", &repo.conf.base_rrdp_dir, snap_map.get(snapshot_name).unwrap());
        repo.conf.base_rrdp_dir_l = format!("{}{}/", &repo.conf.base_rrdp_dir_l, snap_map.get(snapshot_name).unwrap());
    
        for entry in parsed_mft.get_mft_entries(){
            let file_uri = base_uri.clone() + "/" + &entry.0;

            if all_entries.contains_key(&file_uri){
                let entr = all_entries.get(&file_uri).unwrap();
                let path = Path::new(&file_uri);
                let typ  = ObjectType::from_string(&path.extension().unwrap().to_str().unwrap().to_string());
                let parsed = cure_asn1::rpki::parse_rpki_object(&entr.data, &typ);
                if parsed.is_none(){
                    println!("Was none in snapshot {} - {}", snapshot_name, &file_uri)
                }

                let mut parsed = parsed.unwrap();
                let issuer = parsed.get_cert_issuername().unwrap_or_default();
                let child = parsed.get_cert_subjectname().unwrap_or_default();

                if parsed.get_cert_notification_uri().is_some(){
                    // Convert the current notifcation URI to a URI that points to our own domain.
                    let notification_uri = parsed.get_cert_notification_uri().unwrap();
                    let notification_parsed = uri_to_local_https(&notification_uri);
                    let own_uri_s = notification_parsed.split("_").collect::<Vec<&str>>();
                    let new_uri = own_uri_s[..own_uri_s.len() - 1].join("_"); // Remove the "Notification.xml" at the end
    
                    let not_ext = match cfg!(feature="rrdp_proto"){
                        true => ".bin",
                        false => ".xml",
                    };
        
                    let rrdp = format!("https://{}/{}{}/notification{}", &repo.conf.domain, default_conf.base_rrdp_dir, new_uri, not_ext);
                    parsed.set_notification_uri(&rrdp);
                    

                    let mft_ext = match cfg!(feature="no_crl"){
                        true => ".imft",
                        false => ".mft"
                    };
        
                    let mft_uri = format!("rsync://{}/{}{}/{}{}", repo.conf.domain, repo.conf.base_repo_dir, child, child, mft_ext);
                    parsed.set_manifest_uri(&mft_uri);

                    let repo_uri = format!("rsync://{}/{}{}/", repo.conf.domain, repo.conf.base_repo_dir, child);
                    parsed.set_cert_repo_uri(&repo_uri);

                }

                let crl_uri = format!("rsync://{}/{}{}/{}.crl", repo.conf.domain, repo.conf.base_repo_dir, issuer, issuer);
                parsed.set_crl_uri(&crl_uri);

                let fname;
                if typ == ObjectType::CRL{
                    fname = format!("{}.crl", issuer);
                }
                else{
                    let n = Path::new(&file_uri).file_name().unwrap().to_str().unwrap().to_string();
                    if cfg!(feature="no_roa_sig") && typ == ObjectType::ROA{
                        fname =  n.split(".").collect::<Vec<&str>>()[0].to_string() + ".iroa";
                    }
                    else{
                        fname = n.clone();
                    }
                    if n == ""{
                        println!("Filename was empty {}", file_uri);
                    }
                }
                 

                let cure_obj = signed_cure_object_from_tree(&parsed.content, &child, &issuer, &fname, &typ);
                
                match typ{
                    ObjectType::CRL => repo.crl = cure_obj,
                    _=> repo.payloads.push(cure_obj), // Certificates are treated like normal payloads
                }
            }
        }
        // In the end, also add manifest
        let issuer = parsed_mft.get_cert_issuername().unwrap_or_default();
        let mft_ext = match cfg!(feature="no_crl"){
            true => ".imft",
            false => ".mft"
        };

        let mft_uri = format!("{}{}", issuer, mft_ext);

        let crl_uri = format!("rsync://{}/{}{}/{}.crl", repo.conf.domain, repo.conf.base_repo_dir, issuer, issuer);

        let child = parsed_mft.get_cert_subjectname().unwrap_or_default();
        parsed_mft.set_crl_uri(&crl_uri);

        let cure_mft = signed_cure_object_from_tree(&parsed_mft.content, &child, &issuer, &mft_uri, &ObjectType::MFT);

        repo.manifest = cure_mft.clone();
        repo.certificate = cure_mft; // Certificate is not used but since its not optional, just put a random object in there
        
        
        if repo.crl.name == ""{
            continue; // Skip if no CRL
        }
        repo.fix_all_objects(true);


        all_repos.push(repo);
    }

    let base_uri = snap_map.get(snapshot_name).unwrap();
    let objs = snapshot_from_repos(all_repos, base_uri);

    fs::create_dir_all(Path::new(&objs[0].0).parent().unwrap()).unwrap();
    for obj in objs{
        fs::write(obj.0, obj.1).unwrap();
    }
}


fn snapshot_from_repos(repos: Vec<CureRepository>, base_folder: &str) -> Vec<(String, Vec<u8>)>{
    let mut full_serialized = vec![];
    for repo in repos{
        full_serialized.extend(repo.serialize(None, false, false, cfg!(feature="rrdp_proto")));
    }

    let mut conf = repository_util::RepoConfig::default();
    conf.base_rrdp_dir = format!("{}{}/", &conf.base_rrdp_dir, base_folder);
    conf.base_rrdp_dir_l = format!("{}{}/", &conf.base_rrdp_dir_l, base_folder);

    if cfg!(feature="rrdp_proto"){
        CureRepository::create_snap_notification_proto_objs(&full_serialized, &conf)
    }
    else{
        CureRepository::create_shapshot_notification_objs(&full_serialized, &conf)
    }
}


pub fn signed_cure_object_from_tree(tree: &Tree, name: &str, parent_name: &str, filename: &str,  typ: &ObjectType) -> CureObject{
    let mut conf = repository_util::RepoConfig::default();

    conf.ca_name = name.to_string();

    conf.ca_tree.insert(name.to_string(), parent_name.to_string());


    let base_uri = "working/key_cache/".to_string();

    let parent_key_uri = format!("{}{}.der", &base_uri, parent_name);

    let random_number = thread_rng().gen_range(0..10000);
    let child_key_uri = match typ{
        ObjectType::CERTCA  | ObjectType::CERTROOT => format!("{}{}.der", &base_uri, name),
        _ => format!("{}{}_roa", base_uri, &random_number.to_string())
    };

    let parent_key = repository_util::read_cert_key(&parent_key_uri);
    let child_key = repository_util::read_cert_key(&child_key_uri);

    let obj = CureObject::new(typ.clone(), parent_key, child_key, tree.clone(), filename.to_string());

    obj
}

fn split_uri(uri: &str) -> (String, String){
    let s = uri.split("/").collect::<Vec<&str>>();
    let name = s.last().unwrap();
    let base_uri = s[..s.len() - 1].join("/");

    (name.to_string(), base_uri.to_string())
}


pub struct ResultCounts{
    pub mapping: HashMap<String, usize>,
}

impl ResultCounts{
    pub fn new() -> Self{
        let mut mapping = HashMap::new();
        mapping.insert("roa".to_string(), 0);
        mapping.insert("cer".to_string(), 0);
        mapping.insert("mft".to_string(), 0);
        mapping.insert("crl".to_string(), 0);
        ResultCounts{
            mapping,
        }
    }

    pub fn add(&mut self, key: String, value: usize){
        let entry = self.mapping.entry(key).or_insert(0);
        *entry += value;
    }

    pub fn get(&self, key: &str) -> usize{
        *self.mapping.get(key).unwrap_or(&0)
    }

    pub fn unify(&mut self, other: &ResultCounts){
        for (key, value) in &other.mapping{
            let entry = self.mapping.entry(key.clone()).or_insert(0);
            *entry += value;
        }
    }
}


/// Converts publish / modifies entries to the Protobuf structure
fn delta_entry_from_entries(repo_uri: String, entries: (Vec<ObjectEntry>, Vec<UpdatedObject>)) -> CertificateAuthorityDelta{
    CertificateAuthorityDelta{
        repo_uri,
        added_objects: entries.0,
        updated_objects: entries.1
    }
}

pub fn convert_delta(xml: &str) -> (Vec<u8>, ResultCounts){
    let mut all_counts = ResultCounts::new();
    let delta = rrdp_xml::parse_rrdp_delta(xml);
    if delta.is_err(){
        println!("{} - Failed to parse delta", xml);
    }

    let delta = delta.unwrap();

    let mut all_names = vec![];
    let mut cert_count = 0;
    let mut cas: HashMap<String, (Vec<RRDPEntry>, Vec<RRDPEntry>)> = HashMap::new();

    // First: Create a map that sorts by CA
    for val in delta.modifies{
        let (_, base_uri) = split_uri(&val.uri);

        cas.entry(base_uri).or_insert((vec![], vec![])).1.push(val);
    }

    for val in delta.publishes{
        let (_, base_uri) = split_uri(&val.uri);

        cas.entry(base_uri).or_insert((vec![], vec![])).0.push(val);
    }

    // Second: Convert to Protobuf
    let mut proto_cas: HashMap<String, (Vec<ObjectEntry>, Vec<UpdatedObject>)> = HashMap::new();

    // Filter for MFT/CRL
    for ca in cas{
        let mut mft = None;
        let mut crl = None;

        for el in ca.1.0.iter().chain(ca.1.1.iter()){
            let (name, _) = split_uri(&el.uri);
            let ext = name.split(".").last().unwrap_or("");
            all_counts.mapping.get_mut(ext).map(|count| *count += 1);

            all_names.push(name.clone());

            if el.uri.ends_with("mft") || el.uri.ends_with("crl"){
                if el.uri.ends_with("crl"){
                    crl = Some(el.clone());
                }
                else{
                    mft = Some(el.clone());
                }
            }


            else if el.uri.ends_with("roa") || el.uri.ends_with("cer"){
                let data = if el.uri.ends_with("roa"){
                    let roa = cure_asn1::rpki::parse_rpki_object(&el.data, &ObjectType::UNKNOWN).unwrap();
                    let proto = proto_from_roa(&roa.content);
                    proto
                }
                else{
                    cert_count += 1;

                    el.data.clone()
                };

                if el.hash.is_some(){
                    let val = UpdatedObject{
                        new_content: data,
                        old_hash: <[u8; 32]>::from_hex(el.hash.clone().unwrap()).unwrap().to_vec(),
                        name
                    };

                    proto_cas.entry(ca.0.clone()).or_insert((vec![], vec![])).1.push(val);

                }
                else{
                    let val =  ObjectEntry{
                        content: data,
                        name
                    };

                    proto_cas.entry(ca.0.clone()).or_insert((vec![], vec![])).0.push(val);
                }

            }

            else{
                println!("WARNING: Unknown object type in delta: {} - {}", &el.uri, &name);
            }

        }


        if mft.is_none() || crl.is_none(){
            println!("ERROR CA {} has no MFT or CRL", &ca.0);
            continue; // Skip if no MFT or CRL
            
        }

        let mft = mft.unwrap();
        let crl = crl.unwrap();

        let pared_mft = cure_asn1::rpki::parse_rpki_object(&mft.data, &ObjectType::UNKNOWN).unwrap();
        let new_crl = cure_asn1::rpki::parse_rpki_object(&crl.data, &ObjectType::UNKNOWN).unwrap();

        let new_mft = proto_from_mft(&pared_mft.content, &new_crl.content);
        let data = new_mft.encode_to_vec();

        if mft.hash.is_none(){
            let mft_entry = ObjectEntry{
                content: data,
                name: split_uri(&mft.uri).0,
            };

            proto_cas.entry(ca.0).or_insert((vec![], vec![])).0.push(mft_entry);

        }
        else{
            // println!("Manifest safe: {}", data.len() as f32 / (mft.data.len() + crl.data.len()) as f32);

            let mft_entry = UpdatedObject{
                new_content: data,
                name: split_uri(&mft.uri).0,
                old_hash: <[u8; 32]>::from_hex(mft.hash.unwrap()).unwrap().to_vec(),
            };

            proto_cas.entry(ca.0).or_insert((vec![], vec![])).1.push(mft_entry);

        }

        
    }

    let mut cas_delta = vec![];
    for (val, v) in proto_cas{
        cas_delta.push(delta_entry_from_entries(val, v));
    }

    let proto_delta = DeltaFile{
        version: "1".to_string(),
        serial: delta.serial.into(),
        session_id: delta.session_id,
        cas: cas_delta, 
    };


    let mut buffer = Vec::new();
    proto_delta.encode(&mut buffer).expect("Failed to encode");


    (buffer, all_counts)
}


// Convert all deltas in folder to Protobuf
pub fn convert_delta_folder(folder_uri: &str){

    // Get content of all delta files in the folder
    let deltas = fs::read_dir(folder_uri)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.path()
                .to_str()
                .map(|s| s.to_lowercase().contains("delta"))
                .unwrap_or(false)
    }).map(|a| fs::read_to_string(a.path()).unwrap()).collect::<Vec<String>>();

    let total_size = deltas.iter().map(|s| s.len()).sum::<usize>();

    let vals: Vec<(Vec<u8>, ResultCounts)> = deltas.par_iter().map(|xml| {
        convert_delta(&xml)
    }).collect();

    let new_total_size = vals.iter().map(|s| s.0.len()).sum::<usize>();
    let mut all_counts = ResultCounts::new();
    for val in vals{
        all_counts.unify(&val.1);
    }

    println!("Total size of deltas: {} - Converted to Protobuf: {} - Ratio: {}", total_size, new_total_size, (new_total_size as f64 / total_size as f64) * 100.0);
    println!("Total {:?}", all_counts.mapping);
        println!("Total {:?}", deltas.len());


}
