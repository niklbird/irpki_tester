use rand::thread_rng;
use rand::Rng;
use rand_distr::Alphanumeric;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::SigningKey;

use serde::Deserialize;
use serde::Serialize;
//use sha2::Digest;
//use sha2::Sha256;
use std::error::Error;
use std::path::Path;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::RandomizedSigner;
use rsa::signature::SignatureEncoding;

use hex::FromHex;
// use openssl::hash::MessageDigest;
// use openssl::pkey::PKey;


use rsa::RsaPrivateKey;

use std::{fs, str};

// use openssl::rsa::Rsa;

extern crate base64; 

// use openssl::pkey::Private;

use std::collections::HashMap;

use cure_asn1::rpki::rrdp;

use crate::cure_repo::new_repo;

pub fn random_fname() -> String {
    let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(8).map(char::from).collect();
    return rand_string;
}


pub fn create_repo_structure(conf: &RepoConfig) {
    fs::remove_dir_all(&conf.base_data_dir_l).unwrap_or_default();

    fs::create_dir_all(&conf.base_rrdp_dir_l).unwrap();

    fs::create_dir_all(&conf.base_key_dir_l).unwrap();
    fs::create_dir_all(&conf.base_repo_dir_l).unwrap();

    fs::create_dir_all(&conf.base_tal_dir_l).unwrap();
    fs::create_dir_all(&conf.base_ta_dir_l).unwrap();
}

// Careful! This wipes the entire Repo content!
pub fn initialize_repo(conf: &mut RepoConfig) {
    create_repo_structure(conf);
}

// The Filename is generated from the Public-Key identifier of the cert key
pub fn get_filename_crl_mft(cert_key_path: &str) -> String {
    let ks = read_cert_key(cert_key_path);
    let pubkey = ks.get_pub_key();
    let digest = sha1::Sha1::digest(&pubkey);
    hex::encode(digest)
}

fn normalize_uri(uri: String) -> String {
    let uri = uri.replace("\\", "/");
    let uri = uri.replace("./", "");
    uri
}

pub fn create_snapshot_notification_objects(objects: Vec<(String, Vec<u8>)>, conf: &RepoConfig) -> (String, Vec<u8>, String, Vec<u8>) {
    let mut new_objs = Vec::with_capacity(objects.len());
    for obj in objects {
        let base_path = "rsync://".to_string() + &conf.domain + "/" + obj.0.as_str();

        let uri_l = normalize_uri(base_path);

        let uri = local_to_uri(uri_l, &conf);

        new_objs.push((uri, obj.1.clone()));
    }

    rrdp::new_snapshot_and_notification(new_objs, (&conf.base_rrdp_dir, &conf.base_rrdp_dir_l), &conf.domain, conf.irpki)
}

pub fn create_snapshot_notification_delta_objects(
    objects: Vec<(String, Vec<u8>)>,
    delta_objects: Vec<(String, Vec<u8>)>,
    previous_deltas: Vec<(String, String, String)>,
    previous_hashes: &HashMap<String, String>, // Needed because if an object updates an old object, the old hash is needed
    start_serial: u32,
    session_id: &str,
    conf: &RepoConfig,
) -> (String, Vec<u8>, String, Vec<u8>, Vec<(String, Vec<u8>)>) {
    let mut new_objs = Vec::with_capacity(objects.len());
    for obj in objects {
        let base_path = "rsync://".to_string() + &conf.domain_l + "/" + obj.0.as_str();

        let uri_l = normalize_uri(base_path);

        let uri = local_to_uri(uri_l, &conf);

        new_objs.push((uri, obj.1.clone()));
    }

    let mut new_objs_delta = Vec::with_capacity(delta_objects.len());
    for obj in delta_objects {
        let base_path = "rsync://".to_string() + &conf.domain + "/" + obj.0.as_str();

        let uri_l = normalize_uri(base_path);

        let uri = local_to_uri(uri_l, &conf);
        let hash = previous_hashes.get(&uri).unwrap_or(&"".to_string()).clone();
        new_objs_delta.push((uri, hash, obj.1.clone()));
    }

    let ret = rrdp::new_added_deltas(
        new_objs,
        vec![(new_objs_delta, vec![])],
        previous_deltas,
        start_serial,
        session_id,
        &conf.base_rrdp_dir,
        &conf.base_rrdp_dir_l,
        &conf.domain,
    );
    ret
}


pub fn create_default_config() -> RepoConfig {
    return RepoConfig::default();
}

pub fn create_config_name(ca_name: &str) -> RepoConfig {
    let mut conf =  RepoConfig::default();
    conf.ca_name = ca_name.to_string();
    conf
}


fn local_to_uri(uri: String, conf: &RepoConfig) -> String {
    uri.clone().replace(&conf.base_l, "")
}


#[derive(Clone)]
pub struct ObjectKey {
    pub private_key: RsaPrivateKey,
    pub file_uri: String,
}



impl PartialEq for ObjectKey{
    fn eq(&self, other: &Self) -> bool {
        self.private_key.to_pkcs1_der().unwrap().as_bytes() == other.private_key.to_pkcs1_der().unwrap().as_bytes() && self.file_uri == other.file_uri
    }
}

impl Eq for ObjectKey{

}


impl ObjectKey {
    pub fn get_key_id(&self) -> String {
        let pubkey = self.get_pub_key_bits(); //self.private_key.public_key_to_der().unwrap();
        let dg = sha1::Sha1::digest(&pubkey);
        let h = hex::encode(dg);
        return h;
    }

    pub fn get_key_id_raw(&self) -> Vec<u8> {
        let v = <[u8; 20]>::from_hex(self.get_key_id()).unwrap();
        v.to_vec()
    }

    pub fn sign(&self, data: &Vec<u8>) -> Vec<u8> {
        // Load private key from PEM
        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());

        let mut rng = rand::thread_rng();
        let signature = signing_key.sign_with_rng(&mut rng, data);
        signature.to_vec()
    }

    pub fn get_pub_key(&self) -> Vec<u8> {
        self.private_key.to_public_key().to_pkcs1_der().unwrap().to_vec()
    }

    pub fn get_pub_key_bits(&self) -> Vec<u8> {
        let pubkey = self.get_pub_key();

        return pubkey;
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RepoConfig {
    pub base_data_dir: String,
    pub base_repo_dir: String,
    pub base_rrdp_dir: String,
    pub base_key_dir: String,
    pub base_tal_dir: String,
    pub base_ta_dir: String,
    pub base_l: String,
    pub base_data_dir_l: String,
    pub base_repo_dir_l: String,
    pub base_rrdp_dir_l: String,
    pub base_key_dir_l: String,
    pub base_tal_dir_l: String,
    pub base_ta_dir_l: String,
    pub domain: String,
    pub domain_l: String,
    pub default_ipspace_first_octet: u8,
    pub default_ipspace_sec_octet: u8,
    pub default_ipspace_prefix: u8,
    pub default_ipspace_prefix6: u8,
    pub default_as_resources_min: u32,
    pub default_as_resources_max: u32,
    pub ssl_key_webserver: String,
    pub ca_name: String,
    pub ca_tree: HashMap<String, String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub debug: bool,
    // pub use_proto: bool,
    // pub proto_schema: bool,
    // pub new_mft: bool,
    pub fuzzing: bool,
    pub irpki: bool
}


impl RepoConfig {
    fn from_json_file(path: &str) -> Result<Self, Box<dyn Error>> {
        let content = fs::read_to_string(path)?;
        let mut config: RepoConfig = serde_json::from_str(&content)?;

        // Set default parent values because we need them often
        config.ca_tree.insert("ta".to_string(), "ta".to_string());
        config.ca_tree.insert("newca".to_string(), "ta".to_string());

        Ok(config)
    }

    fn from_json_txt(text: &str)-> Result<Self, Box<dyn Error>> {
        let mut config: RepoConfig = serde_json::from_str(&text)?;

        // Set default parent values because we need them often
        config.ca_tree.insert("ta".to_string(), "ta".to_string());
        config.ca_tree.insert("newca".to_string(), "ta".to_string());

        Ok(config)
    }
}

impl Default for RepoConfig {
    fn default() -> RepoConfig {
        let c = RepoConfig::from_json_file("config/repo_config.json");
        let mut conf;
        // In the case of an error, use default values
        // This is a bit of a hack, but it works for now
        if c.is_err() {
            let def;
            if Path::new("/mnt/cure_tmp_fs").exists(){
                def = r#"{
                "base_data_dir": "data/",
                "base_repo_dir": "data/repo/",
                "base_rrdp_dir": "data/rrdp/",
                "base_key_dir": "working/key_cache/",
                "base_tal_dir": "data/tal/",
                "base_ta_dir": "data/tal/",
                "base_l": "/mnt/cure_tmp_fs/",
                "base_data_dir_l": "/mnt/cure_tmp_fs/data/",
                "base_repo_dir_l": "/mnt/cure_tmp_fs/data/repo/",
                "base_rrdp_dir_l": "/mnt/cure_tmp_fs/data/rrdp/",
                "base_key_dir_l": "working/key_cache/",
                "base_tal_dir_l": "data/tal/",
                "base_ta_dir_l": "data/tal/",
                "domain": "my.server.com",
                "domain_l": "my.server.com",
                "default_ipspace_first_octet": 10,
                "default_ipspace_sec_octet": 0,
                "default_ipspace_prefix": 16,
                "default_ipspace_prefix6": 32,
                "default_as_resources_min": 0,
                "default_as_resources_max": 1000,
                "ssl_key_webserver": "ssl/certbundle.pem",
                "ca_name": "ta",
                "ca_tree": {},
                "ipv4": [],
                "ipv6": [],
                "debug": false,
                "use_proto": false,
                "proto_schema": false,
                "new_mft": false,
                "fuzzing": true,
                "irpki": false
            }"#;
            }
            else{
                def = r#"{
                "base_data_dir": "data/",
                "base_repo_dir": "data/repo/",
                "base_rrdp_dir": "data/rrdp/",
                "base_key_dir": "working/key_cache/",
                "base_tal_dir": "data/tal/",
                "base_ta_dir": "data/tal/",
                "base_l": "",
                "base_data_dir_l": "data/",
                "base_repo_dir_l": "data/repo/",
                "base_rrdp_dir_l": "data/rrdp/",
                "base_key_dir_l": "working/key_cache/",
                "base_tal_dir_l": "data/tal/",
                "base_ta_dir_l": "data/tal/",
                "domain": "my.server.com",
                "domain_l": "my.server.com",
                "default_ipspace_first_octet": 10,
                "default_ipspace_sec_octet": 0,
                "default_ipspace_prefix": 16,
                "default_ipspace_prefix6": 32,
                "default_as_resources_min": 0,
                "default_as_resources_max": 1000,
                "ssl_key_webserver": "ssl/certbundle.pem",
                "ca_name": "ta",
                "ca_tree": {},
                "ipv4": [],
                "ipv6": [],
                "debug": false,
                "use_proto": false,
                "proto_schema": false,
                "new_mft": false,
                "fuzzing": true,
                "irpki": false
            }"#;
            }
            conf  = RepoConfig::from_json_txt(def).unwrap();
        }
        else{
            conf =  c.unwrap();
        }

        // Set default parent values here because we need them often
        conf.ca_tree.insert("ta".to_string(), "ta".to_string());
        conf.ca_tree.insert("newca".to_string(), "ta".to_string());

        conf
    }
}

// Generate a new RSA 2048 bit key
pub fn new_key() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let rsa = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let der = rsa.to_pkcs1_der().unwrap();
    der.to_bytes().to_vec()
}


// Create new cert key that can be used to sign objects in the repository
pub fn make_cert_key(file_uri: &str) -> ObjectKey {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

    let path = std::path::Path::new(file_uri);
    let prefix = path.parent().unwrap();
    std::fs::create_dir_all(prefix).unwrap_or_default();
    fs::write(file_uri, &private_key.to_pkcs1_der().unwrap().as_bytes()).unwrap_or_default();

    return ObjectKey {
        private_key,
        file_uri: file_uri.to_string(),
    };
}

pub fn read_cert_key(file_uri: &str) -> ObjectKey {
    if fs::read(file_uri).is_err() {
        if cfg!(feature = "no_cached_keys") {
            return make_cert_key(file_uri);
        }


        return load_cached_key(file_uri);
    }

    let der = fs::read(file_uri).unwrap();

    let private_key = RsaPrivateKey::from_pkcs1_der(&der).unwrap();

    return ObjectKey {
        private_key,
        file_uri: file_uri.to_string(),
    };
}




pub fn create_tal_with_key(httpsuri: &str, rsyncuri: &str, tal_uri: &str, keydata: &str) -> String{
    let mut final_string: String = "".to_owned();
    final_string.push_str(httpsuri);
    final_string.push_str("\n");
    final_string.push_str(rsyncuri);
    final_string.push_str("\n\n");
    final_string.push_str(keydata);
    final_string.push_str("\n");

    let parent = Path::new(tal_uri).parent().unwrap();
    fs::create_dir_all(parent).unwrap_or_default();
    fs::write(tal_uri, &final_string).unwrap_or_default();
    final_string
}

pub fn create_default_tal() {
    let mut root_conf = create_default_config();
    root_conf.ca_name = "ta".to_string();
    root_conf.ca_tree.insert("ta".to_string(), "ta".to_string());

    let root_repository = new_repo(&root_conf, &cure_asn1::rpki::rpki::ObjectType::UNKNOWN, true);

    let tal_uri = root_conf.base_tal_dir_l.clone() + "ta.tal";

    let tal_https_uri = "https://".to_string() + &root_conf.domain + "/" + &root_conf.base_repo_dir + "ta/ta.cer";
    let tal_rsync_uri = "rsync://".to_string() + &root_conf.domain + "/" + &root_conf.base_repo_dir + "ta/ta.cer";

    let aki_b64 = root_repository.certificate.get_ski_b64();

    create_tal_with_key(&tal_https_uri, &tal_rsync_uri, &tal_uri, &aki_b64);
}

pub fn create_tal(conf: &RepoConfig, aki_b64: &str) -> String {
    let tal_uri = conf.base_tal_dir_l.clone() + "ta.tal";

    let tal_https_uri = "https://".to_string() + &conf.domain + "/" + &conf.base_repo_dir + "ta/ta.cer";
    let tal_rsync_uri = "rsync://".to_string() + &conf.domain + "/" + &conf.base_repo_dir + "ta/ta.cer";

    create_tal_with_key(&tal_https_uri, &tal_rsync_uri, &tal_uri, &aki_b64)
}

pub fn _create_tal_def(aki_b64: &str) {
    let tal_uri = "data/tal/ta.tal";

    let tal_https_uri = "https://my.server.com/data/my.server.com/repo/ta/ta.cer";
    let tal_rsync_uri = "rsync://my.server.com/data/my.server.com/repo/ta/ta.cer";

    create_tal_with_key(&tal_https_uri, &tal_rsync_uri, &tal_uri, &aki_b64);
}


pub fn remove_folder_content(folder: &str) {
    let paths = fs::read_dir(folder);
    if paths.is_err() {
        return;
    }
    let paths = paths.unwrap();
    for path in paths {
        let p = path.unwrap().path();
        if p.is_file() {
            fs::remove_file(p).unwrap_or_default();
        } else {
            let v = p.to_str();
            if v.is_none() {
                continue;
            }
            remove_folder_content(v.unwrap());
            
        }
    }
}

pub fn load_random_key(conf: &RepoConfig) -> (ObjectKey, ObjectKey) {
    let key_uri = conf.base_key_dir_l.clone() + &conf.ca_name + "_cer.der";

    let ks = read_cert_key(&key_uri);
    let number = rand::thread_rng().gen_range(1..10000);

    let key_uri2 = conf.base_key_dir.clone() + &number.to_string() + "_roa";

    let ks2 = read_cert_key(&key_uri2);

    (ks, ks2)
}


pub fn clear_repo(conf: &RepoConfig) {
    let r = conf.base_repo_dir_l.clone() + &conf.ca_name;

    let rrdp_dir = &conf.base_rrdp_dir_l;
    let base = &conf.base_l;
    fs::remove_dir_all(&rrdp_dir).unwrap_or_default();
    remove_folder_content(&r);
    fs::remove_dir_all(&r).unwrap_or_default();


    fs::create_dir_all(&rrdp_dir).unwrap_or_default();
    fs::create_dir_all(&r).unwrap_or_default();

    fs::remove_dir_all(&(base.clone() + "/rpki_cache_client")).unwrap_or_default();
    fs::remove_dir_all(&(base.clone() + "/rpki_cache_octo")).unwrap_or_default();
    fs::remove_dir_all(&(base.clone() + "/rpki_cache_fort")).unwrap_or_default();
    fs::remove_dir_all(&(base.clone() + "/rpki_cache_routinator")).unwrap_or_default();
    fs::remove_dir_all(&(base.clone() + "/rpki_cache_prover")).unwrap_or_default();

    fs::remove_dir_all(base.clone() + "/rpki_cache_client").unwrap_or_default();
    fs::remove_dir_all(base.clone() + "/rpki_cache_octo").unwrap_or_default();
    fs::remove_dir_all(base.clone() + "/rpki_cache_fort").unwrap_or_default();
    fs::remove_dir_all(base.clone() + "/rpki_cache_routinator").unwrap_or_default();
    fs::remove_dir_all(base.clone() + "/rpki_cache_prover").unwrap_or_default();

    fs::create_dir_all(base.clone() + "/rpki_cache_client").unwrap_or_default();
    fs::create_dir_all(base.clone() + "/rpki_cache_octo").unwrap_or_default();
    fs::create_dir_all(base.clone() + "/rpki_cache_fort").unwrap_or_default();
    fs::create_dir_all(base.clone() + "/rpki_cache_routinator").unwrap_or_default();
    fs::create_dir_all(base.clone() + "/rpki_cache_prover").unwrap_or_default();

    fs::create_dir_all(base.clone() + "/rpki_cache_prover/tals").unwrap_or_default();
    fs::create_dir_all(base.clone() + "/rpki_cache_prover/cache").unwrap_or_default();
}



pub fn parse_cached_key(key: &str) -> ObjectKey {
    let der = base64::decode(key).unwrap();
    let private_key = RsaPrivateKey::from_pkcs1_der(&der).unwrap();

    return ObjectKey {
        private_key,
        file_uri: "cached_key".to_string(),
    };
}


pub fn load_cached_key(file_uri: &str) -> ObjectKey{
    let key1 = "MIIEowIBAAKCAQEAqicDJAmoBMmEC7RTih/i1dyhh2xrzfwYwo4Vx5fT1IDGLws67iVs8Xze54OPaonSioWYH65RJgK1CH26+pp8sI9DJHXqpZMCFHFfklByFZUmHVmOZVSge04TqR5EbPAvI9f0xy6tCgzn+2FKEWvV0tdXEqFisLXetFNvcR/TnDS/72KiOGL4rWvH3pEWDTdj9xvxjYQUNK2PVvZS4D2NZSwvscwDjIp21clKX45+eGF+bHCkLgJZryRSzNQodtchXcmTz744+3b7px5SEjsAcPzFY+fO0pdWrZ15m0kYH2Wcfkr72wvIqMsRT8c6b6YHHYHKr6Gv1v87sh2iHx2pcwIDAQABAoIBAH30DQYjQ8XvahjD7scjXWXUQZoerxq2z5lNVl/+SudWP95ZINFi0Odd+R9FqudBiKHTzM0+24EYpevYLo4Nx9lm41vdEcppLTP2zLlhZWIGm0VEovztjTJZlIIvDpXZofuVg/Ph4GO9NAhId2y393twvlrjLkwDBQ1VafxChAFvcNntFZw5XquI8+MMaoEFZieLHNd6ksz6RXFaNtVFWEhULZ58DQX7Gfz8XAV9iN4gDJKNKs6fO2hET2oLbS4WIf4tn4XrdEzFWrM8aHaWBRWzef/5bbGcS2truHT+bxx/D2To4t0CaHuB+n7dWu125IkCsr95XxbJOGI3gNQd0oECgYEA4jp9Clzz7VwgDJYVakDHUuKooNnWB2oyCmCLvdoxOjLzkZGo3lmNoOMrORQJJPArhORcbzCQlFsgZ2pW2dLjq5+EXpe4YG3oFRchYJqTBA1rW69IMkFlzWyh2Nvfjte3QpjkcpGakHp8f4pOzJD+O8ZIGeUoXsgIjDk2OKJly7MCgYEAwItaFCddG8QqiZRlPxi/f9/u10wtBaoHaf0lb/zOqpV+ZRbDDLQWVCqSfsVnlf87icizoGnpYLBpIf5t1tyhAeRJlCn0Y35WCKy7ICcJs15ATX4gVWmp/huZsaQD1VOIOyyG4TucJ8EVG91FK4zXwEfg+IJDf90x+I431RNKy0ECgYB1teEh50O0mV7DrcPuyU3tPqpnJ3FJ4mOvKpULb+B1W9WIRLYNG6OptwniZR5s7dp3BythX2+bAd9Wb+pI5IY54oJJhcAVzJoZfzOKxGMClMjrp8R1AboqrP95is5D0NI2AL+9LS2zR0hIRHrDzh26lG0nrCjZSFPKQmqIBVfaKQKBgC1xtnUDRWqERjXqnGrkAG7B/7E4/XdUxiMx6GAiHvUMC6T4VljtOEftNF5PYT952iePAzZdSQPVHzsyveH0eNvlcahSrqe87blma1QPYq6/FBY2KpN+OO0Mvp26xFzZNlIhFEScuSJ44+6LrwO0Xke3r1V4CU5oep7bkjnsL78BAoGBAJwQ3OBzm8CfIqxf6tOmPy9WXP6Kc6o0p+X7MwBogJHfp2pWF7D1K+pr+LAHjmwa38in3R+AFIfdox42PbMjSDdVSzRMfqV6SVxf43PzEZLK+k29ZZ25O3q91Ha5q8GS3D8pCDGBoGMqgmHRr3yHZpaFvGVlksXl3LFJLo+rrBFW";
    let key2 = "MIIEpAIBAAKCAQEAzMtcJz1eMvvRqsEFlTBpErGESArfXMO4KT56w86SsUYWCizguHBYyhqvzQldmLoYieOI0gKs7Aw9uH1EivL+HiubuD8zlebj/3cbE2xDBUjlg2hQqQZkYqjlgtNvyhy/lMXrpJBC03rQ8cJmH4ys6iqB6mbu6IQy7uiFxb8XXAKpj/HT+WRjk8L19FyZ6o0hlyqcZOIEC8ausIAqfkC244owf8WzcvycdUN+FnW7tNrrepX5MSxoOn1UbeBkTv4i19WCIDLx3QUfjYnDNYUjWb+63wbxstkJuE2RYdtTgPalqugdDPG1GLbX+febZyPamO3vvKLd9v7LQWXEuV7/pwIDAQABAoIBABAIn+dmk5h0RL8Uq6Y5ixBum4e0ajZuEF4SSTRJWQzOCu2zA8kM6rawDjGEWTKa507sZIrksLsuXiqyjApA6gpcqa1sLVLAJ/uZTKJhqIGiam22XhJNsNBUntt2SFtPkuRH9qIEtWavR+qVqL8xmVwgBdnfQzcrGn2/8LFBu8d1Pgg9aOIyiN2nR7S0EX4PjPsK/eMDM+f909rs9i8thxgv23lAAW1ChXJOIoyA3swXbCCrJo8hFJwxv18WbXthbb590jGpl/r6XoMCTEBPowHqhRO/Z4cPsWSWwF1tTWNTXNqX4t1PedCZwr3v93c+YPDoSgeTnTXORgyaLioMaSECgYEA3dzeJkIfdPGqJMdOqeIrlIOp6yeWq3UNr1XnQYEbO9UiXZ6H9YeehOu3+RGhw5optgVS0e8ScfSsBPJ/ZERpnpipgWStOk8HUROxx6+C1/lRAlDOLYk/zXzOpxHP/jewCSb+43z6dAnPQEQsdZxhwDMYUZ1gDCvRj5ww2TcebjcCgYEA7E4r65pCu9U603jNkO48Leamg7yqi6tXdvWS0VUr9AK7qR09AnV5MsmUDv2SmDZSZswpZbXFW1eDABxX12Nk0BZ7Jgc4ZqZfH3umOfV5n0TQwrhoM1mvKltR9tOtmALwfMkgFYeqqZRwYbD37maIBMepqk16wo4u/ImBN7vMwhECgYEAiS0L6enOW1cklRLqT125Bl2WDQBwR1jbekKJ9tVlykvQsMPZWnVdDOBV4tkFBNTn31RRTd4csHrQdUqee5dVGqtXetqNxNSiOH4N2OJq6zCK5vyhTkRjP6FggKohyRQTcsU6qdtXW7HJA/pi5uEnC1hMPAIrJbteGgY/qb5LwWcCgYEAnr5c7ucwUXKLFCkhH22La+J4liMWBsHR/g421P18i22Sl6cWpyI3ixCzr+ZUpoBHltssLDGSJSyCyn4/3Gfe/5M6o29SSlMVr9am8mSfkYjvHQA4r9Zdv/yc8U1+XpIK8ClErnH3Cfi4DkiOJc8nLN7ccZWfFDfkBK5y6ff1M6ECgYBoMeLLAcKZvmWb4omK2vYcca4FDwcOQ5U2JqfUBjEtuoHy+GD6oeLUH5pEwN6yQqm2RdAywlDa+1Nd6X+DWqAxCfvWlK4UNeqyF9XDTKLfGST8xkQbRSQ7P6VB2qZepcH4mfZl1QI6enbaJBTkPNch3cSE1RvMJq8XSaIhDSEvrw==";
    let key3 = "MIIEpAIBAAKCAQEA4BFuNGmCe7V5ZS+J+SUyQ0YxfXCoyxAUQ6YH/oxKNwGeDTOu5H6nxwlnIDRBnsx+i58MR42JF8UiCnta6QRZa66P+alsx4xIUAxXbB6IOk4Szl2TE2vFnVBqpjVuGxUtj6hmSnFhAEfRhw+hPjilOJBv1Yd41SxpwsPMbFIh/xbPgBB0x8cDJf79OnIHcDvC3O9n7Q0+7hzxo/BRDwCXA+NTUe9YjLm+SqcLtPnZQ84KFEDByIIYKbolcZFHchNR+OFswp3TEzqK5Y80FWdDWIqvOX7bzwlietmL5wVwWcsKZLpHKwPqEnL0anOiwsfL9Sxt4zN9qqKb2gmfxuxIMQIDAQABAoIBAAKDT4gY8tSuWVkwKkz4BNNKUz3D6LC2UnPbxdUt/5sUUpB1Vu3LGdiam2R6EY5VXsn0E7Atvy7cECCr934LhXE2uPik1Mp8IUd8i/JzeTWmMIHN/NtH5yR3hWqtyLlXCHbG/bayBNN6+reYDkfjXL8Ap7BuX4WMhPchOQax+R2iP3w6A7RWbUU+QLgB/Brh8CgouB5AwMKKIOZYsxBH3iecqiR9Cr444BvwLIpYoT+EIxm9w039m8Ywp6kBfXChpoYKqEtvNCBXL5zPfxj1oJ9HpliuwOiPatpBa7nHMTxkJVdS2BVssO5huVXor3iQwb34YawGkW9yoOVDtk6Elg0CgYEA8Gr8Yf1565/kqnPpschozgce3NcipNsPh4cBO3gpb9sN8JS/x1TzBRQh9JFZAaTcT81B5l4GJCBgHwXOMeb144rMmGgy94w+GtfmN6VYMFTAhb81eDRShQ9wL059SWZXMgXBVh4AWso5PeFkDEs+hjQYI10C8oAnWNeNCce3Q3sCgYEA7pcrFc1j3itc3Jx92KmM7zqEK1AglXHUI/B9voVzChVkRiAJ3svvtRkqBH+FHp+BtXGJHa28eHXfIKlb1RDUlTLOtEcWX7EFgoOyEusatr9tpQIWrgf3gTvymSFxKNZpJCMAHTD3l/bX8HsfIQCv05trfZUVNzhkJ4gFne17LUMCgYEAsPNNhyH1VoN83igqXPvQh7Od95Uwnn3NVEb9lTO/6+Aixmv1K1VO+PH0e/lutVMOBH5ifpe9lWFu3eZ7+Saw3CUQqSwoNyM1orQ9cb90xT3b5ZTyWeLIyb6vJ2JxvFBi5SJvRl8Wi7xDnVQDOzk2b7hv+7c9sBa63xznZcdlD3kCgYAD+MpD06Z89VXXaleB+tiYxu2aVvwj4MA6VO+S81/F5DNGI5RmfBiieCfF6WWK6/bZ0WkJ8HF5w+SSA5++vUf8r9rXD3Pk5eqEkLKvM/C+6BLoM0+zV/ib0yanu/HJT0By1I5U7hLBGd/gZfxPrVY//I9eiNPQloS8T7xgM6rgRwKBgQDDin++L32Odun+D0CG7MDcFsZIXLU6ud9+38ANgKTWCq9FkIUWfmReYSNct8quhJd/TBpLDixDB3U+8DCvsqxkLNZIOiAtBdoJRMo/hMP52Vw8WxM57+K/LqF7nSjyD/u3RqGrD2g7kt7bPgav+YTgejKiLFtS4D9uQ/6Ug0KfOw==";
    let key4 = "MIIEowIBAAKCAQEAr3nSzXvv18hbirFWKzTd87Zli8vAR5tyMClbsLuC7WH/rAiR15gIBlVO9nPIFuligtV5df5C4oThUIv4ZiYOusmYDRVETbedS3zhN05Y5NWGfBnN+4+2u/L9uwop3VfmoeAaIYA2YM7NMO6Ut3hi4m+CfW7Jo3j8/ZSMLU9nCkVHXqyLeT6RlBjEvtkBt6eo/KZMt0yF6va6p58Dxqm47eIvv6paOmrnGk8vZcGFQTD4XRb2DrIzqVlNVC4xRYwci33sHOz+hA/+5ltSrOtI8ehLshcnFKFVFcvr98fUPrwVJqTz01xcccVH2J/RA/P7c1tKXWNVqHTZ5dxD7Zl8TwIDAQABAoIBADM+rXxK3HE01t77CQIXL1ZUBvW7bAy9bax494j2SbcPbn4MBqNih71pvmSkzWM7hwRUWWNG/LtwOOiv57vVE2ojI192vXrAy5PXBWKEY9t4LA0j8A6uGpxqywSLZEx6tiTB8H+mFLtSyYOnuRCXfLFKBV6iMwqlc6SOdB1rWdkahH565HPth9JcKjTw/9cE7uyojRRC5XfI4J70crNM1BsyBZqHwsuD50UD8uo/GtCkY8VW2g+0y7Afd+GkZwLCaIaW+IGgvW1wKGz4cIyuffek/dFoHym3sdVZbcoC20vjf2Odss3Mr/pE8VX5NQQ2bBrJ5GpELjxEPC02OiL/RikCgYEA0UHsKMGhrFVJYkPi3IQS6Lm1TLCW2bw7Bz7sp8hiPAtkz9GjDr9igm96FmxkCcp705TUsnwV8UPpZWDrNW16GbXB8HeAgHN0oBvOxZjjm9j84fxj07woRR1HKGSsLrWZ1xh776QJw1yBHh+t0mxC7dJ+YukGItwnrvIRA1gOLasCgYEA1qwmCvX4oVniCVDMUnA0DtK9FCHxc+oqAX/SlhnrhgiRqyXoZ9xEBortml6Gu4Ygjzek+ONScj4fnGOCAH8kaZMdtJzOdM5xNiPtmWHj367Ss5scMqTS9Dcgmpk9JiJiJf2c9z5nbVg9d4tMuQ8y418NykDD+LpDt/Di0NpUn+0CgYBrC1L4Yl0G4DYC64FAlttpa55f1bHFPjHf+gNrrOj7mESAvtevsp185fPJRrdB/u+rA2Zuy2UaH0hkkNihYxhj0IOeNDNrAiS1xqPWluhQEAcEv2x9orHi8SA2fJFL75/71U2JABvycP6n30K28qSmLdhzVorKCF7QconbcQ8HswKBgQCQNuf7txCHfLWgInqQ6zXdu28wZjkp8Oa1SSS0l8ckrP8HJhlCJLRCXPSQHu6ObeXTsMMQPM63Vsqvqh28ra1Ni3qKSklcKQ/fGjXVM/D85RpBdHN2Bkp9q8codMeipbif4wefBXo/9+abN6acL/y0yLef5vCAWMmDeb02J2ZwZQKBgDkmx14nL6B6tGaBxSEpFezCYbMo1jYkinQoZ0pdi+5TfDaP3sOueqm9pH85CfZdfi93QRSbbghFjNCDe0BOjsBPi1GqFTx9W4Zuedps0E1WZlnRGyy9tpuG9qXNi5d1+e4ir9R+m9sZKtKwgAzfBq51G9xiX6J4vNWSe6lwybni";
    let key5 = "MIIEowIBAAKCAQEAn4vjCUKmiDOIe57Su8r1n03rdZ20pVt9Wl9jVUxDq731E9C9Rul6awYNbQ5H8w9BaqYmKcMnlddypQQ5q+BXwl92od6F+1Uars1Kvo+WfyDnJMmnIxIyWXXG+5MM8ECC3JpDvxBzYjfwgZuF6Ypf/1//OsCiK9PtubKZufX8CMRB8L88f21b4+RDGXfQ51AMOfKnsLNEt9aS6AFK+wp7BDPQ91Mp82MLhOM49vGfjjVrN9/ai3Z/OEOsJ+3zfUZAtSYTMNm+zycAq1uGWFM3INey2oPbqCmETRuJUSYNgZvh7LPpd2TFinBLFkZUNmLZW/zBPNQesKNL6psUaY1mRQIDAQABAoIBADqdPNqxFtdg/1pTPh5p8RUGnmOGfdBmLUZfVvIGY7IbxobyICeGLUhWX+ZZ4csFJsZUph6fqNJe5aqEQ9/GOteZFM9hHh345SWlHDmoLOUlpGWahAHZdI/zOhhArPcy7CC5t/vgwlMqM/yZs3faM2xxyyW9kZbCdErNt7ZfDan2Q5y92UaGYPbzvEKCNn7N4c5/byk57CBFjAiFoUodj4rcdqZkjHNyvHG+76fJeCORf2uMDMoJOsNfIb+rQD3g6ySYqOaltftcvo10ojAFNo8seT+GzzscwO261FRk+c4CII4pHTYwK+fqeAcppeOvfx7CGVNyNEZE0Oub9+eRj+ECgYEAwojtUVDDmyJMbp4nHSTRpi96rk0rcd+fG3smTh2+VfJs5FtJe8QdruNl52FGfxtLKUS+1MPPNW0NCN9G3EozXwzfH8Ffnd39aMDt4exgne6jwg0JcMfJTR76tw8zJCwW0Rf4AU97JEti4QjoPUkcekLRAvWDawiAcBLfE1UL9j0CgYEA0fTmAN5kGAkMCqQuh3QmKcWDk/J7/xhggUJ01QmgS2J6Yr0dE2rPro9mRg/Yh07M1mPsvR25SpMAD0Unk0ppFwm0kTgjhRQix2NRheDGHcTxQmhRyE44jkFzO8358rZPA7UVnBkY7t+nNEFiq/BE6AAY07qxryzqHxbO0YEcuKkCgYAtEu7x5WW9P0A4bTqg3RQajmu9kTHcy7Sg+HLSrL+aSHaEnsYzACjkidnlt7tO3jMXF8+jms8bEO5xPNK9Xg/zGRdl0zdla7c4m2NC8rMcRNv6rWyfjhsNXH05BzORUQnkXspe+1yL90+s1pSBBryrc2ncZqiRl0GzNhwr7Yu8/QKBgQCACvq6TOZ+QgY19yrpMMyVbP9xmtBEInm4Wu8lfVlkoApDbVHuJZXCv3GACOnkmwoRNZ+LNjVqZXwD1AjuqtKsWh7k8Xe4ES+kqc1t+EbaoOEBvt0ha5LSLtg4AMYOX2CQwj8Lk8LA62TtWXLzqPRdCLIbbiAu1RVzIFXBLxx1AQKBgC0xz/Y1PlNM6sjJIJt2e6+2IK5LbHe73Tauceeql/D9uBR9WX36opWrWNqIGmyrZCFYXGMR+77QNPplQaSGj+wGbJsujsRaG0+SARgjYvY+sf3YDriNl/x4msmNj/LwBu9gK+fpABBfgxTioe+FvLg3gnv/QvAypBoIJ+UvB3or";
    let key6 = "MIIEpAIBAAKCAQEA5nT3pCxidtXvZjiP4aEZ1bSQBCtPn2SJv7EYlvzIy3Wmu/eB5tydIXhohCD8pKPOhobkh/ftGvtnT7hjoe2CZVAYwZNvlIDPfQLOgOkVjhM82W3KBc4oIWmmW3UZwIUH8vUnTi8s53ITLMuZeVfAx9sKjBAmlghoXaexCMri+TP9NRAooAAIpTgUKL0O3Slkuvb4tlUtSV7LQWBqoc8HNXXbJR/KQ7fYmXrcmMacPQHnAXGq1oWKsDs6XCtNvI4w2evANB3W6OUVoxpmIZQ82zLEB6S4VbaHJ9EzF6RvGgTEQiXXIoef0LAlxBw/qBvEaK+1Y3h09Ih70zr5vqlJ0QIDAQABAoIBAHYRZu5NbwTDBiuwvsYx6zJ5l28LYXef4pK7AIYabCUQ2aNjYsIMNNR5A9Lts4IGCkERyvN+KZOxSXSmWyUSscOGDajfCENk2uiJD5Mr10c6w+oBPYdL33N+1SP2EoN3pGLtBn4f3TmWUAybIr3wH2xE5Fpty9cB57ZTu3dtumtBJj3K9tIueUzPVBJQRAwdDWwCFp/3pQVYDszTlfzsrDpDQsjVvU2eAziVB1PfGNbjH7vhWCO32GG1NutlBhjCzqO4kWu+ufoizxd4EmqdUrD0AHvPEF5bagpPw/UzaUBd7w47ADdnqLyqSIa0740I5JL3JWwZ28cYzSh1xsuKDYECgYEA/3KTKBju0WDIlteFB/Cgqd+v2pcl1RJpnQRsqfhwvTrbQnhoGt/eGCdNrMNe4g/C10LMMU2FN/6l6JfFtXHOliScSRlnfJL2pzB+Xnp7wCqKoai6udHpTY0AvTqf8NlM/evtkiUIAmA8oYoTyXnSfYDGElExL4dnae4W6RF715UCgYEA5vSOiKGfAULIqKxAs3K3gIlNkCsnQU2cCLA3YCmAIgjhfwZwRecHELo1+JB95NQKP+DLv+LJlBHKzt1/Q0fQUmDWScBgThGj8i57v6gyEJ5OlMz0RUoxUPvIuiQVKCihdGMyPiPtSN2sBSoh6QVqYrDOEFn0QbLAa30PNdAfKk0CgYEA+bzCMclucjT05sP9wy11ZZ7TBhoPWqiNqHzS37mMPvRzuCCPZvbG40ZJokW/VbOjAWDE0M7BF2VWPndjS2jgV9mjEbRMgHYNvpaidSu6IL12m2WiaFjYhoD74ASYqZdItlcaBG8/zVLY8/VSMv9u0lQ7UV0fgSAX8nBa5bG6KaECgYEAi+pGW0HGiUYDOCQ6gjwSLT2BDsEF5Ar3Z1ASDCC4LmZA7ephpAeFAT4+KhqnGjTXDMHLzbC/vANXYSFQ0tqzuuRNjZqM/V60eqhscbycr/Kn2n+b0EpVPCF9Bj+LzatnvJHHw1uSid05NFvE9V1BiQ5hmAhW8GIxLi0yRMCT0NUCgYAiKgjQerOkGteNFOP9+xwhpvBUPGJIC6eOL4OonSlmlyhioFV8OqP+HlbiZoVxJoYhACZf960A74+EoquKy4GGWYnGDOlu60iNjfUGVs7uJ7z83d6u8p4kYG4LMjCyNUq6K1fYVBnBaSCWq6AYo/tnIkB20qTgfCp36cOJeUVq/Q==";

    if file_uri.contains("_crl"){ 
        return parse_cached_key(key1);
    }
    if file_uri.contains("_roa"){
        return parse_cached_key(key2);
    }
    if file_uri.contains("_mft"){
        return parse_cached_key(key3);
    }
    if file_uri.contains("ta_cer"){
        return parse_cached_key(key4);
    }
    if file_uri.contains("cer"){
        return  parse_cached_key(key5);
    }
    return parse_cached_key(key6);
}