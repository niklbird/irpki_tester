use std::collections::HashMap;

use crate::rpki::rrdp::{generate_random_bytes, random_uuid};
use prost::Message;
use sha2::Digest;

use super::parsing::{CertificateAuthority, Manifest, NotificationFile, ObjectEntry, SnapshotFile, SnapshotReference, ROA};


pub fn create_snapshot(data: HashMap<String, Vec<(String, Vec<u8>)>>, serial: u64, session_id: &str, domain: &str, base_repo_dir: &str, base_rrdp_dir: &str, base_rrdp_dir_l: &str) -> (String, String, Vec<u8>){
    let mut cas = Vec::with_capacity(data.len());
    for ca_date in data{
        let ca_uri = format!("{}/{}{}/", domain, base_repo_dir, &ca_date.0);

        let mut ca_entries = Vec::with_capacity(ca_date.1.len());
        for obj in ca_date.1{
            ca_entries.push(ObjectEntry{
                name: obj.0.clone(),
                content: obj.1,
            })
        }

        let ca = CertificateAuthority{
            repo_uri: ca_uri,
            objects: ca_entries,
        };

        cas.push(ca);
    }

    let snapshot = SnapshotFile{
        version: "1".to_string(),
        session_id: session_id.to_string(),
        serial,
        cas,
    };


    let mut buffer = Vec::new();
    snapshot.encode(&mut buffer).unwrap();

    let random = generate_random_bytes();
    let base_uri_l = format!("{}", base_rrdp_dir_l);
    let snapshot_uri_l = format!(
        "{}{}/{}/{}/snapshot.bin",
        &base_uri_l,
        &snapshot.session_id,
        snapshot.serial,
        random
    );

    let base_uri = format!("https://{}/{}", domain, base_rrdp_dir);

    let snapshot_uri = format!(
        "{}{}/{}/{}/snapshot.bin",
        &base_uri,
        &snapshot.session_id,
        snapshot.serial,
        random
    );

    (snapshot_uri, snapshot_uri_l, buffer, )
}

pub fn create_notification(snapshot_uri: &str, snapshot_content: &Vec<u8>, serial: u64, session_id: &str, base_rrdp_dir_l: &str) -> (String, Vec<u8>){
    let snapshot_hash = hex::encode(sha2::Sha256::digest(&snapshot_content));

    let notification = NotificationFile{
        version: "1".to_string(),
        session_id: session_id.to_string(),
        serial,
        snapshot: Some(SnapshotReference{
            uri: snapshot_uri.to_string(),
            hash: snapshot_hash,
        }),
        deltas: vec![],
    };


    let mut buffer = Vec::new();
    notification.encode(&mut buffer).unwrap();

    let notification_uri_l = format!(
        "{}notification.bin",
        base_rrdp_dir_l,        
    );

    (notification_uri_l, buffer)
}

pub fn create_snapshot_notification(data: HashMap<String, Vec<(String, Vec<u8>)>>, domain: &str, base_repo_dir: &str, base_rrdp_dir: &str, base_rrdp_dir_l: &str) -> (String, Vec<u8>, String, Vec<u8>){
    let session_id = random_uuid();
    let serial = 1;
    let (snapshot_uri, snapshot_uri_l, snapshot_content) = create_snapshot(data, serial, &session_id, domain, base_repo_dir, base_rrdp_dir, base_rrdp_dir_l);
    let (notification_uri_l, notification_content) = create_notification(&snapshot_uri, &snapshot_content, serial, &session_id, base_rrdp_dir_l);

    (snapshot_uri_l, snapshot_content, notification_uri_l, notification_content)
}

pub fn decode_snapshot(snapshot_content: &Vec<u8>) -> Result<SnapshotFile, String>{
    SnapshotFile::decode(snapshot_content.as_slice()).map_err(|e| format!("Failed to decode snapshot: {}", e))
}

pub fn decode_notification(notification_content: &Vec<u8>) -> Result<NotificationFile, String>{
    NotificationFile::decode(notification_content.as_slice()).map_err(|e| format!("Failed to decode notification: {}", e))
}

pub fn decode_roa(roa_content: &Vec<u8>) -> Result<ROA, String>{
    ROA::decode(roa_content.as_slice()).map_err(|e| format!("Failed to decode roa: {}", e))
}

pub fn decode_mft(mft_content: &Vec<u8>) -> Result<Manifest, String>{
    Manifest::decode(mft_content.as_slice()).map_err(|e| format!("Failed to decode manifest: {}", e))
}

pub fn encode_mft(mft: &Manifest) -> Result<Vec<u8>, String>{
    let mut buffer = Vec::new();
    mft.encode(&mut buffer).map_err(|e| format!("Failed to encode manifest: {}", e))?;
    Ok(buffer)
}