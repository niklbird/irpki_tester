use base64::{prelude::BASE64_STANDARD, Engine};
use rand::Rng;
use sha2::Digest;
use std::io::Cursor;
use xml::writer::{EmitterConfig, XmlEvent};

use crate::rpki::rrdp_xml;


pub fn random_uuid() -> String {
    let mut rand_bytes: [u8; 16] = rand::thread_rng().gen();

    // Set the version (4) in the correct position
    rand_bytes[6] = (rand_bytes[6] & 0x0F) | 0x40;

    // Set the variant (RFC 4122)
    rand_bytes[8] = (rand_bytes[8] & 0x3F) | 0x80;

    // Format as a standard UUID string
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3],
        rand_bytes[4], rand_bytes[5],
        rand_bytes[6], rand_bytes[7],
        rand_bytes[8], rand_bytes[9],
        rand_bytes[10], rand_bytes[11], rand_bytes[12], rand_bytes[13], rand_bytes[14], rand_bytes[15]
    )
}


pub fn get_hash(data: &Vec<u8>) -> String {
    let hash = sha2::Sha256::digest(data);
    hex::encode(hash)
}

pub fn new_snapshot_and_notification(
    publish: Vec<(String, Vec<u8>)>,
    base_rrdp_dir: (&str, &str),
    domain: &str,
    irpki: bool, 
) -> (String, Vec<u8>, String, Vec<u8>) {
    let serial = 1;

    let session_id = random_uuid();
    let random = generate_random_bytes();
    let suffix = if irpki {".ixml"} else{".xml"};

    let base_uri = format!("{}{}/{}", "https://", domain, base_rrdp_dir.0);
    let snapshot_uri = format!(
        "{}{}/{}/{}/snapshot{}",
        &base_uri,
        &session_id,
        serial.to_string(),
        random,
        suffix
    );
    let notification_uri_l = format!("{}notification{}", base_rrdp_dir.1, suffix);
    let snapshot_uri_l = format!(
        "{}{}/{}/{}/snapshot{}",
        base_rrdp_dir.1,
        &session_id,
        serial.to_string(),
        random,
        suffix
    );

    let snap = create_snapshot(serial, &session_id, publish).unwrap();
    let snap_hash = get_hash(&snap);
    let notif =
        create_notification(serial, &session_id, (&snapshot_uri, &snap_hash), None).unwrap();

    (snapshot_uri_l, snap, notification_uri_l, notif)
}


/// Create a full RRDP State with Notification, Snapshot and Deltas. 
/// Takes multiple parameters
/// 
/// # Arguments
/// * `snap_publish`: A vector of tuples (uri, data) for elements published in the snapshot
/// * `deltas`: A vector of tuples (publishes (uri, hash, data), withdraws (uri, hash) for the deltas
/// * `previous_delta`: A vector of tuples (serial, uri, hash) for the previous deltas
/// * `start_serial`: The starting serial number for the deltas
/// * `session_id`: The session ID for the RRDP session
/// * `base_rrdp_dir`: The base directory for the RRDP files (for HTTPS URI)
/// * `base_rrdp_dir_l`: The base directory for the RRDP files (for local storage)
/// * `domain`: The domain for the RRDP server
/// 
pub fn new_added_deltas(
    snap_publish: Vec<(String, Vec<u8>)>,
    deltas: Vec<(Vec<(String, String, Vec<u8>)>, Vec<String>)>,
    previous_delta: Vec<(String, String, String)>, // Serial, uri, hash
    start_serial: u32,
    session_id: &str,
    base_rrdp_dir: &str,
    base_rrdp_dir_l: &str,
    domain: &str,
) -> (String, Vec<u8>, String, Vec<u8>, Vec<(String, Vec<u8>)>) {
    let base_uri = format!("{}{}/{}", "https://", domain, base_rrdp_dir);

    let mut parsed_deltas = vec![];
    let mut serial = start_serial;
    let mut delta_for_notification = vec![];
    for delta in deltas {
        let parsed_delta = create_delta(serial, session_id, delta.0, delta.1).unwrap();

        let random = generate_random_bytes();
        let delta_uri = format!(
            "{}{}/{}/{}/delta.xml",
            &base_uri,
            &session_id,
            serial.to_string(),
            random
        );
        let delta_hash = get_hash(&parsed_delta);
        delta_for_notification.push((serial.to_string(), delta_uri, delta_hash));

        let delta_uri_l = format!(
            "{}{}/{}/{}/delta.xml",
            base_rrdp_dir_l,
            &session_id,
            serial.to_string(),
            random
        );
        parsed_deltas.push((delta_uri_l, parsed_delta));
        serial += 1;
    }

    // Decrease the serial in the end by one to revert the last increase (for which no delta exists)
    serial -= 1;

    let random = generate_random_bytes();

    let snapshot_uri = format!(
        "{}{}/{}/{}/snapshot.xml",
        &base_uri,
        &session_id,
        serial.to_string(),
        random
    );
    let notification_uri_l = format!("{}notification.xml", base_rrdp_dir_l);
    let snapshot_uri_l = format!(
        "{}{}/{}/{}/snapshot.xml",
        base_rrdp_dir_l,
        &session_id,
        serial.to_string(),
        random
    );

    let mut all_deltas = previous_delta.clone();
    all_deltas.extend(delta_for_notification.clone());
    all_deltas.reverse();
    let snap = create_snapshot(serial, &session_id, snap_publish).unwrap();
    let snap_hash = get_hash(&snap);
    let notif = create_notification(
        serial,
        &session_id,
        (&snapshot_uri, &snap_hash),
        Some(all_deltas),
    )
    .unwrap();

    (
        snapshot_uri_l,
        snap,
        notification_uri_l,
        notif,
        parsed_deltas,
    )
}

pub fn create_snapshot(
    serial: u32,
    session_id: &str,
    publishes: Vec<(String, Vec<u8>)>,
) -> xml::writer::Result<Vec<u8>> {
    let mut output = Cursor::new(Vec::new());
    let mut writer = EmitterConfig::new()
        .perform_indent(true)
        .create_writer(&mut output);

    writer.write(
        XmlEvent::start_element("snapshot")
            .attr("xmlns", "http://www.ripe.net/rpki/rrdp")
            .attr("version", "1")
            .attr("serial", &serial.to_string())
            .attr("session_id", session_id),
    )?;

    for (uri, data) in publishes {
        writer.write(XmlEvent::start_element("publish").attr("uri", &uri))?;
        writer.write(XmlEvent::characters(&BASE64_STANDARD.encode(data)))?;
        writer.write(XmlEvent::end_element())?;
    }

    writer.write(XmlEvent::end_element())?;

    let output = output.into_inner();
    Ok(output)
}

pub fn create_notification(
    serial: u32,
    session_id: &str,
    snap_uri_hash: (&str, &str),
    deltas_serial_uri_hash: Option<Vec<(String, String, String)>>,
) -> xml::writer::Result<Vec<u8>> {
    let mut output = Cursor::new(Vec::new());
    let mut writer = EmitterConfig::new()
        .perform_indent(true)
        .create_writer(&mut output);

    writer.write(
        XmlEvent::start_element("notification")
            .attr("xmlns", "http://www.ripe.net/rpki/rrdp")
            .attr("version", "1")
            .attr("serial", &serial.to_string())
            .attr("session_id", session_id),
    )?;

    writer.write(
        XmlEvent::start_element("snapshot")
            .attr("uri", snap_uri_hash.0)
            .attr("hash", snap_uri_hash.1),
    )?;
    writer.write(XmlEvent::end_element())?;

    for (serial, uri, hash) in deltas_serial_uri_hash.unwrap_or(vec![]) {
        writer.write(
            XmlEvent::start_element("delta")
                .attr("serial", &serial)
                .attr("uri", &uri)
                .attr("hash", &hash),
        )?;
        writer.write(XmlEvent::end_element())?;
    }

    writer.write(XmlEvent::end_element())?;

    let output = output.into_inner();
    Ok(output)
}

pub fn create_delta(
    serial: u32,
    session_id: &str,
    publishes: Vec<(String, String, Vec<u8>)>,
    withdraws: Vec<String>,
) -> xml::writer::Result<Vec<u8>> {
    let mut output = Cursor::new(Vec::new());
    let mut writer = EmitterConfig::new()
        .perform_indent(true)
        .create_writer(&mut output);

    writer.write(
        XmlEvent::start_element("delta")
            .attr("xmlns", "http://www.ripe.net/rpki/rrdp")
            .attr("version", "1")
            .attr("serial", &serial.to_string())
            .attr("session_id", session_id),
    )?;

    for (uri, hash, data) in publishes {
        if hash == "" {
            writer.write(XmlEvent::start_element("publish").attr("uri", &uri))?;
        } else {
            writer.write(
                XmlEvent::start_element("publish")
                    .attr("uri", &uri)
                    .attr("hash", &hash),
            )?;
        }
        writer.write(XmlEvent::characters(&BASE64_STANDARD.encode(data)))?;
        writer.write(XmlEvent::end_element())?;
    }

    for uri in withdraws {
        writer.write(XmlEvent::start_element("withdraw").attr("uri", &uri))?;
        writer.write(XmlEvent::end_element())?;
    }

    writer.write(XmlEvent::end_element())?;

    let output = output.into_inner();
    Ok(output)
}

#[derive(Clone, Debug)]
pub struct RRDPEntry {
    pub uri: String,
    pub hash: Option<String>,
    pub data: Vec<u8>,
    pub typ: String,
    pub serial: Option<u32>,
}

/// Implement an RRDP Snapshot
pub struct XMLSnapshot {
    pub serial: u32,
    pub session_id: String,
    pub entries: Vec<RRDPEntry>,
}

impl XMLSnapshot {
    pub fn encode(&self) -> xml::writer::Result<Vec<u8>>
        {
        let mut output = Cursor::new(Vec::new());
        let mut writer = EmitterConfig::new()
            .perform_indent(true)
            .create_writer(&mut output);
    
        writer.write(
            XmlEvent::start_element("snapshot")
                .attr("xmlns", "http://www.ripe.net/rpki/rrdp")
                .attr("version", "1")
                .attr("serial", &self.serial.to_string())
                .attr("session_id", &self.session_id),
        )?;
    
        for entry in &self.entries {
                writer.write(XmlEvent::start_element("publish").attr("uri", &entry.uri))?;
             
                
            
            writer.write(XmlEvent::characters(&BASE64_STANDARD.encode(&entry.data)))?;
            writer.write(XmlEvent::end_element())?;
        }

    
        writer.write(XmlEvent::end_element())?;
    
        let output = output.into_inner();
        Ok(output)
    }


    pub fn get_entry(&self, uri: &str) -> Option<&RRDPEntry> {
        for entry in &self.entries {
            if entry.uri == uri {
                return Some(entry);
            }
        }
        return None;
    }

    /// Return all entries as a Vec of tuples (uri, data)
    pub fn get_all_entries_raw(&self) -> Vec<(String, Vec<u8>)> {
        let mut entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            entries.push((entry.uri.clone(), entry.data.clone()));
        }
        return entries;
    }

    /// Create a custom fingerprint for the snapshot for comparison between snapshots
    pub fn get_fingerprint(&self) -> String{
        let mut sorted_entries = self.entries.clone();

        sorted_entries.sort_by(|a, b| a.uri.cmp(&b.uri));

        let mut fingerprint_data = sorted_entries.iter().flat_map(|entry| {
            if entry.data.len() < 17{
                return entry.data.clone()
            }
            let mut re = entry.uri.as_bytes().to_vec();
            re.extend_from_slice(&entry.data[entry.data.len() - 16..]);
            return re;
        }).collect::<Vec<u8>>();

        fingerprint_data.extend(self.session_id.as_bytes());
        fingerprint_data.extend(&self.serial.to_be_bytes()); 

        let fingerprint = get_hash(&fingerprint_data);
        return fingerprint;
    }

    /// Apply a delta to the snapshot state.
    /// If checked is true, check if the delta is valid (serial number and session ID), hashes are correct etc.
    pub fn apply_delta(&mut self, delta: &XMLDelta, checked: bool) -> Result<(), String> {
        if checked && self.serial + 1 != delta.serial {
            return Err("Serial mismatch".to_string());
        }

        if checked && self.session_id != delta.session_id {
            return Err("Session ID mismatch".to_string());
        }

        let map = self.entries.iter().map(|entry| (entry.uri.clone(), entry.clone())).collect::<std::collections::HashMap<String, RRDPEntry>>();
        let map_delta = delta.modifies.iter().map(|entry| (entry.uri.clone(), entry.clone())).collect::<std::collections::HashMap<String, RRDPEntry>>();
        let map_withdraws = delta.withdraws.iter().map(|entry| (entry.uri.clone(), entry.clone())).collect::<std::collections::HashMap<String, RRDPEntry>>();

        for entry in &delta.publishes {
            if checked &&  map.contains_key(&entry.uri) {
                return Err(format!("URI {} already exists in snapshot", entry.uri));
            }
            self.entries.push(entry.clone());
        }

        let mut modifications = 0;
        let mut to_withdraw = vec![];
        for self_entry in &mut self.entries {
            if map_delta.contains_key(&self_entry.uri) {
                let v = map_delta.get(&self_entry.uri).unwrap();
                if checked && v.hash.clone().unwrap_or_default() != get_hash(&self_entry.data) {
                    return Err(format!("Modify: Hash mismatch for URI {}", self_entry.uri));
                }
                *self_entry = v.clone();
                modifications += 1;

            }
            else if map_withdraws.contains_key(&self_entry.uri) {
                let v = map_withdraws.get(&self_entry.uri).unwrap();
                if checked && v.hash.clone().unwrap_or_default() != get_hash(&self_entry.data) {
                    return Err(format!("Withdraw: Hash mismatch for URI {}", self_entry.uri));
                }

                to_withdraw.push(self_entry.uri.clone());
            }
        }

        for uri in &to_withdraw {
            self.entries.retain(|entry| &entry.uri != uri);
        }

        if checked && modifications != delta.modifies.len(){
            return Err(format!("Not all entries were modified {}:{}", modifications, delta.modifies.len()));
        }
        if checked && to_withdraw.len() != delta.withdraws.len(){
            return Err(format!("Not all entries were withdrawn {}:{}", to_withdraw.len(), delta.withdraws.len()));
        }

        self.serial = delta.serial;

        Ok(())
    }

    /// Apply a list of deltas to the snapshot state. Deltas are sorted by serial number.
    /// @param deltas: The list of deltas to apply
    /// @param checked: If true, check if the deltas are valid (serial number and session ID), hashes are correct etc.
    pub fn apply_deltas(&mut self, deltas: &Vec<XMLDelta>, checked: bool) -> Result<(), String> {
        let mut sorted = deltas.clone();
        sorted.sort_by(|a, b| a.serial.cmp(&b.serial));

        for delta in sorted {
            self.apply_delta(&delta, checked)?;
        }

        Ok(())
    }


    /// Compare if two Snapshots are functionally equal (not necessary same order of entries but same content)
    pub fn compare_content(&self, other: &XMLSnapshot) -> bool{
        if self.serial != other.serial || self.session_id != other.session_id || self.entries.len() != other.entries.len(){
            return false;
        }

        return self.get_fingerprint() == other.get_fingerprint();
    }
}

pub struct XMLNotification {
    pub serial: u32,
    pub session_id: String,
    pub snapshot_uri: Option<RRDPEntry>,
    pub deltas: Vec<RRDPEntry>,
}

impl XMLNotification {
    pub fn get_snapshot_uri(&self) -> Option<String> {
        if self.snapshot_uri.is_some() {
            return Some(self.snapshot_uri.clone().unwrap().uri);
        }
        return None;
    }

    /// Get the local storage location of the snapshot
    /// @param base_url: The base URL folder of the local storage
    pub fn get_snapshot_uri_local(&self, base_url: &str) -> String {
        let uri = self.get_snapshot_uri().unwrap();
        let uri = uri.replace("https://", "");
        let uri = uri.split("/").collect::<Vec<&str>>()[1..].join("/");
        let uri = format!("{}{}", base_url, uri);
        return uri;
    }


    /// Get the Deltas as a Vec of tuples (serial, uri, hash)
    pub fn get_deltas(&self) -> Vec<(String, String, String)> {
        let mut deltas = vec![];
        for delta in &self.deltas {
            deltas.push((
                delta.serial.clone().unwrap_or(0).to_string(),
                delta.uri.clone(),
                delta.hash.clone().unwrap_or("".to_string()),
            ));
        }
        return deltas;
    }

    pub fn encode(&self) -> xml::writer::Result<Vec<u8>>{
        let mut output = Cursor::new(Vec::new());
        let mut writer = EmitterConfig::new()
            .perform_indent(true)
            .create_writer(&mut output);
    
        writer.write(
            XmlEvent::start_element("notification")
                .attr("xmlns", "http://www.ripe.net/rpki/rrdp")
                .attr("version", "1")
                .attr("serial", &self.serial.to_string())
                .attr("session_id", &self.session_id),
        )?;
    
        if self.snapshot_uri.is_some() {
            let entry = self.snapshot_uri.clone().unwrap();
            writer.write(
                XmlEvent::start_element("snapshot")
                    .attr("uri", &entry.uri)
                    .attr("hash", &entry.hash.clone().unwrap()),
            )?;
            writer.write(XmlEvent::end_element())?;
        }
    
        for entry in &self.deltas {
            writer.write(
                XmlEvent::start_element("delta")
                    .attr("serial", &entry.serial.clone().unwrap_or(0).to_string())
                    .attr("uri", &entry.uri)
                    .attr("hash", &entry.hash.clone().unwrap_or("".to_string())),
            )?;
            writer.write(XmlEvent::end_element())?;
        }
    
        writer.write(XmlEvent::end_element())?;
    
        let output = output.into_inner();
        Ok(output)
    }
}

#[derive(Clone, Debug)]
pub struct XMLDelta{
    pub serial: u32,
    pub session_id: String,
    pub publishes: Vec<RRDPEntry>,
    pub modifies: Vec<RRDPEntry>,
    pub withdraws: Vec<RRDPEntry>,
}

impl XMLDelta{
    pub fn encode(&self) -> xml::writer::Result<Vec<u8>>
        {
        let mut output = Cursor::new(Vec::new());
        let mut writer = EmitterConfig::new()
            .perform_indent(true)
            .create_writer(&mut output);
    
        writer.write(
            XmlEvent::start_element("delta")
                .attr("xmlns", "http://www.ripe.net/rpki/rrdp")
                .attr("version", "1")
                .attr("serial", &self.serial.to_string())
                .attr("session_id", &self.session_id),
        )?;
    
        for entry in &self.publishes {
                writer.write(XmlEvent::start_element("publish").attr("uri", &entry.uri))?;
             
                
            
            writer.write(XmlEvent::characters(&BASE64_STANDARD.encode(&entry.data)))?;
            writer.write(XmlEvent::end_element())?;
        }

        for entry in &self.modifies{
            if entry.hash.as_ref().is_none(){
                return Err(xml::writer::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, "Hash is missing modify")));
            }
            writer.write(
                XmlEvent::start_element("publish")
                    .attr("uri", &entry.uri)
                    .attr("hash", &entry.hash.clone().unwrap()),
            )?;
        }
    
        for entry in &self.withdraws {
            if entry.hash.is_none(){
                return Err(xml::writer::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, "Hash is missing withdraw")));
            }

            writer.write(XmlEvent::start_element("withdraw").attr("uri", &entry.uri).attr("hash", &entry.hash.clone().unwrap()))?;
            writer.write(XmlEvent::end_element())?;
        }
    
        writer.write(XmlEvent::end_element())?;
    
        let output = output.into_inner();
        Ok(output)
    }

}

pub fn parse_delta(xml_data: &str) -> Option<XMLDelta>{
    return rrdp_xml::parse_rrdp_delta(xml_data).ok();
}

pub fn parse_notification(xml_data: &str) -> Option<XMLNotification> {
    return rrdp_xml::parse_rrdp_notification(xml_data).ok();

    // let root: Result<minidom::Element, _> = xml_data.parse();
    // if root.is_err() {
    //     return None;
    // }
    // let root = root.unwrap();

    // let mut snapshot = None;
    // let mut deltas = vec![];
    // for c in root.children() {
    //     if c.name() == "snapshot" {
    //         let uri = c.attr("uri").unwrap();
    //         let hash = c.attr("hash").unwrap();
    //         snapshot = Some(RRDPEntry {
    //             uri: uri.to_string(),
    //             hash: Some(hash.to_string()),
    //             data: vec![],
    //             typ: "snapshot".to_string(),
    //             serial: None,
    //         });
    //     } else {
    //         let uri = c.attr("uri").unwrap_or("none");
    //         let serial = c.attr("serial").unwrap_or("0").parse().unwrap_or(0);
    //         let hash = c.attr("hash").unwrap_or("none");

    //         let typ = c.name();
    //         let entry = RRDPEntry {
    //             uri: uri.to_string(),
    //             hash: Some(hash.to_string()),
    //             data: vec![],
    //             typ: typ.to_string(),
    //             serial: Some(serial),
    //         };
    //         deltas.push(entry);
    //     }
    // }

    // let notification = XMLNotification {
    //     serial: root.attr("serial").unwrap().parse().unwrap(),
    //     session_id: root.attr("session_id").unwrap().to_string(),
    //     snapshot_uri: snapshot,
    //     deltas,
    // };
    
    // return Some(notification);
}

pub fn parse_snapshot(xml_data: &str) -> Option<XMLSnapshot> {
    let quick_res = rrdp_xml::parse_rrdp_snapshot(xml_data).ok();
    if quick_res.is_some(){
        return quick_res;
    }

    // Quick parse failed
    println!("Info: Quick parse of snapshot failed, conducting regular parse");

    let root: Result<minidom::Element, _> = xml_data.parse();
    
    if root.is_err() {
        return None;
    }
    let root = root.unwrap();

    let mut entries = vec![];
    for c in root.children() {
        let uri = c.attr("uri").unwrap();
        let typ = c.name();
        let data_raw = c.text();
        let data_raw = data_raw.trim();
        let data_raw = data_raw.replace("\n", "");
        let data = BASE64_STANDARD.decode(data_raw).unwrap_or(vec![]);

        let entry = RRDPEntry {
            uri: uri.to_string(),
            hash: None,
            data,
            typ: typ.to_string(),
            serial: None,
        };
        entries.push(entry);
    }

    let snapshot = XMLSnapshot {
        serial: root.attr("serial").unwrap().parse().unwrap(),
        session_id: root.attr("session_id").unwrap().to_string(),
        entries,
    };

    return Some(snapshot);
}


pub fn generate_random_bytes() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    hex::encode(bytes)
}
