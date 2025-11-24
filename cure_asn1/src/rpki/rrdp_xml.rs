use std::collections::HashMap;

use crate::{rpki::rrdp::{RRDPEntry, XMLDelta, XMLNotification, XMLSnapshot}};
use base64::{Engine as _, engine::general_purpose};

fn extract_attribute(tag: &str, attr: &str) -> Option<(String, usize)> {
    let search = format!(r#"{}=""#, attr);
    tag.find(&search).and_then(|start| {
        let rest = &tag[start + search.len()..];
        rest.find('"').map(|end| (rest[..end].to_string(), start))
    })
}

use memchr::memchr;

pub fn parse_rrdp_snapshot(xml: &str) -> Result<XMLSnapshot, &'static str> {
    let snapshot_start = xml.find("<snapshot")
        .ok_or("Missing <snapshot> tag")?;
    
    let snapshot_bytes = xml.as_bytes();
    let snapshot_end_rel = memchr(b'>', &snapshot_bytes[snapshot_start..])
        .ok_or("Malformed <snapshot> tag")?;
    let snapshot_end = snapshot_start + snapshot_end_rel;

    let snapshot_tag = &xml[snapshot_start..=snapshot_end];

    let session_id = extract_attribute(snapshot_tag, "session_id")
        .ok_or("Missing session_id")?.0;
    let serial_str = extract_attribute(snapshot_tag, "serial")
        .ok_or("Missing serial")?.0;
    let serial = serial_str.parse::<u32>().map_err(|_| "Invalid serial")?;

    let mut entries = vec![]; // Guess or count beforehand if you can
    let mut pos = snapshot_end + 1;
    let xml_bytes = xml.as_bytes();
    let close_tag = b"</publish>";
    let publish_tag = b"<publish";

    while let Some(start_rel) = twoway::find_bytes(&xml_bytes[pos..], publish_tag) {
        let abs_start = pos + start_rel;

        let tag_end_rel = memchr(b'>', &xml_bytes[abs_start..])
            .ok_or("Malformed <publish>")?;
        let tag_end = abs_start + tag_end_rel;
        let tag_str = &xml[abs_start..=tag_end];

        let uri = extract_attribute(tag_str, "uri").ok_or("Missing uri")?.0;
        let hash_t = extract_attribute(tag_str, "hash");
        let hash;
        if hash_t.is_some(){
            hash = Some(hash_t.unwrap().0);
        } else {
            hash = None;
        }

        let close_pos_rel = twoway::find_bytes(&xml_bytes[tag_end + 200..], close_tag)
            .ok_or("Missing </publish>")?;
        let close_pos = tag_end + 200 + close_pos_rel;

        let base64_data = &xml[tag_end + 1..close_pos];
        let data = general_purpose::STANDARD.decode(base64_data.trim()).map_err(|_| "Base64 decode failed")?;

        entries.push(RRDPEntry {
            uri,
            hash,
            data,
            typ: "publish".into(),
            serial: None,
        });

        pos = close_pos + close_tag.len();
    }

    Ok(XMLSnapshot {
        session_id,
        serial,
        entries,
    })
}


pub fn parse_rrdp_delta(xml: &str) -> Result<XMLDelta, String> {
    let delta_start = xml.find("<delta").ok_or("Missing <delta> tag")?;
    let delta_end = xml[delta_start..].find('>').ok_or("Malformed <delta> tag")? + delta_start;

    let delta_tag = &xml[delta_start..=delta_end];

    let session_id = extract_attribute(delta_tag, "session_id").ok_or("Missing session_id")?.0;
    let serial_str = extract_attribute(delta_tag, "serial").ok_or("Missing serial")?.0;
    let serial = serial_str.parse::<u32>().map_err(|_| "Invalid serial")?;

    let mut publishes = Vec::new();
    let mut modifies = Vec::new();
    let mut withdraws = Vec::new();

    let mut pos = delta_end + 1;

    while pos < xml.len() {
        if let Some(start) = xml[pos..].find('<') {
            let tag_start = pos + start;
            if xml[tag_start..].starts_with("<publish") {
                let tag_end = xml[tag_start..].find('>').ok_or("Malformed <publish>")? + tag_start;
                let tag_str = &xml[tag_start..=tag_end];
                let uri = extract_attribute(tag_str, "uri").ok_or("Missing uri in publish")?.0;
                let hash_t = extract_attribute(tag_str, "hash");
                let hash;
                if hash_t.is_some(){
                    hash = Some(hash_t.unwrap().0);
                } else {
                    hash = None;
                }
        
                let close_tag = "</publish>";
                let close_pos = xml[tag_end + 1..].find(close_tag)
                    .ok_or("Missing </publish>")? + tag_end + 1;

                let base64_data = &xml[tag_end + 1..close_pos];

                let base64_data = base64_data.replace("\n", "");
                let data = general_purpose::STANDARD.decode(base64_data.trim()).map_err(|_| "Base64 decode failed")?;

                let entry = RRDPEntry {
                    uri: uri.clone(),
                    hash,
                    data,
                    typ: "publish".to_string(),
                    serial: Some(serial),
                };

                if entry.hash.is_some() {
                    modifies.push(entry);
                } else {
                    publishes.push(entry);
                }

                pos = close_pos + "</publish>".len();
            } else if xml[tag_start..].starts_with("<withdraw") {
                let tag_end = xml[tag_start..].find("/>").ok_or("Malformed <withdraw/>")? + tag_start;
                let tag_str = &xml[tag_start..=tag_end];
                let uri = extract_attribute(tag_str, "uri").ok_or("Missing uri in withdraw")?.0;
                let hash = extract_attribute(tag_str, "hash").ok_or("Missing hash in withdraw")?.0;

                let entry = RRDPEntry {
                    uri,
                    hash: Some(hash),
                    data: Vec::new(),
                    typ: "withdraw".to_string(),
                    serial: Some(serial),
                };

                withdraws.push(entry);
                pos = tag_end + 2;
            } else {
                break; // stop at unknown tag
            }
        } else {
            break;
        }
    }

    Ok(XMLDelta {
        session_id,
        serial,
        publishes,
        modifies,
        withdraws,
    })
}


pub fn parse_rrdp_notification(xml: &str) -> Result<XMLNotification, &'static str> {
    let notif_start = xml.find("<notification")
        .ok_or("Missing <notification> tag")?;
    
    let notif_bytes = xml.as_bytes();
    let notif_end_rel = memchr(b'>', &notif_bytes[notif_start..])
        .ok_or("Malformed <notification> tag")?;
    let notif_end = notif_start + notif_end_rel;

    let notif_tag = &xml[notif_start..=notif_end];

    let session_id = extract_attribute(notif_tag, "session_id")
        .ok_or("Missing session_id")?.0;
    let serial_str = extract_attribute(notif_tag, "serial")
        .ok_or("Missing serial")?.0;
    let serial = serial_str.parse::<u32>().map_err(|_| "Invalid serial")?;

    // Extract snapshot URI + hash
    let snapshot_start = xml[notif_end + 1..]
        .find("<snapshot").ok_or("Missing <snapshot> tag")? + notif_end + 1;
    let snapshot_end_rel = memchr(b'>', &notif_bytes[snapshot_start..])
        .ok_or("Malformed <snapshot> tag")?;
    let snapshot_end = snapshot_start + snapshot_end_rel;
    let snapshot_tag = &xml[snapshot_start..=snapshot_end];

    let snapshot_uri = extract_attribute(snapshot_tag, "uri")
        .ok_or("Missing snapshot uri")?.0;
    let snapshot_hash = extract_attribute(snapshot_tag, "hash")
        .ok_or("Missing snapshot hash")?.0;

    // Parse deltas
    let mut deltas = vec![];
    let mut pos = snapshot_end + 1;
    let delta_tag = b"<delta";
    while let Some(start_rel) = twoway::find_bytes(&notif_bytes[pos..], delta_tag) {
        let abs_start = pos + start_rel;

        let tag_end_rel = memchr(b'>', &notif_bytes[abs_start..])
            .ok_or("Malformed <delta> tag")?;
        let tag_end = abs_start + tag_end_rel;
        let tag_str = &xml[abs_start..=tag_end];

        let uri = extract_attribute(tag_str, "uri").ok_or("Missing delta uri")?.0;
        let hash = extract_attribute(tag_str, "hash").ok_or("Missing delta hash")?.0;
        let serial_str = extract_attribute(tag_str, "serial").ok_or("Missing delta serial")?.0;
        let delta_serial = serial_str.parse::<u32>().map_err(|_| "Invalid delta serial")?;

        deltas.push(RRDPEntry {
            uri,
            hash: Some(hash),
            data: Vec::new(),
            serial: Some(delta_serial),
            typ: "delta".to_string(),
        });

        pos = tag_end + 1;
    }

    Ok(XMLNotification {
        session_id,
        serial,
        snapshot_uri: Some(RRDPEntry {
            uri: snapshot_uri,
            hash: Some(snapshot_hash),
            data: Vec::new(),
            typ: "snapshot".to_string(),
            serial: Some(serial),
        }),
        deltas,
    })
}

#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub struct NotificationReport{
    pub uri: String,
    pub mappings: HashMap<String, Vec<usize>>,
    pub results: HashMap<usize, NotificationAnalysis>,
}

impl NotificationReport{
    pub fn from_result(result: HashMap<NotificationAnalysis, Vec<String>>, base_uri: String) -> Self {
        let mut mappings = HashMap::new();
        let mut results = HashMap::new();

        let mut i = 0;
        for (key, value) in result {
            for v in &value {
                let entry = mappings.entry(v.clone()).or_insert(vec![]);
                entry.push(i);
            };
            results.insert(i, key);
            i += 1;
        }

        NotificationReport {
            uri: base_uri,
            mappings,
            results,
        }
    }
}


#[derive(Debug, PartialEq, Eq, Clone, Hash, serde::Serialize, serde::Deserialize)]
pub struct NotificationAnalysis{
    pub header_order: Vec<String>,
    pub notification_name: String,
    pub snapshot_name: String,
    pub hash_cap: bool,
    pub delta_order: bool,
    pub randomness_in_uri: bool
}

impl NotificationAnalysis{
    pub fn diff(&self, other: &NotificationAnalysis) -> Vec<String>{
        let mut ret = vec![];
        if self.header_order != other.header_order{
            for (part1, part2) in self.header_order.iter().zip(other.header_order.iter()) {
                if part1 != part2 {
                    ret.push(format!("{} [{:?}]", "Header Order", self.header_order));
                    break;
                }
            }
        }
        if self.notification_name != other.notification_name{
            ret.push(format!("{} [{}]", "Notification Name", self.notification_name));
        }

        if self.snapshot_name != other.snapshot_name{
            ret.push(format!("{} [{}]", "Snapshot Name", self.snapshot_name));
        }

        if self.hash_cap != other.hash_cap{
            ret.push(format!("{} [{}]", "Hash Cap", self.hash_cap));
        }

        if self.delta_order != other.delta_order{
            ret.push(format!("{} [{}]", "Delta Order", self.delta_order));

        }

        if self.randomness_in_uri != other.randomness_in_uri{
            ret.push(format!("{} [{}]", "Random URI", self.randomness_in_uri));
        }

        ret

    }
}





pub fn compare_uris_for_random(uri1: &str, uri2: &str) -> bool {
    let uri1_parts = uri1.split('/').collect::<Vec<&str>>();
    // let uri1_parts = uri1_parts[..uri1_parts.len()-1].to_vec();

    let uri2_parts = uri2.split('/').collect::<Vec<&str>>();
    // let uri2_parts = uri2_parts[..uri2_parts.len()-1].to_vec();

    if uri1_parts.len() != uri2_parts.len() {
        return true; // Different number of parts
    }

    for (part1, part2) in uri1_parts.iter().zip(uri2_parts.iter()) {
        if part1 != part2 {
            let prefix_len = part1.chars()
            .zip(part2.chars())
            .take_while(|(c1, c2)| c1 == c2)
            .count();
    
            let mut suffix1 = &part1[prefix_len..];
            let mut suffix2 = &part2[prefix_len..];
        
            if suffix1.contains("."){
                suffix1 = suffix1.split(".").collect::<Vec<&str>>().first().unwrap();
            }

            if suffix2.contains("."){
                suffix2 = suffix2.split(".").collect::<Vec<&str>>().first().unwrap();
            }

            // Try to parse both suffixes as integers
            let n1 = suffix1.parse::<i32>();
            let n2 = suffix2.parse::<i32>();
        
            match (n1, n2) {
                (Ok(n1), Ok(n2)) => {
                    // Sufficiently different
                    if (n2 - n1).abs() > 500 {
                        return true;
                    } else {
                        continue;
                    }
                }
                _ => return true,
            }
        }
    }

    false // All parts are the same
}


pub fn notification_analysis(xml: &str, fname: &str) -> Result<NotificationAnalysis, String> {
    let notif_start = xml.find("<notification")
        .ok_or("Missing <notification> tag")?;
    
    let notif_bytes = xml.as_bytes();
    let notif_end_rel = memchr(b'>', &notif_bytes[notif_start..])
        .ok_or("Malformed <notification> tag")?;
    let notif_end = notif_start + notif_end_rel;

    let notif_tag = &xml[notif_start..=notif_end];



    // Order of attributes in header
    let version = ("version".to_string(), extract_attribute(notif_tag, "version")
        .ok_or("Missing session_id")?.1);

    let session_id =  ("session".to_string(), extract_attribute(notif_tag, "session_id")
        .ok_or("Missing session_id")?.1);
    let serial_str =  ("serial".to_string(), extract_attribute(notif_tag, "serial")
        .ok_or("Missing serial")?.1);


    let mut v = vec![version, session_id, serial_str];
    v.sort_by(|a, b| a.1.cmp(&b.1));

    let v = v.iter().map(|x| x.0.clone()).collect::<Vec<String>>();

    // File Name Notification
    let notification_name = fname.split("_").collect::<Vec<&str>>().last().unwrap().to_string();


    let snapshot_start = xml[notif_end + 1..]
        .find("<snapshot").ok_or("Missing <snapshot> tag")? + notif_end + 1;
    let snapshot_end_rel = memchr(b'>', &notif_bytes[snapshot_start..])
        .ok_or("Malformed <snapshot> tag")?;
    let snapshot_end = snapshot_start + snapshot_end_rel;
    let snapshot_tag = &xml[snapshot_start..=snapshot_end];

    let snapshot_uri = extract_attribute(snapshot_tag, "uri")
        .ok_or("Missing snapshot uri")?.0;
    let snapshot_hash = extract_attribute(snapshot_tag, "hash")
        .ok_or("Missing snapshot hash")?.0;

    // Snapshot name
    let mut snapshot_name = snapshot_uri.split("/").collect::<Vec<&str>>().last().unwrap().to_string();
    if snapshot_name.replace(".xml", "").parse::<u64>().is_ok(){
        snapshot_name = "number-snapshot".to_string();
    }

    // Hash capitlized
    let is_cap = snapshot_hash.to_string().to_uppercase() == snapshot_hash.to_string();




    // Parse deltas
    let mut deltas = vec![];
    let mut pos = snapshot_end + 1;
    let delta_tag = b"<delta";
    while let Some(start_rel) = twoway::find_bytes(&notif_bytes[pos..], delta_tag) {
        let abs_start = pos + start_rel;

        let tag_end_rel = memchr(b'>', &notif_bytes[abs_start..])
            .ok_or("Malformed <delta> tag")?;
        let tag_end = abs_start + tag_end_rel;
        let tag_str = &xml[abs_start..=tag_end];

        let uri = extract_attribute(tag_str, "uri").ok_or("Missing delta uri")?.0;
        let hash = extract_attribute(tag_str, "hash").ok_or("Missing delta hash")?.0;
        let serial_str = extract_attribute(tag_str, "serial").ok_or("Missing delta serial")?.0;
        let delta_serial = serial_str.parse::<u32>().map_err(|_| "Invalid delta serial")?;

        deltas.push(RRDPEntry {
            uri,
            hash: Some(hash),
            data: Vec::new(),
            serial: Some(delta_serial),
            typ: "delta".to_string(),
        });

        pos = tag_end + 1;
    }

    // Delta order
    let delta_order;
    let randomness_in_uri;
    if deltas.len() > 1{
        delta_order = deltas[0].serial.unwrap() > deltas[1].serial.unwrap();
        randomness_in_uri = compare_uris_for_random(&deltas[0].uri, &deltas[1].uri)
    }
    else{
        delta_order = true;
        randomness_in_uri = true;
    }

    Ok(NotificationAnalysis{
        header_order: v,
        notification_name: notification_name.to_string(),
        snapshot_name,
        hash_cap: is_cap,
        delta_order,
        randomness_in_uri,
    })

}


