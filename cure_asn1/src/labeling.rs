/// Label an ASN.1 syntax tree. Currently only RPKI labels are supported, which includes most X.509 certificate extensions.


use std::collections::HashMap;

use crate::tree_parser::{Tree, Types};

pub fn parse_oid(data: &Vec<u8>) -> String {
    let mut oid = String::new();

    if data.is_empty() {
        return oid;
    }

    // Handle the first byte: first two OID components
    let first_byte = data[0];
    oid.push_str(&format!("{}.", first_byte / 40));
    oid.push_str(&format!("{}", first_byte % 40));

    let mut value = 0u32;
    for &byte in &data[1..] {
        value = (value << 7) | (byte & 0x7F) as u32;
        if (byte & 0x80) == 0 {
            oid.push_str(&format!(".{}", value));
            value = 0;
        }
    }

    oid
}

#[derive(Clone, Debug)]
pub struct LabelInfo {
    pub optional_child: Option<usize>,
    pub repeating_labels: bool,
}

impl LabelInfo {
    pub fn new(repeating_labels: bool) -> LabelInfo {
        LabelInfo {
            optional_child: None,
            repeating_labels,
        }
    }
}

/// The functions generate dynamic labels for fields that are not statically defined.
fn label_fn_encoded_content<'a>(id: usize, tree: &Tree) -> LabelObject {
    let children = label_enc_content_inner(&tree.obj_type);
    let c = &tree.get_node(id).unwrap().children;

    // No children or not a nested octetstring -> Just return normal
    if c.len() == 0 || tree.get_node(c[0]).unwrap().tag != Types::OctetString {
        return LabelObject::new(Some("eContentOuterOctet".to_string()), children);
    }

    let inner_oc = LabelObject::new(Some("eContentInnerOctet".to_string()), children);
    let outer = LabelObject::new(Some("eContentOuterOctet".to_string()), vec![inner_oc]);
    outer
}

fn label_fn_signed_attrs<'a>(id: usize, tree: &Tree) -> LabelObject {
    let mut labels = Vec::new();

    let signed_attrs_map = label_signed_attributes_rpki();

    for child_id in &tree.get_node(id).unwrap().children {
        let child = tree.get_node(*child_id).unwrap();
        if child.children.len() == 0 {
            continue;
        }
        let oid = parse_oid(&tree.get_node(child.children[0]).unwrap().data);
        if signed_attrs_map.contains_key(&oid.as_str()) {
            let label_obj = signed_attrs_map.get(&oid.as_str()).unwrap();
            labels.push(label_obj.clone());
        } else {
            println!("Unknown Extension OID: {}", oid);
            labels.push(LabelObject::new(None, vec![]));
        }
    }
    LabelObject::new(Some("signerSignedAttributesField".to_string()), labels)
}

fn label_fn_extensions<'a>(id: usize, tree: &Tree) -> LabelObject {
    let mut labels = Vec::new();

    let ext_map = label_extensions_rpki();

    for child_id in &tree.get_node(id).unwrap().children {
        let child = tree.get_node(*child_id).unwrap();
        if child.children.len() == 0 {
            continue;
        }
        let oid = parse_oid(&tree.get_node(child.children[0]).unwrap().data);
        if ext_map.contains_key(&oid.as_str()) {
            let label_obj = ext_map.get(&oid.as_str()).unwrap();
            labels.push(label_obj.clone());
        } else {
            println!("Unknown Extension OID: {}", oid);
            labels.push(LabelObject::new(None, vec![]));
        }
    }
    LabelObject::new(Some("extensions".to_string()), labels)
}

fn label_fn_subject_info<'a>(id: usize, tree: &Tree) -> LabelObject {
    let mut labels = Vec::new();

    let ext_map = label_extension_subject_info();

    for child_id in &tree.get_node(id).unwrap().children {
        let child = tree.get_node(*child_id).unwrap();
        if child.children.len() == 0 {
            continue;
        }
        let oid = parse_oid(&tree.get_node(child.children[0]).unwrap().data);
        if ext_map.contains_key(&oid.as_str()) {
            let label_obj = ext_map.get(&oid.as_str()).unwrap();
            labels.push(label_obj.clone());
        } else {
            println!("Unknown Extension OID: {}", oid);
            labels.push(LabelObject::new(None, vec![]));
        }
    }
    LabelObject::new(Some("subjectInfoAccessSeq".to_string()), labels)
}


fn label_fn_roa_ip_seq<'a>(id: usize, tree: &Tree) -> LabelObject {
    let mut labels = Vec::new();

    if tree.get_node(id).unwrap().children.len() < 2 {
        return LabelObject::new(Some("encapsulatedContent".to_string()), vec![]);
    }

    let as_id = LabelObject::new(Some("asID".to_string()), vec![]);

    for child_id in &tree.get_node(tree.get_node(id).unwrap().children[1]).unwrap().children {

        let child = tree.get_node(*child_id).unwrap();

        if child.children.len() != 2 {
            continue;
        }
        let ip_afi = child.children[0];

        let ip_addresses = child.children[1];
        let suffix;
        if tree.get_node(ip_afi).unwrap().data == vec![0, 1]{
            suffix = "v4";
        }
        else{
            suffix = "v6";
        }

        let ip_afi_l = LabelObject::new(Some(format!("ipAFI{}", suffix)), vec![]);

        let mut ip_counter = 0;
        let mut child_labels = vec![];

        for ip_val in &tree.get_node(ip_addresses).unwrap().children{
            let ip_node = tree.get_node(*ip_val).unwrap();
            let ip = format!("ipAddrBlock{}_{}", suffix, ip_counter);

            let mut ip_labels = vec![];
            
            let lab = format!("ipAddr{}_{}", suffix, ip_counter);
            let label_ml = format!("ipMl{}_{}", suffix, ip_counter);


            if ip_node.children.len() == 1{
                ip_labels.push(LabelObject::new(Some(lab), vec![]));
            }
            else{
                ip_labels.push(LabelObject::new(Some(lab), vec![]));

                ip_labels.push(LabelObject::new(Some(label_ml), vec![]));
            }

            child_labels.push(LabelObject::new(Some(ip), ip_labels));
            ip_counter += 1;
        }
        
        let la = LabelObject::new(Some(format!("ipAddrBlocks{}", suffix)), child_labels);
        let afi_and_ips = LabelObject::new(Some(format!("ipAddrBlocks{}Seq", suffix)), vec![ip_afi_l, la]);

        labels.push(afi_and_ips);
    }

    if tree.get_node(id).unwrap().children.len() > 2{
        return LabelObject::new(Some("encapsulatedContent".to_string()), vec![as_id, LabelObject::new(Some("ipAddrBlocks".to_string()), labels), label_rpki_info()])
    }

    LabelObject::new(Some("encapsulatedContent".to_string()), vec![as_id, LabelObject::new(Some("ipAddrBlocks".to_string()), labels)])
}

fn label_fn_mft<'a>(id: usize, tree: &Tree) -> LabelObject {
    let manifest_number = LabelObject::new(Some("manifestNumber".to_string()), vec![]);

    let this_update = LabelObject::new(Some("thisUpdate".to_string()), vec![]);

    let next_update = LabelObject::new(Some("nextUpdate".to_string()), vec![]);

    let hash_algo = LabelObject::new(Some("manifestHashAlgorithm".to_string()), vec![]);

    let last = tree.get_node(id).unwrap().children.last();
    if last.is_none(){
        return LabelObject::new(Some("encapsulatedContent".to_string()), vec![manifest_number, this_update, next_update, hash_algo]);
    }
    

    let mut val_counter = 0;
    let mut entries = vec![];
    for child_id in &tree.get_node(*last.unwrap()).unwrap().children {
        let child = tree.get_node(*child_id).unwrap();
        if child.children.len() != 2 {
            continue;
        }
        let name_label = LabelObject::new(Some(format!("mftHashName_{}", val_counter)), vec![]);
        let hash_label = LabelObject::new(Some(format!("mftHashValue_{}", val_counter)), vec![]);
        val_counter += 1;
        let entry = LabelObject::new(Some(format!("mftEntry_{}", val_counter)), vec![name_label, hash_label]);
        entries.push(entry);
    }
    let hashes = LabelObject::new(Some("manifestHashes".to_string()), entries);
    let enc;
    if tree.obj_type == "imft"{
        let crl_entries = LabelObject::new(Some("crlEntriesField".to_string()), vec![LabelObject::new(Some("crlEntries".to_string()), vec![])]);

        enc = LabelObject::new(Some("encapsulatedContent".to_string()), vec![manifest_number, this_update, next_update, hash_algo, hashes, crl_entries]);
    }
    else{
        enc = LabelObject::new(Some("encapsulatedContent".to_string()), vec![manifest_number, this_update, next_update, hash_algo, hashes]);
    } 
    enc
    
}

#[derive(Clone, Debug)]
pub struct LabelObject {
    pub label: Option<String>,
    pub label_info: Option<LabelInfo>,
    pub children: Vec<LabelObject>,
    pub label_function: Option<fn(usize, &Tree) -> LabelObject>,
}

impl<'a> LabelObject {
    pub fn new(label: Option<String>, children: Vec<LabelObject>) -> LabelObject {
        LabelObject {
            label,
            label_info: None,
            children,
            label_function: None,
        }
    }
}

pub fn label_extension_subject_info() -> HashMap<&'static str, LabelObject> {
    let ca_repo_ext = LabelObject::new(
        Some("caRepositoryURIExt".to_string()),
        vec![
            LabelObject::new(Some("caRepositoryExtID".to_string()), vec![]),
            LabelObject::new(Some("caRepositoryURI".to_string()), vec![]),
        ],
    );

    let manifest_uri = LabelObject::new(
        Some("rpkiManifestExt".to_string()),
        vec![
            LabelObject::new(Some("rpkiManifestExtID".to_string()), vec![]),
            LabelObject::new(Some("rpkiManifestURI".to_string()), vec![]),
        ],
    );

    let notification_uri = LabelObject::new(
        Some("rpkiNotifyExt".to_string()),
        vec![
            LabelObject::new(Some("rpkiNotifyExtID".to_string()), vec![]),
            LabelObject::new(Some("rpkiNotifyURI".to_string()), vec![]),
        ],
    );

    let signed_object_uri = LabelObject::new(
        Some("signedObjectExt".to_string()),
        vec![
            LabelObject::new(Some("signedObjectExtID".to_string()), vec![]),
            LabelObject::new(Some("signedObjectURI".to_string()), vec![]),
        ],
    );

    let mut map = HashMap::new();
    map.insert("1.3.6.1.5.5.7.48.5", ca_repo_ext);
    map.insert("1.3.6.1.5.5.7.48.10", manifest_uri);
    map.insert("1.3.6.1.5.5.7.48.13", notification_uri);
    map.insert("1.3.6.1.5.5.7.48.11", signed_object_uri);

    map
}

pub fn label_extensions_rpki() -> HashMap<&'static str, LabelObject> {
    let basic_constaints = LabelObject::new(
        Some("basicConstraintsExt".to_string()),
        vec![
            LabelObject::new(Some("basicConstraintsExtID".to_string()), vec![]),
            LabelObject::new(Some("basicConstraintsCritc".to_string()), vec![]),
            LabelObject::new(
                Some("basicConstraintsOctetString".to_string()),
                vec![LabelObject::new(
                    Some("basicConstraintsSeq".to_string()),
                    vec![LabelObject::new(Some("basicConstraintsCA".to_string()), vec![])],
                )],
            ),
        ],
    );

    let subject_key_identifier = LabelObject::new(
        Some("subjectKeyIdentifierExt".to_string()),
        vec![
            LabelObject::new(Some("subjectKeyIdentifierExtID".to_string()), vec![]),
            LabelObject::new(
                Some("subjectKeyIdentifierOctetstring".to_string()),
                vec![LabelObject::new(Some("subjectKeyIdentifier".to_string()), vec![])],
            ),
        ],
    );

    let authority_key_identifier = LabelObject::new(
        Some("authorityKeyIdentifierExt".to_string()),
        vec![
            LabelObject::new(Some("authorityKeyIdentifierExtID".to_string()), vec![]),
            LabelObject::new(
                Some("authorityKeyIdentifierOctetstring".to_string()),
                vec![LabelObject::new(
                    Some("authorityKeyIdentifierSeq".to_string()),
                    vec![LabelObject::new(Some("authorityKeyIdentifier".to_string()), vec![])],
                )],
            ),
        ],
    );

    let key_usage = LabelObject::new(
        Some("keyUsageExt".to_string()),
        vec![
            LabelObject::new(Some("keyUsageExtExtID".to_string()), vec![]),
            LabelObject::new(Some("keyUsageCritc".to_string()), vec![]),
            LabelObject::new(
                Some("keyUsageOctetString".to_string()),
                vec![LabelObject::new(Some("keyUsageBitstring".to_string()), vec![])],
            ),
        ],
    );

    let crl_distribution_points = LabelObject::new(
        Some("crlDistributionPointsExt".to_string()),
        vec![
            LabelObject::new(Some("crlDistributionPointsExtID".to_string()), vec![]),
            LabelObject::new(
                Some("crlDistributionPointsOctetString".to_string()),
                vec![LabelObject::new(
                    Some("crlDistributionPointsSeq".to_string()),
                    vec![LabelObject::new(
                        Some("crlDistributionPointsSeq2".to_string()),
                        vec![LabelObject::new(
                            Some("crlDistributionPointsSeq3".to_string()),
                            vec![LabelObject::new(
                                Some("crlDistributionPointsSeq4".to_string()),
                                vec![LabelObject::new(Some("crlDistributionPoint".to_string()), vec![])],
                            )],
                        )],
                    )],
                )],
            ),
        ],
    );

    let authority_info_access = LabelObject::new(
        Some("authorityInfoAccessExt".to_string()),
        vec![
            LabelObject::new(Some("authorityInfoAccessExtID".to_string()), vec![]),
            LabelObject::new(
                Some("authorityInfoAccessOctetString".to_string()),
                vec![LabelObject::new(
                    Some("authorityInfoAccessSeq".to_string()),
                    vec![LabelObject::new(
                        Some("authorityInfoAccessSeq2".to_string()),
                        vec![
                            LabelObject::new(Some("caIssuersOID".to_string()), vec![]),
                            LabelObject::new(Some("caIssuersURI".to_string()), vec![]),
                        ],
                    )],
                )],
            ),
        ],
    );

    let subject_info_acc_seq = LabelObject {
        label: Some("subjectInfoAccessSeq".to_string()),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_subject_info),
    };

    let subject_info_access = LabelObject::new(
        Some("subjectInfoAccessExt".to_string()),
        vec![
            LabelObject::new(Some("subjectInfoAccessExtID".to_string()), vec![]),
            LabelObject::new(Some("subjectInfoAccessOctetString".to_string()), vec![subject_info_acc_seq]),
        ],
    );

    let certificate_policies = LabelObject::new(
        Some("certificatePoliciesExt".to_string()),
        vec![
            LabelObject::new(Some("certificatePoliciesExtID".to_string()), vec![]),
            LabelObject::new(Some("certificatePoliciesCritc".to_string()), vec![]),
            LabelObject::new(
                Some("certificatePoliciesOctetString".to_string()),
                vec![LabelObject::new(
                    Some("certificatePoliciesSeq".to_string()),
                    vec![LabelObject::new(
                        Some("certificatePoliciesSeq2".to_string()),
                        vec![LabelObject::new(
                            Some("certificatePolicyOID".to_string()),
                            vec![
                                LabelObject::new(Some("certificatePolicyQualifier".to_string()), vec![]),
                                LabelObject::new(Some("certificatePolicy".to_string()), vec![]),
                            ],
                        )],
                    )],
                )],
            ),
        ],
    );

    let ip_addr_blocks = LabelObject::new(
        Some("ipAddrBlocksExt".to_string()),
        vec![
            LabelObject::new(Some("ipAddrBlocksExtID".to_string()), vec![]),
            LabelObject::new(Some("ipAddrBlocksCritc".to_string()), vec![]),
            LabelObject::new(
                Some("ipAddrBlocksOctetString".to_string()),
                vec![LabelObject::new(
                    Some("ipAddrBlocksSequence".to_string()),
                    vec![LabelObject::new(
                        Some("ipAddrBlocksInnerSeq".to_string()),
                        vec![
                            LabelObject::new(Some("ipAddrBlockFamily".to_string()), vec![]),
                            LabelObject::new(
                                Some("ipAddrBlockDataSeq".to_string()),
                                vec![
                                    LabelObject::new(Some("ipAddrBlockMin".to_string()), vec![]),
                                    LabelObject::new(Some("ipAddrBlockMax".to_string()), vec![]),
                                ],
                            ),
                        ],
                    )],
                )],
            ),
        ],
    );

    let autonomous_system_ids = LabelObject::new(
        Some("autonomousSystemIdsExt".to_string()),
        vec![
            LabelObject::new(Some("autonomousSystemIdsExtID".to_string()), vec![]),
            LabelObject::new(Some("autonomousSystemIdsCritc".to_string()), vec![]),
            LabelObject::new(
                Some("autonomousSystemIdsOctetString".to_string()),
                vec![LabelObject::new(Some("autonomousSystemIdsSequence".to_string()), vec![])],
            ),
        ],
    );

    let crl_numbers = LabelObject::new(
        Some("crlNumbersExt".to_string()),
        vec![
            LabelObject::new(Some("crlNumbersExtID".to_string()), vec![]),
            LabelObject::new(Some("crlNumbersOctetString".to_string()), vec![LabelObject::new(Some("crlNumber".to_string()), vec![])]),
        ],
    );

    let mut map = HashMap::new();

    map.insert("2.5.29.19", basic_constaints);
    map.insert("2.5.29.14", subject_key_identifier);
    map.insert("2.5.29.35", authority_key_identifier);
    map.insert("2.5.29.15", key_usage);
    map.insert("2.5.29.31", crl_distribution_points);
    map.insert("1.3.6.1.5.5.7.1.1", authority_info_access);
    map.insert("1.3.6.1.5.5.7.1.11", subject_info_access);
    map.insert("2.5.29.32", certificate_policies);
    map.insert("1.3.6.1.5.5.7.1.7", ip_addr_blocks);
    map.insert("1.3.6.1.5.5.7.1.8", autonomous_system_ids);
    map.insert("2.5.29.20", crl_numbers);

    map
}

// Assuming typ == "crl"
pub fn label_empty_crl() -> LabelObject {
    let serial = LabelObject::new(Some("serialNumber".to_string()), vec![]);

    let sig_alg_id = LabelObject::new(
        Some("signatureAlgorithmField".to_string()),
        vec![
            LabelObject::new(Some("certificateSignatureAlgorithm".to_string()), vec![]),
            LabelObject::new(Some("certificateSignatureAlgorithmParameters".to_string()), vec![]),
        ],
    );

    let issuer = LabelObject::new(
        Some("issuerField".to_string()),
        vec![LabelObject::new(
            Some("issuerFieldSet".to_string()),
            vec![LabelObject::new(
                Some("issuerFieldElement".to_string()),
                vec![
                    LabelObject::new(Some("issuerOid".to_string()), vec![]),
                    LabelObject::new(Some("issuerName".to_string()), vec![]),
                ],
            ),
            LabelObject::new(
                Some("issuerFieldElement1".to_string()),
                vec![
                    LabelObject::new(Some("issuerOid1".to_string()), vec![]),
                    LabelObject::new(Some("issuerName1".to_string()), vec![]),
                ],
            ),
            LabelObject::new(
                Some("issuerFieldElement2".to_string()),
                vec![
                    LabelObject::new(Some("issuerOid2".to_string()), vec![]),
                    LabelObject::new(Some("issuerName2".to_string()), vec![]),
                ],
            )],
        ),
        LabelObject::new(
            Some("issuerFieldSet1".to_string()),
            vec![LabelObject::new(
                Some("issuerFieldElement3".to_string()),
                vec![
                    LabelObject::new(Some("issuerOid3".to_string()), vec![]),
                    LabelObject::new(Some("issuerName3".to_string()), vec![]),
                ],
            )]),
            LabelObject::new(
            Some("issuerFieldSet2".to_string()),
            vec![LabelObject::new(
                Some("issuerFieldElement4".to_string()),
                vec![
                    LabelObject::new(Some("issuerOid4".to_string()), vec![]),
                    LabelObject::new(Some("issuerName4".to_string()), vec![]),
                ],
            )])],
    );

    let ext = LabelObject {
        label: Some("extensions".to_string()),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_extensions),
    };

    let extensions = LabelObject::new(Some("extensionsField".to_string()), vec![ext]);
    let certificate = {
        LabelObject::new(
            Some("certificate".to_string()),
            vec![
                serial,
                sig_alg_id,
                issuer,
                LabelObject::new(Some("notBefore".to_string()), vec![]),
                LabelObject::new(Some("notAfter".to_string()), vec![]),
                extensions,
            ],
        )
    };

    let cert_choices = LabelObject::new(
        Some("certificateChoices".to_string()),
        vec![
            certificate,
            LabelObject::new(
                Some("certificateSignatureAlgorithm".to_string()),
                vec![
                    LabelObject::new(Some("certificateSignatureAlgorithmOid".to_string()), vec![]),
                    LabelObject::new(Some("certificateSignatureAlgorithmParameters".to_string()), vec![]),
                ],
            ),
            LabelObject::new(Some("certificateSignature".to_string()), vec![]),
        ],
    );

    return cert_choices;
}

pub fn label_certificate(typ: &str) -> LabelObject {
    let version = LabelObject::new(Some("versionImp".to_string()), vec![LabelObject::new(Some("version".to_string()), vec![])]);

    let serial = LabelObject::new(Some("serialNumber".to_string()), vec![]);

    let sig_alg_id = LabelObject::new(
        Some("signatureAlgorithmField".to_string()),
        vec![
            LabelObject::new(Some("certificateSignatureAlgorithm".to_string()), vec![]),
            LabelObject::new(Some("certificateSignatureAlgorithmParameters".to_string()), vec![]),
        ],
    );

    let issuer = LabelObject::new(
        Some("issuerField".to_string()),
        vec![LabelObject::new(
            Some("issuerFieldSet".to_string()),
            vec![LabelObject::new(
                Some("issuerFieldElement".to_string()),
                vec![
                    LabelObject::new(Some("issuerOid".to_string()), vec![]),
                    LabelObject::new(Some("issuerName".to_string()), vec![]),
                ],
            ),
            LabelObject::new(
                Some("issuerFieldElement1".to_string()),
                vec![
                    LabelObject::new(Some("issuerOid1".to_string()), vec![]),
                    LabelObject::new(Some("issuerName1".to_string()), vec![]),
                ],
            ),
            LabelObject::new(
                Some("issuerFieldElement2".to_string()),
                vec![
                    LabelObject::new(Some("issuerOid2".to_string()), vec![]),
                    LabelObject::new(Some("issuerName2".to_string()), vec![]),
                ],
            )],
        ),
        LabelObject::new(
            Some("issuerFieldSet1".to_string()),
            vec![LabelObject::new(
                Some("issuerFieldElement3".to_string()),
                vec![
                    LabelObject::new(Some("issuerOid3".to_string()), vec![]),
                    LabelObject::new(Some("issuerName3".to_string()), vec![]),
                ],
            )]),
            LabelObject::new(
            Some("issuerFieldSet2".to_string()),
            vec![LabelObject::new(
                Some("issuerFieldElement4".to_string()),
                vec![
                    LabelObject::new(Some("issuerOid4".to_string()), vec![]),
                    LabelObject::new(Some("issuerName4".to_string()), vec![]),
                ],
            )])],
    );

    let validity = LabelObject::new(
        Some("validityField".to_string()),
        vec![
            LabelObject::new(Some("notBefore".to_string()), vec![]),
            LabelObject::new(Some("notAfter".to_string()), vec![]),
        ],
    );

    let subject = LabelObject::new(
        Some("subjectField".to_string()),
        vec![LabelObject::new(
            Some("subjectFieldSeq".to_string()),
            vec![LabelObject::new(
                Some("subjectFieldSeqElement".to_string()),
                vec![
                    LabelObject::new(Some("subjectOid".to_string()), vec![]),
                    LabelObject::new(Some("subjectName".to_string()), vec![]),
                ],
                
            ),
            LabelObject::new(
                Some("subjectFieldSeqElement1".to_string()),
                vec![
                    LabelObject::new(Some("subjectOid1".to_string()), vec![]),
                    LabelObject::new(Some("subjectName1".to_string()), vec![]),
                ],
                
            ),
            LabelObject::new(
                Some("subjectFieldSeqElement2".to_string()),
                vec![
                    LabelObject::new(Some("subjectOid2".to_string()), vec![]),
                    LabelObject::new(Some("subjectName2".to_string()), vec![]),
                ],
                
            )],
        ),
        LabelObject::new(
            Some("subjectFieldSeq2".to_string()),
            vec![LabelObject::new(
                Some("subjectFieldSeqElement2".to_string()),
                vec![
                    LabelObject::new(Some("subjectOid2".to_string()), vec![]),
                    LabelObject::new(Some("subjectName2".to_string()), vec![]),
                ],
                
            ),
            ],
        ),
        LabelObject::new(
            Some("subjectFieldSeq3".to_string()),
            vec![LabelObject::new(
                Some("subjectFieldSeqElement3".to_string()),
                vec![
                    LabelObject::new(Some("subjectOid3".to_string()), vec![]),
                    LabelObject::new(Some("subjectName3".to_string()), vec![]),
                ],
                
            ),
            ],
        )],
    );

    let subject_publickey_info = LabelObject::new(
        Some("subjectPublicKeyInfoField".to_string()),
        vec![
            LabelObject::new(
                Some("subjectPublicKeyInfoFieldSeq".to_string()),
                vec![
                    LabelObject::new(Some("subjectPublicKeyAlgorithm".to_string()), vec![]),
                    LabelObject::new(Some("subjectPublicKeyAlgorithmParameters".to_string()), vec![]),
                ],
            ),
            LabelObject::new(Some("subjectPublicKey".to_string()), vec![]),
        ],
    );

    let crl_entries = LabelObject::new(Some("crlEntriesField".to_string()), vec![LabelObject::new(Some("crlEntries".to_string()), vec![])]);

    let ext = LabelObject {
        label: Some("extensions".to_string()),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_extensions),
    };

    let extensions = LabelObject::new(Some("extensionsField".to_string()), vec![ext]);
    let certificate = if typ == "crl" {
        LabelObject::new(
            Some("certificate".to_string()),
            vec![
                serial,
                sig_alg_id,
                issuer,
                LabelObject::new(Some("notBefore".to_string()), vec![]),
                LabelObject::new(Some("notAfter".to_string()), vec![]),
                crl_entries,
                extensions,
            ],
        )
    } else {
        LabelObject::new(
            Some("certificate".to_string()),
            vec![
                version,
                serial,
                sig_alg_id,
                issuer,
                validity,
                subject,
                subject_publickey_info,
                extensions,
            ],
        )
    };

    let cert_choices = LabelObject::new(
        Some("certificateChoices".to_string()),
        vec![
            certificate,
            LabelObject::new(
                Some("certificateSignatureAlgorithm".to_string()),
                vec![
                    LabelObject::new(Some("certificateSignatureAlgorithmOid".to_string()), vec![]),
                    LabelObject::new(Some("certificateSignatureAlgorithmParameters".to_string()), vec![]),
                ],
            ),
            LabelObject::new(Some("certificateSignature".to_string()), vec![]),
        ],
    );

    if typ == "roa" || typ == "mft" || typ == "gbr" || typ == "asa" {
        return LabelObject::new(Some("CertificateImp".to_string()), vec![cert_choices]);
    } else {
        return cert_choices;
    }
}

pub fn label_tree_roa() -> LabelObject {
    LabelObject{
        label: Some("encapsulatedContent".to_string()),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_roa_ip_seq),
    }
}

pub fn label_tree_manifest() -> LabelObject {
    // let manifest_number = LabelObject::new(Some("manifestNumber".to_string()), vec![]);

    // let this_update = LabelObject::new(Some("thisUpdate".to_string()), vec![]);

    // let next_update = LabelObject::new(Some("nextUpdate".to_string()), vec![]);

    // let hash_algo = LabelObject::new(Some("manifestHashAlgorithm".to_string()), vec![]);

    // let hashes_list = LabelObject::new(Some("manifestHashes".to_string()), vec![]);

    let manifest = LabelObject{
        label: Some("encapsulatedContent".to_string()),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_mft),
    };
    manifest
}

pub fn label_tree_aspa() -> LabelObject {
    let version = LabelObject::new(Some("versionImp".to_string()), vec![LabelObject::new(Some("version".to_string()), vec![])]);

    let customer_asid = LabelObject::new(Some("customerASID".to_string()), vec![]);

    let provider_as_seq = LabelObject::new(Some("providerASSequence".to_string()), vec![]);

    let aspa = LabelObject::new(Some("ASProviderAttestation".to_string()), vec![version, customer_asid, provider_as_seq]);

    aspa
}

pub fn label_tree_gbr() -> LabelObject {
    let content = LabelObject::new(Some("gbrContent".to_string()), vec![]);

    content
}

pub fn label_enc_content_inner(typ: &str) -> Vec<LabelObject> {
    let mut children = Vec::new();
    if typ == "roa" || typ == "iroa" || typ == "sroa" || typ == "rroa" {
        children.push(label_tree_roa());
    } else if typ == "mft" || typ == "imft"{
        children.push(label_tree_manifest());
    } else if typ == "asa" {
        children.push(label_tree_aspa());
    } else if typ == "gbr" {
        children.push(label_tree_gbr());
    }

    children
}

pub fn label_enc_content() -> LabelObject {
    let oc_label = LabelObject {
        label: Some("eContentOuterOctet".to_string()),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_encoded_content),
    };
    LabelObject::new(
        Some("encapsulatedContentInfo".to_string()),
        vec![
            LabelObject::new(Some("eContentType".to_string()), vec![]),
            LabelObject::new(Some("eContent".to_string()), vec![oc_label]),
        ],
    )
}

pub fn label_signed_attributes_rpki() -> HashMap<&'static str, LabelObject> {
    let mut map = HashMap::new();

    let content_type = LabelObject::new(
        Some("contentType".to_string()),
        vec![
            LabelObject::new(Some("contentTypeOid".to_string()), vec![]),
            LabelObject::new(
                Some("contentTypeValueParent".to_string()),
                vec![LabelObject::new(Some("contentTypeValue".to_string()), vec![])],
            ),
        ],
    );

    let message_digest = LabelObject::new(
        Some("messageDigestType".to_string()),
        vec![
            LabelObject::new(Some("messageDigestOid".to_string()), vec![]),
            LabelObject::new(
                Some("messageDigestValueParent".to_string()),
                vec![LabelObject::new(Some("messageDigest".to_string()), vec![])],
            ),
        ],
    );

    let signing_time = LabelObject::new(Some("signingTime".to_string()), vec![]);

    let signature = LabelObject::new(Some("signedAttrsSig".to_string()), vec![]);

    map.insert("1.2.840.113549.1.9.3", content_type);
    map.insert("1.2.840.113549.1.9.4", message_digest);
    map.insert("1.2.840.113549.1.9.5", signing_time);
    map.insert("1.2.840.113549.1.9.6", signature);

    map
}

pub fn label_signer_infos() -> LabelObject {
    let version = LabelObject::new(Some("signerVersion".to_string()), vec![]);

    let sid = LabelObject::new(Some("signerIdentifier".to_string()), vec![]);

    let digest_alg = LabelObject::new(
        Some("signerDigestAlgorithmField".to_string()),
        vec![
            LabelObject::new(Some("signerDigestAlgorithm".to_string()), vec![]),
            LabelObject::new(Some("signerDigestAlgorithmParameters".to_string()), vec![]),
        ],
    );

    let signed_attributes = LabelObject {
        label: Some("signerSignedAttributesField".to_string()),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_signed_attrs),
    };

    // let signed_attributes = LabelObject::new(Some("signerSignedAttributesField".to_string()), vec![]);

    let signed_signature_algorithm = LabelObject::new(
        Some("signerSignatureAlgorithm".to_string()),
        vec![
            LabelObject::new(Some("signerSignatureAlgorithmOid".to_string()), vec![]),
            LabelObject::new(Some("signedSignatureAlgorithmParameters".to_string()), vec![]),
        ],
    );

    let signed_signature = LabelObject::new(Some("signerSignature".to_string()), vec![]);

    let signer_info = LabelObject::new(
        Some("signerInfo".to_string()),
        vec![
            version,
            sid,
            digest_alg,
            signed_attributes,
            signed_signature_algorithm,
            signed_signature,
        ],
    );

    let signer_infos = LabelObject::new(Some("signerInfos".to_string()), vec![signer_info]);

    signer_infos
}


pub fn label_rpki_info() -> LabelObject{
    LabelObject::new(Some("rpkiInfo".to_string()), vec![
        LabelObject::new(Some("serialNumber".to_string()), vec![]),
        LabelObject::new(Some("authorityKeyIdentifier".to_string()), vec![]),
        LabelObject::new(Some("validityPeriod".to_string()), vec![
            LabelObject::new(Some("notBefore".to_string()), vec![]),
            LabelObject::new(Some("notAfter".to_string()), vec![]),
        ]),
    ])
}

pub fn label_iroa() -> LabelObject{
    return LabelObject {
        label: Some("eContentOuterOctet".to_string()),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_roa_ip_seq),
    };
}

pub fn label_tree(typ: &str) -> Option<LabelObject> {
    if typ == "roa" || typ == "mft" || typ == "gbr" || typ == "asa" {
        let signed_data = LabelObject::new(
            Some("signedData".to_string()),
            vec![
                LabelObject::new(Some("version".to_string()), vec![]),
                LabelObject::new(
                    Some("digestAlgorithmsSet".to_string()),
                    vec![LabelObject::new(
                        Some("digestAlgorithmSeq".to_string()),
                        vec![
                            LabelObject::new(Some("digestAlgorithm".to_string()), vec![]),
                            LabelObject::new(Some("digestParameters".to_string()), vec![]),
                        ],
                    )],
                ),
                label_enc_content(),
                label_certificate(typ),
                label_signer_infos(),
            ],
        );

        let content_info = LabelObject::new(
            Some("contentInfo".to_string()),
            vec![
                LabelObject::new(Some("contentType".to_string()), vec![]),
                LabelObject::new(Some("content".to_string()), vec![signed_data]),
            ],
        );

        Some(content_info)
    } else if typ == "cert" || typ == "cer"|| typ=="tls"{
        Some(label_certificate(typ))
    } 
    else if typ == "crl"{
        Some(label_certificate(typ))
    }
    else if typ == "iroa" || typ == "rroa"{
        Some(label_iroa())
    }
    else if typ == "imft" || typ == "sroa"{
        let signed_data = LabelObject::new(
            Some("signedData".to_string()),
            vec![
                LabelObject::new(Some("version".to_string()), vec![]),
                LabelObject::new(
                    Some("digestAlgorithmsSet".to_string()),
                    vec![LabelObject::new(
                        Some("digestAlgorithmSeq".to_string()),
                        vec![
                            LabelObject::new(Some("digestAlgorithm".to_string()), vec![]),
                            LabelObject::new(Some("digestParameters".to_string()), vec![]),
                        ],
                    )],
                ),
                label_enc_content(),
                label_signer_infos(),
            ],
        );

        let content_info = LabelObject::new(
            Some("contentInfo".to_string()),
            vec![
                LabelObject::new(Some("contentType".to_string()), vec![]),
                LabelObject::new(Some("content".to_string()), vec![signed_data]),
            ],
        );

        Some(content_info)

    }
    else {
        None
        // unimplemented!("Unknown type: {}", typ);
    }
}
