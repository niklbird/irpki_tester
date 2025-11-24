use std::{collections::{HashMap, HashSet}, fs::{self, File}, io::{self, Read}, path::Path};

use cure_asn1::{asn1_parser::{Element, Sequence, TLV},  rpki::rpki::ObjectType, rpki::rrdp::parse_notification, tree_parser::Tree};
use rand::{distributions::Alphanumeric, seq::SliceRandom, Rng};

use crate::{cure_object::{new_object, CureObject}, objects::asn1_helper, repository_util::{self, create_tal, RepoConfig}};

use sha2::{Digest, Sha256};
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};



pub fn load_example_roa(conf: &RepoConfig, asid: u16, amount: u16) -> Vec<CureObject> {
    // If using an amount > 1, asid will be increased for each next ROA
    let roa = asn1_helper::create_object(&ObjectType::ROA);
    let roa_tree = cure_asn1::tree_parser::parse_tree(&roa, "roa").unwrap();

    let mut ret = vec![];

    for i in 0..amount {
        let mut tr = roa_tree.clone();
        let aid = asid + i;

        let d = if aid < 128 {
            vec![aid as u8]
        } else {
            vec![(aid >> 8) as u8, aid as u8]
        };
        tr.set_data_by_label("asID", d, true, false);

        tr.fix_sizes(false);

        let parent_key_roa = repository_util::load_random_key(conf).0;
        let subject_key_roa = repository_util::load_random_key(conf).1;

        let froa = CureObject::new(
            ObjectType::ROA,
            parent_key_roa,
            subject_key_roa,
            tr,
            conf.ca_name.clone() + "_" + &aid.to_string() + ".roa",
        );

        ret.push(froa);
    }
    ret
}


pub fn load_example_iroa(conf: &RepoConfig, asid: u16, amount: u16) -> Vec<CureObject> {
    // If using an amount > 1, asid will be increased for each next ROA
    let roa = asn1_helper::create_object(&ObjectType::IROA);
    let roa_tree = cure_asn1::tree_parser::parse_tree(&roa, "iroa").unwrap();

    let mut ret = vec![];

    for i in 0..amount {
        let mut tr = roa_tree.clone();
        let aid = asid + i;

        let d = if aid < 128 {
            vec![aid as u8]
        } else {
            vec![(aid >> 8) as u8, aid as u8]
        };
        tr.set_data_by_label("asID", d, true, false);

        tr.fix_sizes(false);

        let parent_key_roa = repository_util::load_random_key(conf).0;
        let subject_key_roa = repository_util::load_random_key(conf).1;

        let mut froa = CureObject::new(
            ObjectType::IROA,
            parent_key_roa,
            subject_key_roa,
            tr,
            conf.ca_name.clone() + "_" + &aid.to_string() + ".iroa",
        );
        froa.tree.fix_sizes(false);
        ret.push(froa);

    }

    ret
}





#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RepoInfo {
    pub amount_objects: u16,
    pub ca_index: u16,
    pub target_object: ObjectType,
    pub additional_info: String,
}

impl RepoInfo {
    pub fn new(amount_objects: u16, ca_index: u16, target_object: ObjectType) -> Self {
        Self {
            amount_objects,
            ca_index,
            target_object,
            additional_info: "".to_string(),
        }
    }

    pub fn _default() -> Self {
        Self {
            amount_objects: 102,
            ca_index: 0,
            target_object: ObjectType::ROA,
            additional_info: "".to_string(),
        }
    }
}


#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CureRepository {
    pub payloads: Vec<CureObject>,
    pub manifest: CureObject,
    pub crl: CureObject,
    pub conf: RepoConfig,
    pub certificate: CureObject,
    pub child_repos: Vec<CureRepository>,
    pub repo_info: RepoInfo,
    pub raw_objects: Vec<(String, Vec<u8>)>,
}

impl CureRepository {
    pub fn _default() -> CureRepository{
        let obj = CureObject::_default();
        let conf = repository_util::RepoConfig::default();
        let repo_info = RepoInfo::_default();

        CureRepository{payloads: vec![], manifest: obj.clone(), crl: obj.clone(), conf, certificate: obj.clone(), child_repos: vec![], raw_objects: vec![], repo_info}
    }

    pub fn _new(
        payloads: Vec<CureObject>,
        manifest: CureObject,
        crl: CureObject,
        conf: RepoConfig,
        certificate: CureObject,
        child_repos: Vec<CureRepository>,
        repo_info: RepoInfo,
    ) -> Self {
        Self {
            payloads,
            manifest,
            crl,
            conf,
            certificate,
            child_repos,
            repo_info,
            raw_objects: vec![],
        }
    }

    pub fn set_additional_info(&mut self, entry: (String, Vec<u8>)){
        match self.repo_info.target_object{
            ObjectType::ASA | ObjectType::GBR | ObjectType::ROA => {
                self.payloads[0].tree.additional_info.insert(entry.0, entry.1);
            }
            ObjectType::CERTCA | ObjectType::CERTEE | ObjectType::CERTROOT => {
                self.certificate.tree.additional_info.insert(entry.0, entry.1);
            }
            ObjectType::MFT => {
                self.manifest.tree.additional_info.insert(entry.0, entry.1);
            }
            ObjectType::CRL => {
                self.crl.tree.additional_info.insert(entry.0, entry.1);
            }
            _ => {}
        }
    }

    pub fn serialize_default(&self) -> Vec<(String, Vec<(String, String, String, String, Vec<u8>)>)>{
        self.serialize(None, true, true, false)
    }

    pub fn serialize_proto(&self) -> Vec<(String, Vec<(String, String, String, String, Vec<u8>)>)>{
        self.serialize(None, true, true, true)
    }

    pub fn repositorify(&self, _havoc_factor: f32) -> Vec<(String, Vec<u8>)> {
        return self.create_snapshot_notification(&self.conf);
    }

     #[cfg(feature="research")]
    pub fn create_snap_notification_proto(&self, conf: &RepoConfig) -> Vec<(String, Vec<u8>)>{
        let objects = self.serialize_proto();
        Self::create_snap_notification_proto_objs(&objects, conf)
    }

    #[cfg(feature="research")]
    pub fn create_snap_notification_proto_objs(objects: &Vec<(String, Vec<(String, String, String, String, Vec<u8>)>)>, conf: &RepoConfig) -> Vec<(String, Vec<u8>)>{
        for ca in objects{
            for o in &ca.1{
                fs::create_dir_all(Path::new(&o.3).parent().unwrap()).unwrap();
                fs::write(&o.3, &o.4).unwrap();
            }
        }

        let mut map: HashMap<String, Vec<(String, Vec<u8>)>> = HashMap::new();

        for val in objects{
            for o in &val.1{
                if map.contains_key(&val.0){
                    map.get_mut(&val.0).unwrap().push((o.2.clone(), o.4.clone()));
                }
                else{
                    map.insert(val.0.clone(), vec![(o.2.clone(), o.4.clone())]);
                }
            }
        }

        let mut ret = vec![];
        let (s, su, n, nu) = cure_asn1::prot::util::create_snapshot_notification(map, &conf.domain, &conf.base_repo_dir, &conf.base_rrdp_dir, &conf.base_rrdp_dir_l);

        ret.push((s, su));
        ret.push((n, nu));
        ret

    }

    pub fn create_shapshot_notification_objs(objects: &Vec<(String, Vec<(String, String, String, String, Vec<u8>)>)>, conf: &RepoConfig) -> Vec<(String, Vec<u8>)>{
        if !cfg!(feature = "fuzzing"){
            // Write individual objects to disc
            for ca in objects {
                for o in &ca.1 {
                    fs::create_dir_all(Path::new(&o.3).parent().unwrap()).unwrap_or_default();
                    
                    let er = fs::write(&o.3, &o.4);
                    if er.is_err(){
                        println!("Was error {} {:?}", o.3, er);
                    }
                }
            }
    
        }

        let mut map: HashMap<String, (String, Vec<(String, Vec<u8>)>)> = HashMap::new();
        for ca in objects {

        for o in &ca.1 {
            if map.contains_key(&o.0) {
                map.get_mut(&o.0).unwrap().1.push((o.2.clone(), o.4.clone()));
            } else {
                map.insert(o.0.clone(), (o.1.clone(), vec![(o.2.clone(), o.4.clone())]));
            }
        }}

        let mut ret = vec![];
        for (k, v) in map {
            let mut conf = conf.clone();
            conf.base_rrdp_dir = k.clone();
            conf.base_rrdp_dir_l = v.0.clone();

            let (s, su, n, nu) = repository_util::create_snapshot_notification_objects(v.1, &conf);

            ret.push((s, su));
            ret.push((n, nu));
        }
        ret

    }

    pub fn create_snapshot_notification(&self, conf: &RepoConfig) -> Vec<(String, Vec<u8>)> {
        let objects = self.serialize_default();
        return Self::create_shapshot_notification_objs(&objects, conf);
    }

    fn collect_files_with_hashes(folder_uri: &str) -> io::Result<HashMap<String, String>> {
        let mut files_with_hashes = HashMap::new();
        
        for entry in fs::read_dir(folder_uri)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                files_with_hashes.extend(Self::collect_files_with_hashes(path.to_str().unwrap())?);
            } else if path.is_file() {
                let file_name = path.to_string_lossy().to_string();
                let hash = Self::hash_file(&path)?;
                files_with_hashes.insert(file_name, hash);
            }
        }
    
        Ok(files_with_hashes)
    }

    fn hash_file(path: &Path) -> io::Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];
    
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
    
        Ok(format!("{:x}", hasher.finalize()))
    }
    


   /*
    This function is experimental. It assumes the change was made in child_repo[0]
     */
    pub fn create_delta_notification(&self, conf: &RepoConfig) -> Vec<(String, Vec<u8>)> {
        let all_repo_files = Self::collect_files_with_hashes(&conf.base_repo_dir_l).unwrap();
        let snapshot_content = self.serialize_default();

        // Current dont write objects to disc
        for ca in &snapshot_content {
            for o in &ca.1 {
                fs::create_dir_all(Path::new(&o.3).parent().unwrap()).unwrap();
                fs::write(&o.3, &o.4).unwrap();
            }
        }

        let mut map_added: HashMap<String, (String, Vec<(String, Vec<u8>)>)> = HashMap::new();
        let mut map: HashMap<String, (String, Vec<(String, Vec<u8>)>)> = HashMap::new(); // Snapshot content
        
        let mut hashes = HashMap::new();
        let mut handled = HashSet::new();
        for ca in snapshot_content{
            for o in ca.1{ // File: parent_rrdp, parent_rrdp_l, obj_name, parent_data_dir_l + &self.certificate.name, cert_b
                if map.contains_key(&o.0) {
                    map.get_mut(&o.0).unwrap().1.push((o.2.clone(), o.4.clone()));
                } else {
                    map.insert(o.0.clone(), (o.1.clone(), vec![(o.2.clone(), o.4.clone())]));
                }

                if all_repo_files.contains_key(o.3.as_str()){
                    handled.insert(o.0.clone());
                    
                    let hash = hex::encode(sha2::Sha256::digest(&o.4));
                    if &hash == all_repo_files.get(o.3.as_str()).unwrap(){
                        continue;
                    }

                    if map_added.contains_key(&o.0) {
                        map_added.get_mut(&o.0).unwrap().1.push((o.2.clone(), o.4.clone()));
                    } else {
                        map_added.insert(o.0.clone(), (o.1.clone(), vec![(o.2.clone(), o.4.clone())]));
                    }
                    // Updated
                    hashes.insert(o.3.clone(), hash);

                }
                else{
                    if map_added.contains_key(&o.0) {
                        map_added.get_mut(&o.0).unwrap().1.push((o.2.clone(), o.4.clone()));
                    } else {
                        map_added.insert(o.0.clone(), (o.1.clone(), vec![(o.2.clone(), o.4.clone())]));
                    }
                }
            }
        }



        // let (snapshot_content, delta_content) = self.serialize_for_delta();
        // let mut snap_con = vec![];

        // for c in &snapshot_content {
        //     for o in &c.1{
        //         fs::create_dir_all(Path::new(&o.3).parent().unwrap()).unwrap();
        //         fs::write(&o.3, &o.4).unwrap();
    
        //         snap_con.push((o.2.clone(), o.4.clone()));    
        //     }
        // }


        // let mut delta_con = vec![];
        // for c in &delta_content {
        //     for o in &c.1{
        //         delta_con.push((o.2.clone(), o.4.clone()));
        //     }
        // }
        let mut ret = vec![];
        for entry in map{
            let mut new_conf = conf.clone();

            new_conf.base_rrdp_dir = entry.0.clone();
            new_conf.base_rrdp_dir_l = entry.1.0.clone();

            let notification_content = fs::read_to_string(&(new_conf.base_rrdp_dir_l.clone() + "notification.xml")).unwrap();
            let notification = parse_notification(&notification_content).unwrap();
    
            let prev_deltas = notification.get_deltas();
            let serial = notification.serial + 1;
            let session = notification.session_id;
    

            let snap_content = entry.1.1;
            let delta_content;
            if map_added.contains_key(&entry.0){
                delta_content = map_added.get(&entry.0).unwrap().1.clone();
            }
            else{
                delta_content = vec![];
            }
            let v = repository_util::create_snapshot_notification_delta_objects(snap_content, delta_content, prev_deltas.clone(), &hashes, serial, &session, &new_conf);
            ret.push((v.0, v.1));
            ret.push((v.2, v.3));
            for o in &v.4 {
                ret.push((o.0.clone(), o.1.clone()));
            }
    
        }

        ret
    }

    pub fn _add_roa(&mut self, as_id: u16) {
        let new_roa = load_example_roa(&self.conf, as_id, 1)[0].clone();

        self.payloads.push(new_roa);
    }

    pub fn update_names(&mut self) {
        let key_uri = self.conf.base_key_dir_l.clone() + &self.conf.ca_name + "_cer.der";
        let base_uri = repository_util::get_filename_crl_mft(&key_uri);

        self.manifest.name = base_uri.clone() + ".mft";

        self.crl.name = base_uri.clone() + ".crl";
        self.certificate.name = self.conf.ca_name.clone() + ".cer";
    }

    pub fn duplicate(&self, ca_name: &str) -> CureRepository {
        let mut ret = self.clone();

        // If name stayed the same, no need to update anything.
        if ret.conf.ca_name == ca_name {
            return ret;
        }

        ret.conf.ca_name = ca_name.to_string();
        ret.conf.ca_tree.remove(&self.conf.ca_name);
        ret.conf.ca_tree.insert(ret.conf.ca_name.clone(), "ta".to_string());

        let key_uri = self.conf.base_key_dir_l.clone() + ca_name + "_cer.der";

        ret.certificate.child_key = repository_util::read_cert_key(&key_uri);
        ret.manifest.parent_key = repository_util::read_cert_key(&key_uri);
        ret.crl.parent_key = repository_util::read_cert_key(&key_uri);
        ret.payloads[0].parent_key = repository_util::read_cert_key(&key_uri);

        ret.update_names();

        let asn_o = i32::from_str_radix(ca_name, 10);
        if asn_o.is_err() {
            ret.payloads[0].random_asn();
        } else {
            ret.payloads[0].ca_matching_asn(asn_o.unwrap());
        }
        ret.payloads[0].tree.fix_sizes(true);
        ret.payloads[0].name = ca_name.to_string() + ".roa";
        ret
    }

    pub fn serialize(
        &self,
        parent_config: Option<&RepoConfig>,
        include_children: bool,
        include_cert: bool,
        for_proto: bool
    ) -> Vec<(String, Vec<(String, String, String, String, Vec<u8>)>)> {
        let mut output = vec![];
        let mut ret = vec![];

        let data_dir = self.conf.base_repo_dir.clone() + &self.conf.ca_name + "/";
        let data_dir_l = self.conf.base_repo_dir_l.clone() + &self.conf.ca_name + "/";

        let parent_name = self.conf.ca_tree.get(&self.conf.ca_name).unwrap();
        let parent_data_dir = self.conf.base_repo_dir.clone() + &parent_name + "/";
        let parent_data_dir_l = self.conf.base_repo_dir_l.clone() + &parent_name + "/";

        let own_rrdp = self.conf.base_rrdp_dir.clone();
        let own_rrdp_l = self.conf.base_rrdp_dir_l.clone();

        let parent_rrdp = if parent_config.is_some() {
            parent_config.unwrap().base_rrdp_dir.clone()
        } else {
            self.conf.base_rrdp_dir.clone()
        };

        let parent_rrdp_l = if parent_config.is_some() {
            parent_config.unwrap().base_rrdp_dir_l.clone()
        } else {
            self.conf.base_rrdp_dir_l.clone()
        };

        let parent_ca = if parent_config.is_some() {
            parent_config.unwrap().ca_name.clone()
        } else {
            self.conf.ca_tree.get(&self.conf.ca_name).unwrap_or(&self.conf.ca_name).clone()
        };


        if include_cert {
            let cert_b = self.certificate.tree.encode();
            let obj_name = if !for_proto {format!("{}{}", &parent_data_dir, &self.certificate.name)} else {self.certificate.name.clone()};

            ret.push((parent_ca, vec![(parent_rrdp.clone(), parent_rrdp_l.clone(), obj_name, parent_data_dir_l.clone() + &self.certificate.name, cert_b)]));
        }

        for v in &self.payloads {
            let b;
            if cfg!(feature = "roa_proto") && (v.op_type == ObjectType::ROA || v.op_type == ObjectType::IROA) {
                panic!("Disabled support for proto in cargo");
                // b = v.tree.encode_proto("roa"); 
            } else {
                b = v.tree.encode();
            }


            let obj_name = if !for_proto {format!("{}{}", &data_dir, &v.name)} else {v.name.clone()};

            output.push((own_rrdp.clone(), own_rrdp_l.clone(), obj_name, data_dir_l.clone() + &v.name, b));
        }

        for v in &self.raw_objects{
            let obj_name = if !for_proto {format!("{}{}", &data_dir, &v.0)} else {v.0.clone()};

            output.push((own_rrdp.clone(), own_rrdp_l.clone(), obj_name, data_dir_l.clone() + &v.0, v.1.clone()));
        }

        if self.repo_info.additional_info != "no mft" {
            let mft_b;
            if !cfg!(feature = "roa_proto") {
                mft_b = self.manifest.tree.encode();
            } else {
                panic!("Disabled support for proto in cargo");
                // let mut tmp = prot::parsing::proto_from_mft(&self.manifest.tree, &self.crl.tree);
                // mft_b = self.sign_mft_proto(&mut tmp);
            } 

            let obj_name = if !for_proto {format!("{}{}", &data_dir, &self.manifest.name)} else {self.manifest.name.clone()};

            output.push((own_rrdp.clone(), own_rrdp_l.clone(), obj_name, data_dir_l.clone() + &self.manifest.name, mft_b));
        }

        if self.repo_info.additional_info != "no crl" && !cfg!(feature = "no_crl") && !self.manifest.name.ends_with("imft"){
            let crl_b = self.crl.tree.encode();
            let obj_name = if !for_proto {format!("{}{}", &data_dir, &self.crl.name)} else {self.crl.name.clone()};

            output.push((own_rrdp.clone(), own_rrdp_l.clone(), obj_name, data_dir_l.clone() + &self.crl.name, crl_b));
        }

        // println!("Output {:?}", output);

        ret.push((self.conf.ca_name.clone(), output));

        if include_children {
            for r in &self.child_repos {
                ret.extend(r.serialize(Some(&self.conf), true, true, for_proto));
            }
        }
        ret
    }

    // pub fn split_payloads(&self, factor: usize) -> Vec<Vec<CureObject>> {
    //     return split_vector_into_parts(&self.payloads, factor);
    // }

    pub fn write_to_disc(&self) -> Vec<(String, Vec<u8>)>{
        let v = self.create_snapshot_notification(&self.conf);
        for (uri, content) in &v {
            fs::create_dir_all(Path::new(&uri).parent().unwrap()).unwrap_or_default();
            fs::write(uri, content).unwrap();
        }
        let cert_uri = format!("{}/{}/ta.cer", self.conf.base_repo_dir_l, "ta");
        fs::write(cert_uri, self.certificate.tree.encode()).unwrap();
        v
    }

    pub fn write_to_disc_delta(&self) -> Vec<(String, Vec<u8>)> {
        let v = self.create_delta_notification(&self.conf);
        for (uri, content) in &v {
            fs::create_dir_all(Path::new(&uri).parent().unwrap()).unwrap_or_default();
            fs::write(uri, content).unwrap();
        }
        v
    }


    pub fn mutate_name(name: String) -> String {
        // Get the last part of the name
        let mut parts = name.split(".").collect::<Vec<&str>>();
        let last = parts.pop().unwrap();

        // Random string
        let s: String = rand::thread_rng().sample_iter(&Alphanumeric).take(10).map(char::from).collect();
        let new_name = s + "." + last;
        new_name
    }

    fn inflate(data: &Vec<CureObject>, factor: usize) -> Vec<CureObject> {
        let mut new_payloads = Vec::with_capacity(data.len() * factor);

        let mut cur_ind = 0;
        for p in data {
            for _ in 0..factor {
                let mut v = p.clone();

                // Randomize ASN in ROA each run to make objects better distinguishable
                if p.op_type == ObjectType::ROA {
                    v.random_asn();
                    v.name = cur_ind.to_string() + ".roa";

                    cur_ind += 1;
                } else {
                    v.name = Self::mutate_name(v.name.clone());
                }
                // v.mutate();

                new_payloads.push(v);
            }
        }
        new_payloads
    }

    pub fn inflate_payloads(&mut self, factor: usize) {
        let mut new_payloads = Vec::with_capacity(self.payloads.len() * factor);
        let payload_list;
        if self.repo_info.target_object == ObjectType::ROA {
            payload_list = Self::inflate(&self.payloads, factor);
            new_payloads.extend(payload_list);
        } else {
            new_payloads.push(self.payloads[0].clone());
            payload_list = Self::inflate(&self.payloads[1..].to_vec(), factor);
            new_payloads.extend(payload_list);
        }

        self.payloads = new_payloads;
    }

    // pub fn adapt_ip_addr_blocks(&mut self, new_data: Vec<u8>) {
    //     self.certificate
    //         .tree
    //         .set_data_by_label("ipAddrBlocksSequence", new_data, true, false);
    //     self.certificate.tree.fix_sizes(true);
    // }

    /// This Function will fix all objects in the repository. This, e.g., includes signing all objects, ensuring validity is not expired, adding all object hashes to the manifest etc.
    /// It will not overwrite any fields flagged with "manipulated".
    /// If initial_run is true, fixing also includes things like correcting issuer name, object URIs etc. This is generally only needed in the first run and can be skipped in later runs for efficiency.
    /// 
    /// Call this function after any changes to objects, otherwise signatures / manifest hashes will be invalid.
    pub fn fix_all_objects(&mut self, initial_run: bool) {
        self.fix_all_objects_c(initial_run, vec![]);
    }

    pub fn fix_all_objects_c(&mut self, initial_run: bool, additional_mft_entries: Vec<Element>) {
        let payloads = &mut self.payloads;

        let old_cure = true;
        let fixing_lvl = if initial_run { FixingLevel::Full } else { FixingLevel::Partial };

        self.certificate.fix_fields(&fixing_lvl, &self.conf, None);

        payloads.par_iter_mut().for_each(|obj| {
            if !(old_cure && !initial_run) {
                obj.fix_fields(&fixing_lvl, &self.conf, None);
            }
        });

        // Then collect values in parallel
        let mut values: Vec<_> = payloads.iter().map(|obj| obj.asn1_name_and_hash()).collect();

        if !self.raw_objects.is_empty(){
            for obj in &self.raw_objects {
                let tlv_name = TLV::new(22, obj.0.as_bytes().to_vec());
                let hash = sha2::Sha256::digest(&obj.1);

                let mut bs = vec![0];
                bs.extend(hash);
                let hash_tlv = TLV::new(3, bs);
                let seq = Sequence::new(vec![tlv_name.into(), hash_tlv.into()]);

                values.push(seq.into());
            }

        }
        if !cfg!(feature = "no_crl") && !self.conf.irpki {
            self.crl.fix_fields(&fixing_lvl, &self.conf, None);

            values.push(self.crl.asn1_name_and_hash());

        }

        for obj in &self.child_repos {
            values.push(obj.certificate.asn1_name_and_hash());
        }

        values.extend(additional_mft_entries);

        let hashlist = Sequence::new(values);
        self.manifest.fix_fields(&fixing_lvl, &self.conf, Some(hashlist.into()));

    }

    pub fn create_hash_list(&self) -> Element {
        let payloads = &self.payloads;

        let mut values = vec![];
        for obj in payloads {
            values.push(obj.asn1_name_and_hash());
        }
        values.push(self.crl.asn1_name_and_hash());
        for c in &self.child_repos {
            values.push(c.certificate.asn1_name_and_hash());
        }

        let hashlist = Sequence::new(values).into();
        hashlist
    }


    /*
    Can provide other object for splicing
     */
    pub fn mutate_object(&mut self, other_object: Option<&Tree>) {
        match self.repo_info.target_object {
            ObjectType::MFT => {
                // For Manifest, additionally fix hashlist
                if other_object.is_some(){
                    self.manifest.splice_mutation(other_object.unwrap());
                }
                else{
                    self.manifest.token_mutation();
                }
                self.manifest
                    .fix_fields(&FixingLevel::Minimal, &self.conf, Some(self.create_hash_list()))
            }
            ObjectType::CRL => {
                if other_object.is_some(){
                    self.crl.splice_mutation(other_object.unwrap());
                }
                else{
                    self.crl.token_mutation();
                }
            }
            ObjectType::CERTCA | ObjectType::CERTROOT => {
                if other_object.is_some(){
                    self.certificate.splice_mutation(other_object.unwrap());
                }
                else{
                    self.certificate.token_mutation();
                }
            }
            ObjectType::ROA | ObjectType::ASA | ObjectType::GBR => {
                let mut rand = rand::thread_rng();

                let ind_pl = rand.gen_range(0..self.payloads.len());
                self.payloads[ind_pl].token_mutation();
            }

            _ => {}
        }
    }


    #[cfg(feature = "research")]
    fn sign_mft_proto(&self, mft: &mut Manifest) -> Vec<u8>{
        let signed = mft.get_signed_data();
        let signature = self.manifest.parent_key.sign(&signed);
        mft.add_signature(signature);
        prot::util::encode_mft(mft).unwrap()
    }

    fn select_splicing_object(op_type: ObjectType, other_repo: &CureRepository) -> Tree {
        // Choose a random object, with a much higher likelyhood of selecting the same ObjectType
        let op_type = ObjectType::random_with_weight(op_type, 20);

        let oo = match op_type {
            ObjectType::ROA => other_repo.payloads.choose(&mut rand::thread_rng()).unwrap(),
            ObjectType::MFT => &other_repo.manifest,
            ObjectType::CRL => &other_repo.crl,
            ObjectType::CERTCA => &other_repo.certificate,
            _ => &other_repo.payloads[0],
        };
        let other_object = oo.tree.clone();
        other_object
    }

    pub fn get_tal(&self) -> String{
        create_tal(&self.conf, &self.certificate.get_ski_b64())
    }

}



impl CureRepository{
    pub fn mutate_all_objects(&mut self, other_repo: Option<&CureRepository>) {
        // If other_repo.is_some() then will use splice, otherwise will run token_mutation
        if self.repo_info.target_object.is_payload() {
            if other_repo.is_some() {
                let other_repo = other_repo.unwrap();

                for i in 0..self.payloads.len() {
                    let other_object = Self::select_splicing_object(self.repo_info.target_object, other_repo);
                    self.payloads[i].splice_mutation(&other_object);
                }
            } else {
                for i in 0..self.payloads.len() {
                    self.payloads[i].token_mutation();
                }
            }
        } else {
            if other_repo.is_some() {
                let other_repo = other_repo.unwrap();
                let tree = Self::select_splicing_object(self.repo_info.target_object, other_repo);
                self.mutate_object(Some(&tree));
            } else {
                self.mutate_object(None);
            }
        }
    }
}





#[derive(PartialEq)]
pub enum FixingLevel {
    Full,
    Partial,
    Minimal,
}

impl FixingLevel {
    pub fn score(&self) -> u8 {
        match self {
            FixingLevel::Full => 2,
            FixingLevel::Partial => 1,
            FixingLevel::Minimal => 0,
        }
    }
}


pub fn nest_payloads_in_repo(payloads: Vec<Vec<u8>>, typ: &str) -> CureRepository{
    let s = fs::read_to_string("snapshot_repo").unwrap();
    let mut repo: CureRepository = serde_json::from_str(&s).unwrap();

    serde_json::to_string(&repo).unwrap();
    let mut raw_objects = vec![];
    for i in 0..payloads.len(){
        let name = format!("{}.{}", i, typ);
        raw_objects.push((name, payloads[i].clone()));
    }
    
    repo.child_repos[0].raw_objects = raw_objects;
    repo.child_repos[0].payloads = vec![];


    repo.child_repos[0].fix_all_objects(true);
    // repo.fix_all_objects(true);

    repo
}



/// Create a default repository with parameters
/// 
/// # Arguments
/// * `roa_amount` - The amount of ROAs to create
/// * `start_asn` - The starting for the ROAs
/// * `include_child` - Whether to include a child repository. If true, ROAs will be put in the child repository
/// 
pub fn default_repo_c(roa_amount: u16, start_asn: u16, include_child: bool) -> CureRepository {
    let root_conf = repository_util::create_config_name("ta");

    let mut root = new_repo(&root_conf, &ObjectType::UNKNOWN, true);

    if include_child{
        let mut child = new_repo_from_name("newca", "ta", &ObjectType::UNKNOWN, false);


        let payloads = match roa_amount > 0 {
            true => load_example_roa(&child.conf, start_asn, roa_amount).clone(),
            false => vec![],
        }; 

        child.payloads = payloads;
        child.fix_all_objects(true);

        root.child_repos.push(child);
        root.fix_all_objects(true);
    

    
    }
    else{
        let payloads = match roa_amount > 0 {
            true => load_example_roa(&root_conf, start_asn, roa_amount).clone(),
            false => vec![],
        };
        root.payloads = payloads;
        root.fix_all_objects(true);
    }

    let aki_b64 = root.certificate.get_ski_b64();
    create_tal(&root_conf, &aki_b64);

    root    
}


pub fn default_repo_c_irpki(roa_amount: u16, start_asn: u16, include_child: bool) -> CureRepository {
    let mut root_conf = repository_util::create_config_name("ta");
    root_conf.irpki = true;

    let mut root = new_repo_irpki(&root_conf, &ObjectType::UNKNOWN, true);

    if include_child{
        let mut child = new_repo_from_name_irpki("newca", "ta", &ObjectType::UNKNOWN, false);

        let payloads = match roa_amount > 0 {
            true => load_example_iroa(&child.conf, start_asn, roa_amount).clone(),
            false => vec![],
        }; 

        child.payloads = payloads;
        child.fix_all_objects(true);

        root.child_repos.push(child);
        root.fix_all_objects(true);
    }
    else{
        let payloads = match roa_amount > 0 {
            true => load_example_iroa(&root_conf, start_asn, roa_amount).clone(),
            false => vec![],
        };
        root.payloads = payloads;
        root.fix_all_objects(true);
    }

    let aki_b64 = root.certificate.get_ski_b64();
    create_tal(&root_conf, &aki_b64);

    root    
}



pub fn default_repo_irpki(roa_amount: u16) -> CureRepository {
    default_repo_c_irpki(roa_amount, 1, true)
}

pub fn default_repo_roa(roa_amount: u16) -> CureRepository {
    default_repo_c(roa_amount, 1, false)
}

/// Creates a default repository, no children, one ROA
pub fn default_repo() -> CureRepository {
    default_repo_c(1, 1, true)
}


pub fn new_repo_from_name(child: &str, parent: &str, typ: &ObjectType, root: bool) -> CureRepository{
    let mut conf = repository_util::create_config_name(child);
    conf.ca_tree.insert(child.to_string(), parent.to_string());

    new_repo(&conf, typ, root)
}

pub fn new_repo_from_name_irpki(child: &str, parent: &str, typ: &ObjectType, root: bool) -> CureRepository{
    let mut conf = repository_util::create_config_name(child);
    conf.irpki = true;
    conf.ca_tree.insert(child.to_string(), parent.to_string());

    new_repo_irpki(&conf, typ, root)
}



pub fn new_repo(conf: &RepoConfig, typ: &ObjectType, root: bool) -> CureRepository{
    let fmft = new_object(conf, &ObjectType::MFT);
    let fcrl = new_object(conf, &ObjectType::CRL);
    let fcer = if root  {new_object(conf, &ObjectType::CERTROOT)} else {new_object(conf, &ObjectType::CERTCA)};

    let payloads;
    if typ.is_payload(){
        let payload = new_object(conf, typ);
        payloads = vec![payload];
    }
    else{
        payloads = vec![];
    }

    let rep_inf = RepoInfo::new(0, 0, typ.clone());

    let mut repo = CureRepository {
        payloads,
        manifest: fmft,
        crl: fcrl,
        conf: conf.clone(),
        certificate: fcer,
        child_repos: vec![],
        repo_info: rep_inf,
        raw_objects: vec![],
    };

    repo.fix_all_objects(true);
    repo
}

pub fn new_repo_irpki(conf: &RepoConfig, typ: &ObjectType, root: bool) -> CureRepository{
    let fmft = new_object(conf, &ObjectType::IMFT);
    let fcer = if root  {new_object(conf, &ObjectType::CERTROOT)} else {new_object(conf, &ObjectType::CERTCA)};

    let payloads;
    if typ.is_payload(){
        let payload = new_object(conf, typ);
        payloads = vec![payload];
    }
    else{
        payloads = vec![];
    }

    let rep_inf = RepoInfo::new(0, 0, typ.clone());

    let mut repo = CureRepository {
        payloads,
        manifest: fmft.clone(),
        crl: fmft.clone(),
        conf: conf.clone(),
        certificate: fcer,
        child_repos: vec![],
        repo_info: rep_inf,
        raw_objects: vec![],
    };

    repo.fix_all_objects(true);
    repo
}

pub fn new_parent_child()-> CureRepository{
    let child = RepoTreeNode{
        payload_amounts: HashMap::new(),
        children: vec![],
    };
    let root = RepoTreeNode{
        payload_amounts: HashMap::new(),
        children: vec![child],
    };

    repos_from_tree(&root)
}


pub fn repos_from_tree(root: &RepoTreeNode) -> CureRepository{
    let mut payloads = vec![];
    let mut conf = repository_util::RepoConfig::default();
    conf.ca_name = "ta".to_string();
    conf.ca_tree.insert("ta".to_string(), "ta".to_string());

    for (k, v) in &root.payload_amounts{
        for _ in 0..*v{
            let obj = new_object(&conf, k);
            payloads.push(obj);    
        }
    }

    let mut repo = new_repo(&conf, &ObjectType::UNKNOWN, true);
    repo.payloads = payloads;

    for child in &root.children{
        let child_repo = repos_from_tree(child);
        repo.child_repos.push(child_repo);
    }

    repo
}

pub fn repos_from_tree_rec(node: &RepoTreeNode, parent_name: &str, root: bool) -> CureRepository{
    let rname = repository_util::random_fname();
    let mut repo = new_repo_from_name(&rname, parent_name, &ObjectType::UNKNOWN, root);
    
    let mut payloads = vec![];
    for (k, v) in &node.payload_amounts{
        for _ in 0..*v{
            let obj = new_object(&repo.conf, k);
            payloads.push(obj);    
        }
    }

    repo.payloads = payloads;

    for child in &node.children{
        let child_repo = repos_from_tree_rec(child, &rname, false);
        repo.child_repos.push(child_repo);
    }

    repo
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RepoTreeNode{
    pub payload_amounts: HashMap<ObjectType, u16>,
    pub children: Vec<RepoTreeNode>,
}
