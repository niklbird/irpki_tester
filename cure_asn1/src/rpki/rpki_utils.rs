fn ipv6_to_octets(addr_str: &str) -> Result<Vec<u8>, String> {
    // Handle "::" (zero compression)
    let parts: Vec<&str> = addr_str.split("::").collect();
    if parts.len() > 2 {
        return Err("Invalid IPv6 address: too many '::'".into());
    }

    let head: Vec<&str> = if !parts[0].is_empty() {
        parts[0].split(':').collect()
    } else {
        Vec::new()
    };

    let tail: Vec<&str> = if parts.len() == 2 && !parts[1].is_empty() {
        parts[1].split(':').collect()
    } else {
        Vec::new()
    };

    // Number of missing 16-bit groups
    let missing = 8usize.saturating_sub(head.len() + tail.len());
    if parts.len() == 1 && head.len() != 8 {
        return Err("Invalid IPv6 address: wrong number of groups".into());
    }

    // Build full list of groups
    let mut groups = Vec::new();
    groups.extend(head.into_iter());
    for _ in 0..missing {
        groups.push("0");
    }
    groups.extend(tail.into_iter());

    if groups.len() != 8 {
        return Err(format!("Invalid IPv6 address: got {} groups", groups.len()));
    }

    // Convert groups (hex) to octets
    let mut octets = Vec::with_capacity(16);
    for g in groups {
        let val = u16::from_str_radix(g, 16)
            .map_err(|_| format!("Invalid hex group '{}'", g))?;
        octets.push((val >> 8) as u8);
        octets.push((val & 0xff) as u8);
    }

    Ok(octets)
}


fn ipv4_to_octets(addr_str: &str) -> Result<Vec<u8>, String> {
    // Split "addr/prefixlen"
    let octets: Vec<&str> = addr_str.split('.').collect();
    if octets.len() != 4 {
        return Err("Invalid IPv4 address: wrong number of octets".into());
    }

    let mut bytes = Vec::with_capacity(4);
    for o in octets {
        let val = o.parse::<u8>().map_err(|_| format!("Invalid octet '{}'", o))?;
        bytes.push(val);
    }

    Ok(bytes)
}

pub fn parse_ip_from_string(input: &str) -> Result<Vec<u8>, String>{
    let raw_ip;
    let p_len;
    if input.contains("/"){
        let s = input.split("/").collect::<Vec<&str>>();
        if s.len() != 2{
            return Err("Invalid IP format".to_string());
        }
        raw_ip = s[0];
        p_len = s[1];
    }
    else{
        raw_ip = input;
        p_len = "";
    }


    let mut octets = if raw_ip.contains("."){
        ipv4_to_octets(raw_ip).map_err(|e| e.to_string())?
    } else if raw_ip.contains(":") {
        ipv6_to_octets(raw_ip).map_err(|e| e.to_string())?
    }
    else{
        return Err("Invalid IP format".to_string());
    };

    let prefix_length = if !p_len.is_empty() {
        p_len.parse::<usize>().map_err(|_| "Invalid prefix length".to_string())?
    }
    else{
        octets.len()
    };



    // Calculate padding
    let total_bits = if octets.len() == 4{32} else {128};
    if prefix_length > total_bits{
        return Err("Prefix length exceeds total bits for IPv4".to_string());
    }
    let full_bytes = prefix_length / 8;
    let padding_amount = prefix_length % 8;
    if full_bytes < octets.len() && padding_amount > 0{
        octets.truncate(full_bytes + 1);
    }
    if padding_amount > 0{
        let mask = 0xFF << (padding_amount);
        if full_bytes < octets.len(){
            octets[full_bytes] = octets[full_bytes] & mask;
        }
    }

    let mut output = vec![ 8 - padding_amount as u8];
    output.extend(octets);

   

    Ok(output)


}

pub fn parse_ip(ip: &Vec<u8>, fam: u8, padding_amount: usize) -> String {
    if ip.len() == 0{
        return "".to_string();
    }

    let mut ret = "".to_string();
    if fam == 1 {
        for i in 0..ip.len() {
            ret += &ip[i].to_string();
            ret += ".";
        }
        for _ in ip.len()..4 {
            ret += "0";
            ret += ".";
        }

        ret = ret[..ret.len() - 1].to_string();

        let tmp = ip.last().unwrap();
        let mut v = 1;

        while tmp & v == 0 && tmp != &0 {
            v = v << 1;
        }

        ret += &format!("/{}", 8 * ip.len() - padding_amount);
    } else if fam == 2 {
        // In two steps
        for i in (0..ip.len()).step_by(2) {
            let mut tmp;
            if i + 1 < ip.len() {
                tmp = format!("{:02x}{:02x}", ip[i], ip[i + 1]);
            } else {
                tmp = format!("{:02x}00", ip[i]);
            }
            tmp = tmp.trim_start_matches('0').to_string();

            if tmp == "" {
                tmp += "0";
            }
            tmp += ":";
            ret += &tmp;
        }
        ret = ret[..ret.len() - 1].to_string();
        let v = ip.len() as f64 / 2.0;
        let v = v.ceil() as usize;
        for _ in v..8 {
            ret += ":0";
        }

        let mut largest = (0, 0, 0);
        let mut currently_in_streak = false;
        let mut current_count = (0, 0, 0);
        let mut ind = 0;
        for val in ret.split(":") {
            if val == "0" {
                current_count.0 += 1;
                if !currently_in_streak {
                    current_count = (current_count.0, ind, ind + 1);
                    currently_in_streak = true;
                } else {
                    current_count.2 += 1;
                }
                if current_count.0 > largest.0 {
                    largest = current_count;
                }
            } else {
                current_count = (0, 0, 0);
                currently_in_streak = false;
            }
            ind += 1;
        }

        if largest.0 > 1 {
            let mut ind = 0;
            let mut new_ret = "".to_string();
            for val in ret.split(":") {
                if ind == largest.1 {
                    new_ret += "::";
                    if new_ret.ends_with(":::") {
                        new_ret = new_ret[..new_ret.len() - 1].to_string();
                    }
                } else if ind < largest.1 || ind >= largest.2 {
                    new_ret += val;
                    new_ret += ":";
                }
                ind += 1;
                // else{
                //     new_ret += val;
                //     new_ret += ":";
                //     ind += 1;
                // }
            }
            if new_ret.ends_with(":") && !new_ret.ends_with("::") {
                new_ret = new_ret[..new_ret.len() - 1].to_string();
            }
            if new_ret == "::0:0:0" {
                println!("{}", ret);
            }
            ret = new_ret;
        }

        ret += &format!("/{}", 8 * ip.len() - padding_amount);
    }

    return ret;
}

pub fn byt_to_in(inp: &Vec<u8>) -> u64 {
    let mut result: u64 = 0;
    for byte in inp {
        result = (result << 8) | (*byte as u64);
    }
    result
}
