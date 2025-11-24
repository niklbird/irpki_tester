/*
Mutate an ASN.1 syntax tree for fuzzing.
*/

use std::collections::HashSet;

use crate::tree_parser::{self, Token, Tree, Types};
use rand::distributions::WeightedIndex;
use rand::prelude::Distribution;
use rand::seq::SliceRandom;
use rand::{self, thread_rng};
use rand::{random, Rng};

pub enum MutationClass {
    Token,
    Splice,
    Shuffle,
}

// pub struct MutationConfig {
//     pub mutation_type: MutationClass,
//     pub number_mutations: usize,
//     pub mutation_probabilities: HashMap<String, f32>,
// }

// #[derive(Serialize, Deserialize)]
// pub struct MutationProbabilities {
//     pub mutation_probabilities: HashMap<String, f32>,
// }

// impl MutationConfig {
//     pub fn new(
//         mutation_type: MutationClass,
//         number_mutations: usize,
//         mutation_probabilities: HashMap<String, f32>,
//     ) -> Self {
//         MutationConfig {
//             mutation_type,
//             number_mutations,
//             mutation_probabilities,
//         }
//     }

//     pub fn from_file(uri: &str) {
//         let file_content =
//             fs::read_to_string("mutation_probabilities.json").expect("Failed to read the file");

//         // Parse the JSON content
//         let mutation_probabilities: HashMap<String, f32> =
//             serde_json::from_str(&file_content).expect("Failed to parse the JSON file");

//         // Print the parsed content (for demonstration purposes)
//         for (mutation, probability) in &mutation_probabilities {
//             println!("{}: {}", mutation, probability);
//         }

//         // You can now use the mutation_probabilities HashMap in your code
//         let my_struct = MutationProbabilities {
//             mutation_probabilities,
//         };
//     }

//     pub fn get_mutation_probabilities(&self) -> HashMap<String, f32> {
//         self.mutation_probabilities.clone()
//     }

//     pub fn get_mutation_probablity(&self, mutation: String) -> f32 {
//         return *self.mutation_probabilities.get(&mutation).unwrap_or(&1.0);
//     }
// }

pub fn mutate_tree(tree: &mut Tree, number_mutations: usize) {
    let havoc = false;
    let old_cure = false;

    if havoc {
        let mut enc = tree.encode();
        mutate_binary_data(&mut enc);
        tree.additional_info.insert("havocc".to_string(), enc);
        return;
    }

    if old_cure {
        loop {
            let node_id = tree.splice_token_id();
            let node = tree.tokens.get_mut(&node_id).unwrap();
            let mut data = node.data.clone();
            let mutation = mutate_binary_data(&mut data);
            if mutation != ContentMutation::NoMutation {
                node.data = data;
                node.manipulated = true;
                break;
            }
        }
        return;
    }

    let likelihood_random = 0.7;
    for _ in 0..number_mutations {
        let mut node_id;
        if tree.mutations.len() > 0 {
            let last_id = tree.mutations.last().unwrap().node_id;
            let random_res = random::<f32>();
            if random_res < likelihood_random
                || !tree.tokens.contains_key(&last_id)
                || tree.mutations.last().unwrap().get_mutation_string().contains("NoMutation")
            {
                node_id = tree.guided_token_id();
            } else {
                node_id = last_id;
            }
        } else {
            node_id = tree.guided_token_id();
        }
        let mut m = mutate_token(tree, node_id);

        // If no mutation -> Retry
        if m.is_no_mutation() {
            let attempt = 3;
            for _ in 0..attempt {
                node_id = tree.guided_token_id();
            
            m = mutate_token(tree, node_id);
            if !m.is_no_mutation() {
                break;
            }}
        }
        else{
            // println!("{:?} on {}", m, tree.tokens.get(&node_id).unwrap().info);
        }
        tree.mutations.push(Mutation { mutation: m, node_id });
    }
    tree.fix_sizes(true);
}

/*
Splice a tree, i.e. insert a subtree from another tree into the current tree.
@param tree: The tree to splice into
@param other_trees: The trees to splice from
@param amount_splices: The amount of splices to perform
@param random_splice: Whether to use a random node or not (Using random will result in much more difficult to parse tree)
*/
pub fn splice_tree(tree: &mut Tree, other_tree: &Tree, amount_splices: usize, random_splice: bool) {
    for _ in 0..amount_splices {
        let node_id = tree.splice_token_id();

        let node_in_other;
        if !random_splice {
            let node_path = tree.get_node_path(node_id);
            node_in_other = other_tree.get_node_from_node_path(&node_path);
        } else {
            node_in_other = other_tree.random_token_id();
        }

        let new_tokens = other_tree.get_offspring_tokens(node_in_other);
        tree.splice_tree(node_id, &new_tokens, node_in_other);
    }

    tree.fix_sizes(false);
}

pub fn shuffle_tree(tree: &mut Tree) {
    tree.shuffle();
}

pub fn mutate_token(tree: &mut Tree, id: usize) -> TokenMutation {
    if !tree.tokens.contains_key(&id) {
        println!("Error: Token was not contained");
        return TokenMutation::NoMutation;
    }

    let tag = &tree.tokens.get(&id).unwrap().tag;

    let m = match tag {
        &Types::Sequence => TokenMutation::Sequence(mutate_sequence(tree, id)),
        &Types::TLV => mutate_tlv(tree, id),
        &Types::Set => TokenMutation::Set(mutate_sequence(tree, id)),
        &Types::OctetString => mutate_octetstring(tree, id),
        &Types::Implicit => mutate_implicit(tree, id),
        &Types::BitString => mutate_tlv(tree, id),
        &Types::NULL => mutate_tlv(tree, id),
        &Types::ObjectIdentifier => mutate_tlv(tree, id),
        &Types::Cont0 => mutate_tlv(tree, id),
        &Types::Integer => mutate_tlv(tree, id),
        &Types::IA5String => mutate_tlv(tree, id),
    };

    // Token can not be contained anymore if it was deleted from a sequence e.g.
    if tree.tokens.contains_key(&id) {
        tree.tokens.get_mut(&id).unwrap().tainted = true;
        tree.tokens.get_mut(&id).unwrap().manipulated = true;

        tree.taint_parents(id);
    }

    return m;
}

fn next_power_of_two(n: u32) -> u32 {
    let mut n = n.clone();

    if n == 0 {
        return 1;
    }

    n -= 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n += 1;

    n
}

fn prev_power_of_two(n: u32) -> u32 {
    let mut n = n.clone();
    if n == 0 {
        return 0;
    }

    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;

    // At this point, n is the next power of two. Shift it right to get the previous power of two.
    n >>= 1;

    n
}

pub fn manipulate_value(value: u32, max: u32) -> (u32, ValueMutation) {
    let mut rng = rand::thread_rng();
    let mutation_types = [(0, 5), (1, 5), (2, 5), (3, 5), (4, 2), (5, 2), (6, 15), (7, 7), (8, 7)];
    let chosen_type = mutation_types.choose_weighted(&mut rng, |&(_, weight)| weight).unwrap().0;

    match chosen_type {
        0 => return (0, ValueMutation::Zero),
        1 => return (max, ValueMutation::Max),
        2 => return (value.wrapping_add(1), ValueMutation::Add),
        3 => return (value.wrapping_sub(1), ValueMutation::Substract),
        4 => return (next_power_of_two(value), ValueMutation::NextPowerOfTwo),
        5 => return (prev_power_of_two(value), ValueMutation::PreviousPowerOfTwo),
        6 => return (rng.gen_range(0..max), ValueMutation::Random),
        7 => (value.wrapping_add(rng.gen_range(0..10)), ValueMutation::Add),
        8 => (value.wrapping_sub(rng.gen_range(0..10)), ValueMutation::Substract),

        _ => unreachable!(),
    }
}

// Generic manipulation of a tag
pub fn mutate_tag(token: &mut Token) -> ValueMutation {
    let mut rng = rand::thread_rng();
    let val = rng.gen_range(0..3);

    let interesting_tags = vec![
        1, 2, 3, 4, 5, 5, 6, 10, 12, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 31, 31, 31, 48, 48, 49, 49,
    ];

    if token.visual_tag.len() == 0 {
        token.visual_tag = vec![0];
    }

    match val {
        0 => {
            let res = manipulate_value(token.visual_tag[0] as u32, 255);
            token.visual_tag = vec![res.0.try_into().unwrap_or(255)];
            return res.1;
        }
        1 => {
            let interesting_tag = interesting_tags.choose(&mut rng).unwrap();
            token.visual_tag = vec![*interesting_tag as u8];
            return ValueMutation::Random;
        }
        2 => {
            mutate_binary_data(&mut token.visual_tag);
            return ValueMutation::Random;
        }
        _ => unreachable!(),
    }
}

// Generic manipulation of a length
pub fn mutate_length(token: &mut Token) -> ValueMutation {
    let res = manipulate_value(token.visual_length as u32, 4000);
    token.visual_length = res.0.try_into().unwrap();
    token.manipulated_length = true;
    return res.1;
}

pub fn mutate_bool(data: Vec<u8>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let random_number: u8 = rng.gen_range(0..2);

    match random_number {
        0 => {
            let mut new_data = data.clone();
            new_data[0] = 255 - data[0];
            return new_data;
        }
        1 => {
            let mut new_data = data.clone();
            let random_value: u8 = rng.gen_range(0..=255);

            new_data[0] = random_value;
            return new_data;
        }
        _ => unreachable!(),
    };
}

pub fn mutate_integer(data: Vec<u8>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let random_number: u8 = rng.gen_range(0..5);

    match random_number {
        0 => {
            // Flip all values
            let mut new_data = data.clone();

            for i in 0..data.len() {
                new_data[i] = 255 - data[i];
            }
            return new_data;
        }
        1 => {
            // Random Bytes
            let mut new_data = data.clone();
            let random_value: u8 = rng.gen_range(0..=255);
            let byte = rng.gen_range(0..data.len());

            new_data[byte] = random_value;
            return new_data;
        }
        2 => {
            // Interesting Integers
            let mut new_data = data.clone();

            let byte = rng.gen_range(0..data.len());
            let interesting_ints: [u8; 4] = [0, 255, 127, 128];
            let interesting_int = *interesting_ints.choose(&mut rng).unwrap();
            new_data[byte] = interesting_int;
            return new_data;
        }
        3 => {
            // Add 1 to all bytes
            let mut new_data = data.clone();
            for i in 0..data.len() {
                new_data[i] = data[i].wrapping_add(1);
            }
            return new_data;
        }
        4 => {
            // Substract 1 from all bytes
            let mut new_data = data.clone();
            for i in 0..data.len() {
                new_data[i] = data[i].wrapping_sub(1);
            }
            return new_data;
        }
        _ => unreachable!(),
    };
}

pub fn mutate_oid(data: Vec<u8>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let random_number: u8 = rng.gen_range(0..7);

    let interesting_oids = vec![
        "1.2.840.113549.1.7.2",
        "2.16.840.1.101.3.4.2.1",
        "1.2.840.113549.1.9.16.1.24",
        "1.2.840.113549.1.1.11",
        "2.5.4.3",
        "1.2.840.113549.1.1.1",
        "2.5.29.14",
        "2.5.29.35",
        "2.5.29.15",
        "2.5.29.31",
        "1.3.6.1.5.5.7.1.1",
        "1.3.6.1.5.5.7.48.2",
        "1.3.6.1.5.5.7.1.11",
        "1.3.6.1.5.5.7.48.11",
        "2.5.29.32",
        "1.3.6.1.5.5.7.14.2",
        "1.3.6.1.5.5.7.1.7",
        "2.16.840.1.101.3.4.2.1",
        "1.2.840.113549.1.9.3",
        "1.2.840.113549.1.9.16.1.24",
        "1.2.840.113549.1.9.4",
    ];

    match random_number {
        0 => {
            // Add one to last value
            let mut new_data = data.clone();
            let l = new_data.len();

            let mut last_value = new_data[l - 1];
            last_value = last_value.wrapping_add(1);
            new_data[l - 1] = last_value;
            return new_data;
        }
        1 => {
            // Substract one from last value
            let mut new_data = data.clone();
            let l = new_data.len();
            let mut last_value = new_data[l - 1];
            last_value = last_value.wrapping_sub(1);
            new_data[l - 1] = last_value;
            return new_data;
        }
        2 => {
            // Change random value
            let mut new_data = data.clone();
            let random_value: u8 = rng.gen_range(0..=255);
            let byte = rng.gen_range(0..data.len());
            new_data[byte] = random_value;
            return new_data;
        }
        3 => {
            // Add one to random value
            let mut new_data = data.clone();
            let byte = rng.gen_range(0..data.len());
            new_data[byte] = new_data[byte].wrapping_add(1);
            return new_data;
        }
        4 => {
            // Substract one from random value
            let mut new_data = data.clone();
            let byte = rng.gen_range(0..data.len());
            new_data[byte] = new_data[byte].wrapping_sub(1);
            return new_data;
        }
        5 => {
            // Change to interesting OID
            let oid = interesting_oids.choose(&mut rng).unwrap();
            let new_v = tree_parser::encode_oid(oid).unwrap();
            return new_v;
        }
        6 => {
            // Change first byte
            let mut new_data = data.clone();
            let random_value: u8 = rng.gen_range(20..=255);
            new_data[0] = random_value;
            return new_data;
        }
        _ => {
            unreachable!();
        }
    }
}

pub fn mutate_string(data: Vec<u8>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let random_number: u8 = rng.gen_range(0..6);

    match random_number {
        0 => {
            // Duplicate first X Bytes
            let mut new_data = data.clone();
            let size = rng.gen_range(1..10);
            let v = data[0..size].to_vec();
            new_data.splice(0..0, v);
            return new_data;
        }
        1 => {
            // Capatilize random chars
            let mut new_data = data.clone();
            let byte = rng.gen_range(0..data.len());

            for i in byte..data.len() {
                if new_data[i].is_ascii_uppercase() {
                    new_data[i] = new_data[i].to_ascii_lowercase();
                } else {
                    new_data[i] = new_data[i].to_ascii_uppercase();
                }
            }
            return new_data;
        }
        2 => {
            // Change random value
            let mut new_data = data.clone();
            let random_value: u8 = rng.gen_range(0..=255);
            let byte = rng.gen_range(0..data.len());
            new_data[byte] = random_value;
            return new_data;
        }
        3 => {
            // Add one to random value
            let mut new_data = data.clone();
            let byte = rng.gen_range(0..data.len());
            new_data[byte] = new_data[byte].wrapping_add(1);
            return new_data; 
        }
        4 => {
            // Insert random char
            let mut new_data = data.clone();
            let byte = rng.gen_range(0..data.len());
            let random_value: u8 = rng.gen_range(65..91);
            new_data.insert(byte, random_value);
            return new_data;
        }
        5 => {
            // Insert interesting char
            let mut new_data = data.clone();
            let byte = rng.gen_range(0..data.len());
            let interesting_chars = vec![0, 7, 8, 9, 10, 11, 12, 27, 32, 127, 128, 139, 158, 169, 254, 255];
            let random_value: usize = rng.gen_range(0..interesting_chars.len()).try_into().unwrap();

            new_data.insert(byte, interesting_chars[random_value]);
            return new_data;
        }
        _ => {
            unreachable!()
        }
    }
}

pub fn mutate_date(data: Vec<u8>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let random_number: u8 = rng.gen_range(0..7);

    match random_number {
        0 => {
            // Add one to field
            let mut new_data = data.clone();
            let byte = rng.gen_range(0..data.len() - 1);
            new_data[byte] = new_data[byte].wrapping_add(1);
            return new_data;
        }
        1 => {
            // Substract one from field
            let mut new_data = data.clone();
            let byte = rng.gen_range(0..data.len() - 1);
            new_data[byte] = new_data[byte].wrapping_sub(1);
            return new_data;
        }
        2 => {
            // Change random value
            let mut new_data = data.clone();
            let random_value: u8 = rng.gen_range(0..=255);
            let byte = rng.gen_range(0..data.len());
            new_data[byte] = random_value;
            return new_data;
        }
        3 => {
            // Change last Byte
            let mut new_data = data.clone();
            let random_value: u8 = rng.gen_range(0..=255);
            let l = new_data.len();
            new_data[l - 1] = random_value;
            return new_data;
        }
        4 => {
            // Add data to end
            let mut new_data = data.clone();
            for _ in 0..rng.gen_range(1..10) {
                let random_value: u8 = rng.gen_range(0..=255);
                new_data.push(random_value);
            }
            return new_data;
        }
        5 => {
            // Insert zero
            let mut new_data = data.clone();
            let byte = rng.gen_range(0..data.len());
            new_data.insert(byte, 0);
            return new_data;
        }
        6 => {
            // Random Date
            let year: i32 = rng.gen_range(0..100); // You can adjust the range as needed

            let month: u32 = rng.gen_range(1..13);
            let day: u32 = rng.gen_range(1..31);

            let mut new_data = data.clone();

            if year < 10 {
                new_data[0] = '0' as u8;
                new_data[1] = year.to_string().chars().nth(0).unwrap() as u8;
            } else {
                new_data[0] = year.to_string().chars().nth(0).unwrap() as u8;
                new_data[1] = year.to_string().chars().nth(1).unwrap() as u8;
            }

            if month < 10 {
                new_data[2] = '0' as u8;
                new_data[3] = month.to_string().chars().nth(0).unwrap() as u8;
            } else {
                new_data[2] = month.to_string().chars().nth(0).unwrap() as u8;
                new_data[3] = month.to_string().chars().nth(1).unwrap() as u8;
            }

            if day < 10 {
                new_data[4] = '0' as u8;
                new_data[5] = day.to_string().chars().nth(0).unwrap() as u8;
            } else {
                new_data[4] = day.to_string().chars().nth(0).unwrap() as u8;
                new_data[5] = day.to_string().chars().nth(1).unwrap() as u8;
            }

            return new_data;
        }
        _ => {
            unreachable!()
        }
    }
}

pub fn mutate_content_specific(token: &mut Token) -> ContentMutation {
    let data = token.data.clone();
    let tag = token.tag.to_type_id();
    if tag == 1 {
        token.data = mutate_bool(data);
        return ContentMutation::DataSpecific;
    } else if tag == 2 {
        // Integer
        token.data = mutate_integer(data);
        return ContentMutation::DataSpecific;
    } else if tag == 3 {
        return mutate_content_random(token);
    } else if tag == 4 {
        return mutate_content_random(token);
    } else if tag == 6 {
        token.data = mutate_oid(data);
        return ContentMutation::DataSpecific;
    } else if tag == 12 || tag == 19 || tag == 25 || tag == 22 || tag == 30 || tag == 27 || tag == 29 || tag == 18 {
        token.data = mutate_string(data);
        return ContentMutation::DataSpecific;
    } else if tag == 23 || tag == 24 || tag == 31 || tag == 33 {
        token.data = mutate_date(data);
        return ContentMutation::DataSpecific;
    } else {
        return mutate_content_random(token);
    }
}

pub fn mutate_binary_data(data: &mut Vec<u8>) -> ContentMutation {
    if data.len() == 0 {
        *data = vec![0];
    }
    let mut rng = rand::thread_rng();

    // Mutation types with their probabilities
    let mutation_types = [
        (0, 20),
        (1, 15),
        (2, 20),
        (3, 15),
        (4, 10),
        (5, 10),
        (6, 10),
        (7, 10),
        (8, 20),
        (9, 20),
    ];
    let chosen_type = mutation_types.choose_weighted(&mut rng, |&(_, weight)| weight).unwrap().0;

    match chosen_type {
        0 => {
            // Bit flipping
            let byte = rng.gen_range(0..data.len());
            let bit = rng.gen_range(0..8);
            data[byte] ^= 1 << bit;

            return ContentMutation::BitFlipping;
        }
        1 => {
            // Byte flipping
            let byte = rng.gen_range(0..data.len());
            data[byte] = !data[byte];

            return ContentMutation::ByteFlipping;
        }
        2 => {
            // Arithmetic operations
            let byte = rng.gen_range(0..data.len());
            let change = rng.gen_range(1..128);
            if rng.gen_bool(0.5) {
                data[byte] = data[byte].wrapping_add(change as u8);
            } else {
                data[byte] = data[byte].wrapping_sub(change as u8);
            }

            return ContentMutation::ArithmeticOperations;
        }
        3 => {
            // Insertion of known interesting integers
            if data.len() >= 4 {
                let byte = rng.gen_range(0..(data.len() - 3));
                let interesting_ints: [u8; 5] = [0, 255, 127, 128, 1];
                let interesting_int = *interesting_ints.choose(&mut rng).unwrap();
                for i in 0..4 {
                    data[byte + i] = interesting_int;
                }
                return ContentMutation::InterestingIntegers;
            }

            return ContentMutation::NoMutation;
        }
        4 => {
            // Chunk swapping
            if data.len() > 3 {
                let size = rng.gen_range(1..(data.len() / 2));
                let first_start = rng.gen_range(0..(data.len() - 2 * size));
                let second_start = rng.gen_range((first_start + size)..(data.len() - size));
                let mut cloned = data.clone();
                data[first_start..(first_start + size)].swap_with_slice(&mut cloned[second_start..(second_start + size)]);
                return ContentMutation::ChunkSwapping;
            } else {
                return ContentMutation::NoMutation;
            }
        }
        5 => {
            // Data duplication
            if data.len() > 3 {
                let size = rng.gen_range(1..(data.len() / 2));
                let source = rng.gen_range(0..(data.len() - 2 * size));
                let target = rng.gen_range((source + size)..(data.len() - size));
                let cloned = data.clone();

                data[target..(target + size)].clone_from_slice(&cloned[source..(source + size)]);
                return ContentMutation::DataDuplication;
            } else {
                return ContentMutation::NoMutation;
            }
        }
        6 => {
            // Data insertion
            let byte = rng.gen_range(0..data.len());
            let new_data: Vec<u8> = (0..rng.gen_range(1..10)).map(|_| rng.gen()).collect();
            data.splice(byte..byte, new_data);

            return ContentMutation::DataInsertion;
        }
        7 => {
            if data.len() < 2 {
                *data = vec![data[0], data[0]];
                return ContentMutation::DataInsertion;
            }
            let max_l;
            if data.len() > 10 {
                max_l = 10;
            } else {
                max_l = data.len();
            }
            // Duplicate first X Bytes
            let mut new_data = data.clone();
            let size = rng.gen_range(1..max_l);
            let v = data[0..size].to_vec();
            new_data.splice(0..0, v);

            return ContentMutation::DataInsertion;
        }
        8 => {
            if data.len() < 2 {
                *data = vec![];
                return ContentMutation::DataRemoval;
            }
            let max_amount;
            if data.len() < 4 {
                max_amount = 2;
            } else {
                max_amount = data.len() / 2;
            }

            // Remove random bytes
            let mut to_remove = HashSet::new();
            let amount = rng.gen_range(1..max_amount);
            for _ in 0..amount {
                let mut index = rng.gen_range(0..data.len());
                while to_remove.contains(&index) {
                    index = rng.gen_range(0..data.len());
                }
                to_remove.insert(index);
            }
            let mut new_data = vec![];
            for i in 0..data.len() {
                if !to_remove.contains(&i) {
                    new_data.push(data[i]);
                }
            }
            *data = new_data;
            return ContentMutation::DataRemoval;
        }
        9 => {
            if data.len() < 2 {
                *data = vec![];
                return ContentMutation::DataRemoval;
            }
            let max_l;
            if data.len() > 10 {
                max_l = 10;
            } else {
                max_l = data.len();
            }
            // Remove first bytes
            let amount = rng.gen_range(1..max_l);
            let mut new_data = data.clone();

            new_data = new_data.split_off(amount);
            *data = new_data;
            return ContentMutation::DataRemoval;
        }
        _ => unreachable!(),
    }
}

// Random Byte mutations on content
pub fn mutate_content_random(token: &mut Token) -> ContentMutation {
    let mut data = token.data.clone();
    let ret = mutate_binary_data(&mut data);
    if ret == ContentMutation::NoMutation {
        // println!("No mutation on token {:?}", token);
    }
    token.data = data;
    ret
}

// Generic manipulation of a field
pub fn mutate_field(tree: &mut Tree, node_id: usize) -> FieldMutation {
    let mut rng = rand::thread_rng();
    let mutation_types = [(0, 10), (1, 10), (2, 20), (3, 40)];
    let chosen_type = mutation_types.choose_weighted(&mut rng, |&(_, weight)| weight).unwrap().0;

    match chosen_type {
        0 => {
            let node = tree.tokens.get_mut(&node_id).unwrap();

            let m = mutate_tag(node);
            return FieldMutation::Tag(m);
        }
        1 => {
            let node = tree.tokens.get_mut(&node_id).unwrap();

            let m = mutate_length(node);

            return FieldMutation::Length(m);
        }
        2 => {
            let children = &tree.tokens.get(&node_id).unwrap().children.clone();
            let m;
            if tree.tokens.get(&node_id).unwrap().data.is_empty() && children.len() > 0 {
                m = mutate_content_random(tree.tokens.get_mut(&children[0]).unwrap());
            } else {
                m = mutate_content_random(tree.tokens.get_mut(&node_id).unwrap());
            }
            return FieldMutation::Content(m);
        }
        3 => {
            let children = &tree.tokens.get(&node_id).unwrap().children.clone();
            let m;
            if tree.tokens.get(&node_id).unwrap().data.is_empty() && children.len() > 0 {
                m = mutate_content_specific(tree.tokens.get_mut(&children[0]).unwrap());
            } else {
                m = mutate_content_specific(tree.tokens.get_mut(&node_id).unwrap());
            }
            return FieldMutation::Content(m);
        }
        _ => unreachable!(),
    };
}

pub fn re_order(token: &mut Token) {
    let mut rng = thread_rng();

    token.children.shuffle(&mut rng);
}

pub fn delete_elements(token: &mut Token) -> Vec<usize> {
    let mut rng = rand::thread_rng();
    let mut distr = vec![];
    if token.children.len() == 0 {
        return Vec::new();
    }
    for i in 1..token.children.len() + 1 {
        distr.push(i);
    }
    distr.reverse();

    let dist = WeightedIndex::new(&distr).unwrap();

    let amount = dist.sample(&mut rng) + 1;

    let mut to_remove = HashSet::new();
    for _ in 0..amount {
        let mut index = rng.gen_range(0..token.children.len());
        while to_remove.contains(&index) {
            index = rng.gen_range(0..token.children.len());
        }
        to_remove.insert(index);
    }

    let mut ret = Vec::with_capacity(to_remove.len());
    for i in to_remove.iter() {
        ret.push(token.children[*i]);
    }

    // Remove the children from the token
    token.children = token
        .children
        .iter()
        .enumerate()
        .filter(|&(i, _)| !to_remove.contains(&i))
        .map(|(_, v)| v.clone())
        .collect();

    ret
}

// Duplicate child elements
pub fn duplicate_elements(token: &mut Token) {
    if token.children.len() == 0 {
        return;
    }
    let mut rng = rand::thread_rng();
    let mut distr = vec![];
    for i in 0..token.children.len() {
        distr.push(i + 1);
    }
    distr.reverse();

    let dist = WeightedIndex::new(&distr).unwrap();

    // Draws a value from the distribution according to weights. 1 is the most likely value.
    let amount = dist.sample(&mut rng) + 1;

    let mut used = vec![];
    for _ in 0..amount {
        let mut index = rng.gen_range(0..token.children.len());
        while used.contains(&index) {
            index = rng.gen_range(0..token.children.len());
        }
        used.push(index);
        let c = token.children[index];
        token.children.push(c.clone());
    }
}

pub fn mutate_sequence(tree: &mut Tree, node_id: usize) -> SequenceMutation {
    let mut rng = rand::thread_rng();
    let random_number: u8 = rng.gen_range(0..4);
    match random_number {
        0 => {
            let node = tree.tokens.get_mut(&node_id).unwrap();

            re_order(node);
            return SequenceMutation::ReOrder;
        }
        1 => {
            let node = tree.tokens.get_mut(&node_id).unwrap();

            duplicate_elements(node);
            return SequenceMutation::DuplicateElements;
        }
        2 => {
            // Delete children of this node
            let node = tree.tokens.get_mut(&node_id).unwrap();

            let deleted = delete_elements(node);
            for d in deleted {
                tree.deep_delete(d);
            }

            return SequenceMutation::DeleteElements;
        }
        3 => {
            // Add element
            let mut max_id = 0;
            for (k, _) in &tree.tokens {
                if *k > max_id {
                    max_id = *k;
                }
            }
            let new_id = max_id + 1;
            let nt = rng.gen_range(0..50);
            let mut new_token = Token::new(Types::TLV, 1, vec![0], node_id, new_id, nt);
            new_token.visual_tag = vec![nt];
            tree.tokens.insert(new_id, new_token);

            tree.tokens.get_mut(&node_id).unwrap().children.push(new_id);
            return SequenceMutation::AddElement;
        }
        _ => unreachable!(),
    }
}

pub fn mutate_tlv(tree: &mut Tree, node_id: usize) -> TokenMutation {
    return TokenMutation::Tlv(mutate_field(tree, node_id));
}

pub fn mutate_octetstring(tree: &mut Tree, node_id: usize) -> TokenMutation {
    let mut rng = rand::thread_rng();
    let random_number: u8 = rng.gen_range(0..1);

    match random_number {
        0 => {
            let c = &tree.tokens[&node_id].children;
            let m;
            if c.len() > 0 {
                m = mutate_field(tree, c[0]);
            } else {
                m = mutate_field(tree, node_id);
            }
            return TokenMutation::OctetString(ConstructedMutation::Field(m));
        }
        _ => unreachable!(),
    }
}

pub fn mutate_implicit(tree: &mut Tree, node_id: usize) -> TokenMutation {
    // let node = tree.tokens.get_mut(&node_id).unwrap();
    let mut rng = rand::thread_rng();
    let random_number: u8 = rng.gen_range(0..1);

    match random_number {
        0 => {
            let c = &tree.tokens[&node_id].children;
            let m;
            if c.len() > 0 {
                m = mutate_field(tree, c[0]);
            } else {
                m = mutate_field(tree, node_id);
            }

            return TokenMutation::Implicit(ConstructedMutation::Field(m));
        }
        _ => unreachable!(),
    }
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Mutation {
    pub mutation: TokenMutation,
    pub node_id: usize,
}

impl Mutation {
    pub fn get_mutation_string(&self) -> String {
        return format!("{:?}", self.mutation);
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum TokenMutation {
    Tlv(FieldMutation),
    Sequence(SequenceMutation),
    Set(SequenceMutation),
    OctetString(ConstructedMutation),
    Implicit(ConstructedMutation),
    NoMutation,
}

impl TokenMutation{
    pub fn is_no_mutation(&self) -> bool {
        matches!(self, TokenMutation::NoMutation) || format!("{:?}", self).contains("NoMutation")
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ConstructedMutation {
    Field(FieldMutation),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum FieldMutation {
    Tag(ValueMutation),
    Length(ValueMutation),
    Content(ContentMutation),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ValueMutation {
    Zero,
    Max,
    Add,
    Substract,
    NextPowerOfTwo,
    PreviousPowerOfTwo,
    Random,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ContentMutation {
    BitFlipping,
    ByteFlipping,
    ArithmeticOperations,
    InterestingIntegers,
    ChunkSwapping,
    DataDuplication,
    DataInsertion,
    DataSpecific,
    NoMutation,
    DataRemoval,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum SequenceMutation {
    Field(FieldMutation),
    ReOrder,
    DeleteElements,
    DuplicateElements,
    AddElement,
}
