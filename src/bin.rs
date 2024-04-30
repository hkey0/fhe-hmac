use tfhe::boolean::prelude::*;

fn u64_to_bool_vec(mut num: u64) -> Vec<bool> {
    let mut bits = Vec::with_capacity(64); 

    for _ in 0..64 {
        bits.push(num & 1 == 1);
        num >>= 1;  
    }
    bits.reverse();  
    println!("bool vec {:?}", bits);
    bits
}

fn main() {
    let (ck, sk) = gen_keys();
    let data: Vec<bool> = vec![
        false, true, true, false, false, false, false, true, false, 
        true, true, false, false, false, true, false, false, true,
        true, false, false, false, true, true
    ];

    let mut en_data = vec![];
    
    for d in data {
        en_data.push(ck.encrypt(d)); 
    }

    // padding phase
    
    // - push "1" bit 
    let data_len = u64_to_bool_vec(en_data.len() as u64);
    en_data.push(sk.trivial_encrypt(true));

    
    // - pad with zeros
    while en_data.len() % 512 != 448 {
        en_data.push(sk.trivial_encrypt(false));
    }

    // - push data len
    for bit in data_len {
        en_data.push(sk.trivial_encrypt(bit));
    }
    

    let mut dc_data = vec![];
    for d in en_data {
        dc_data.push(ck.decrypt(&d));
    }
    println!("{:?}", dc_data);
}
