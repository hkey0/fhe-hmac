use num_bigint::BigUint;


pub fn vec_to_u32(bits: &[bool]) -> u32 {
    let mut result = 0;

    for (index, bit) in bits.iter().enumerate() {
        if *bit {
            result |= 1 << (31 - index);
        }
    }
    result
}

fn u64_to_bool_vec(mut num: u64) -> Vec<bool> {
    let mut bits = Vec::with_capacity(64); 

    for _ in 0..64 {
        bits.push(num & 1 == 1);
        num >>= 1;  
    }
    bits.reverse();  
    bits
}

pub fn sha1_hash(message: Vec<bool>) -> BigUint {
    let mut msg = message.clone();
    let mut w: Vec<u32> = Vec::with_capacity(80);
    msg.push(true);

    let new_pad: Vec<bool> = u64_to_bool_vec(message.len() as u64);
    
    while msg.len() % 512 != 448 {
        msg.push(false);
    }

    for i in new_pad {
        msg.push(i);
    }

    println!("sss {:?}  len is {}", msg, msg.len());

    let iter = msg.chunks(32);
    for chunk in iter {
        w.push(vec_to_u32(chunk));
    }
    
    for i  in 16..=79 {
        let val = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1) ;
        w.push(val);
    };

    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xEFCDAB89;
    let mut c: u32 = 0x98BADCFE;
    let mut d: u32 = 0x10325476;
    let mut e: u32 = 0xC3D2E1F0;

    for i in 0..=79 {
        let mut f: u32 = 0;
        let mut k: u32 = 0;

        match i {
            0..=19 => {
                f = (b & c) | ((!b) & d);
                k = 0x5A827999;
            },
            20..=39 => {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            },
            40..=59 => {
                f = (b & c) |  (b & d) | (c & d);
                k = 0x8F1BBCDC;
            },
            60..=79 => {
                f = b ^ c ^ d; 
                k = 0xCA62C1D6;
            },
            _ => {} 
            
        };
        let temp = (a.rotate_left(5)) + f + e + k + w[i];
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    };
    
    let h0 = BigUint::from(0x67452301 + a); 
    let h1 = BigUint::from(0xEFCDAB89 + b); 
    let h2 = BigUint::from(0x98BADCFE + c); 
    let h3 = BigUint::from(0x10325476 + d);  
    let h4 = BigUint::from(0xC3D2E1F0 + e); 

    let hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32_u8) | h4;
    hh
}


#[cfg(test)]
mod test;

