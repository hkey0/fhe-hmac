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

fn hex_to_bools(hex_value: u32) -> [bool; 32] {
    let mut bool_array = [false; 32];
    let mut mask = 0x8000_0000;

    for i in 0..32 {
        bool_array[i] = (hex_value & mask) != 0;
        mask >>= 1;
    }

    bool_array
}


pub fn trivial_bools(bools: &[bool; 32], sk: &ServerKey) -> Vec<Ciphertext> {

    vec![
        sk.trivial_encrypt(bools[0]), sk.trivial_encrypt(bools[1]), sk.trivial_encrypt(bools[2]), sk.trivial_encrypt(bools[3]),
        sk.trivial_encrypt(bools[4]), sk.trivial_encrypt(bools[5]), sk.trivial_encrypt(bools[6]), sk.trivial_encrypt(bools[7]),
        sk.trivial_encrypt(bools[8]), sk.trivial_encrypt(bools[9]), sk.trivial_encrypt(bools[10]), sk.trivial_encrypt(bools[11]),
        sk.trivial_encrypt(bools[12]), sk.trivial_encrypt(bools[13]), sk.trivial_encrypt(bools[14]), sk.trivial_encrypt(bools[15]),
        sk.trivial_encrypt(bools[16]), sk.trivial_encrypt(bools[17]), sk.trivial_encrypt(bools[18]), sk.trivial_encrypt(bools[19]),
        sk.trivial_encrypt(bools[20]), sk.trivial_encrypt(bools[21]), sk.trivial_encrypt(bools[22]), sk.trivial_encrypt(bools[23]),
        sk.trivial_encrypt(bools[24]), sk.trivial_encrypt(bools[25]), sk.trivial_encrypt(bools[26]), sk.trivial_encrypt(bools[27]),
        sk.trivial_encrypt(bools[28]), sk.trivial_encrypt(bools[29]), sk.trivial_encrypt(bools[30]), sk.trivial_encrypt(bools[31]),
    ]
}

fn fhe_xor(a: &Vec<Ciphertext>, b: &Vec<Ciphertext>, sk: &ServerKey) -> Vec<Ciphertext> {
    let mut result = Vec::with_capacity(a.len());

    for i in 0..a.len() {
        result.push(sk.xor(&a[i], &b[i]));
    }
    result
}

fn fhe_and(a: &Vec<Ciphertext>, b: &Vec<Ciphertext>, sk: &ServerKey) -> Vec<Ciphertext> {
    let mut result = Vec::with_capacity(a.len());

    for i in 0..a.len() {
        result.push(sk.and(&a[i], &b[i]));
    }
    result
}


fn fhe_or(a: &Vec<Ciphertext>, b: &Vec<Ciphertext>, sk: &ServerKey) -> Vec<Ciphertext> {
    let mut result = Vec::with_capacity(a.len());

    for i in 0..a.len() {
        result.push(sk.or(&a[i], &b[i]));
    }
    result
}

fn fhe_not(a: &Vec<Ciphertext>, sk: &ServerKey) -> Vec<Ciphertext> {
    let mut result = Vec::with_capacity(32);

    for bit in a {
        result.push(sk.not(bit));
    }
    result
}

pub fn add(a: &Vec<Ciphertext>, b: Vec<Ciphertext>, sk: &ServerKey) -> Vec<Ciphertext> {
    let propagate = fhe_xor(&a, &b, &sk); // Parallelized bitwise XOR
    let generate = fhe_and(&a, &b, &sk); // Parallelized bitwise AND

    let carry = compute_carry(&propagate, &generate, &sk);
    let sum = fhe_xor(&propagate, &carry, &sk); // Parallelized bitwise XOR

    sum
}


fn compute_carry(propagate: &Vec<Ciphertext>, generate: &Vec<Ciphertext>, sk: &ServerKey) -> Vec<Ciphertext> {
    let mut carry = trivial_bools(&[false; 32], sk);
    carry[31] = sk.trivial_encrypt(false);

    for i in (0..31).rev() {
        carry[i] = sk.or(&generate[i + 1], &sk.and(&propagate[i + 1], &carry[i + 1]));
    }

    carry
}


pub fn fhe_sha(mut data: Vec<Ciphertext>, sk: &ServerKey, ck: &ClientKey) -> Vec<Ciphertext> {

    let mut h0 = trivial_bools(&hex_to_bools(0x67452301), &sk);
    let mut h1 = trivial_bools(&hex_to_bools(0xEFCDAB89), &sk);
    let mut h2 = trivial_bools(&hex_to_bools(0x98BADCFE), &sk);
    let mut h3 = trivial_bools(&hex_to_bools(0x10325476), &sk);
    let mut h4 = trivial_bools(&hex_to_bools(0xC3D2E1F0), &sk);
    // padding phase
    
    // - push "1" bit 
    let data_len = u64_to_bool_vec(data.len() as u64);
    data.push(sk.trivial_encrypt(true));

    // - pad with zeros
    while data.len() % 512 != 448 {
        data.push(sk.trivial_encrypt(false));
    }
    // - push data len
    for bit in data_len {
        data.push(sk.trivial_encrypt(bit));
    }

    // W
    let mut w: Vec<Vec<Ciphertext>> = Vec::with_capacity(80);
    for chunk in data.chunks(32) {
        w.push(chunk.to_vec());
    } 

    for i in 16..=79 {
        let mut r = fhe_xor(&fhe_xor(&fhe_xor(&w[i-3], &w[i-8], sk), &w[i-14], &sk), &w[i-16], &sk);
        r.rotate_left(1);

        w.push(r);
    }
    
    let mut a = h0.clone();
    let mut b = h1.clone();
    let mut c = h2.clone();
    let mut d = h3.clone();
    let mut e = h4.clone();

    let k_vals = [
         trivial_bools(&hex_to_bools(0x5A827999), &sk),
         trivial_bools(&hex_to_bools(0x6ED9EBA1), &sk),
         trivial_bools(&hex_to_bools(0x8F1BBCDC), &sk),
         trivial_bools(&hex_to_bools(0xCA62C1D6), &sk)
    ];

    for i in 0..=79 {
        let mut f  = vec![];
        let mut k = vec![];

        match i {
            0..=19 => {
                f = fhe_or(&fhe_and(&b,  &c, &sk), &fhe_and(&fhe_not(&b, &sk), &d, &sk), &sk);
                k = k_vals[0].clone();
            },
            20..=39 => {
                f = fhe_xor(&fhe_xor(&b, &c, &sk), &d, &sk);
                k = k_vals[1].clone();
            },
            40..=59 => {
                f = fhe_or(&fhe_or(&fhe_and(&b, &c, &sk),  &fhe_and(&b, &d, &sk), &sk), &fhe_and(&c,  &d, &sk), &sk);
                k = k_vals[2].clone();
            },
            60..=79 => {
                f = fhe_xor(&fhe_xor(&b, &c, &sk), &d, &sk);
                k = k_vals[3].clone();
            },
            _ => {} 
            
        };

        let mut tempa = a.clone();
        tempa.rotate_left(5);

        let temp = add(&add(&add(&tempa, f, &sk), add(&e, k, &sk), &sk), w[i].clone(), &sk);  
        e = d;
        d = c;
        let mut tempb = b.clone();
        tempb.rotate_left(30);
        c = tempb;
        b = a;
        a = temp;

        println!("ROUND {i}");
    };

    h0 = add(&h0, a, &sk);
    h1 = add(&h1, b, &sk);
    h2 = add(&h2, c, &sk);
    h3 = add(&h3, d, &sk);
    h4 = add(&h4, e, &sk);

    for i in 0..128 {
        h0.push(sk.trivial_encrypt(false));
        h4.insert(0, sk.trivial_encrypt(false));
    }

    for i in 0..96 {
        h1.push(sk.trivial_encrypt(false));
        h3.insert(0, sk.trivial_encrypt(false));
    }

    for i in 0..64 {
        h2.push(sk.trivial_encrypt(false));
        h2.insert(0, sk.trivial_encrypt(false));
    }
    
    for i in 0..32 {
        h3.push(sk.trivial_encrypt(false));
        h1.insert(0, sk.trivial_encrypt(false));
    }


    let hh = fhe_or(&fhe_or(
        &fhe_or(&h0, &h1, &sk),
        &fhe_or(&h2, &h3, &sk),
        &sk
    ), &h4, &sk);

    hh
}

fn shift_left(x: Vec<Ciphertext>, n: usize, sk: &ServerKey) -> Vec<Ciphertext> {
    let mut result = trivial_bools(&[false; 32], sk);
    for i in 0..(32 - n) {
        result[i] = x[i + n].clone();
    }
    result
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

    let result = fhe_sha(en_data.clone(), &sk, &ck);

    let mut dc_data = vec![];

    for d in result {
        dc_data.push(ck.decrypt(&d));
    }
    println!("{:?}", dc_data);
}
