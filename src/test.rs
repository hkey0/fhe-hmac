use super::*;

 #[test]
 fn test_one(){
    // bit representation of "abc" 
    let hexdigest = sha1_hash(vec![
        false, true, true, false, false, false, false, true, false, 
         true, true, false, false, false, true, false, false, true,
        true, false, false, false, true, true
    ]);

    assert_eq!(format!("{:x}", hexdigest), "a9993e364706816aba3e25717850c26c9cd0d89d");
}


