use super::*;

 #[test]
 fn test_one(){
    // bit representation of "abc" 
    sha1_hash(vec![
        false, true, true, false, false, false, false, true, false, 
         true, true, false, false, false, true, false, false, true,
        true, false, false, false, true, true
    ]);
}
