use lazy_static::*;
use regex::Regex;
use sha2::{Digest, Sha256};
use voca_rs::*;

lazy_static! {
    ///Special chars that should be filtered out.
    static ref SPECIAL_CHAR: Regex = Regex::new("[!@#$%^&*(){}_-]").unwrap_or_else(|e| panic!("Developer error. Bad regex {:?}", e));
}

pub fn make_index(s: &str, key: &str, salt: &[u8]) -> Vec<u32> {
    make_index_n_grams(s: &str, 3, key: &str, salt: &[u8])
}

///
/// Make an index, for the string s considering all n-grams of length size.
/// The string will be latinised, lowercased and stripped of special chars before being broken into ngrams.
/// The values will be prefixed with key and salt before being hashed.
/// Each entry in the Vec will be truncated to 32 bits and will be encoded as a big endian number.
///
pub fn make_index_n_grams(s: &str, size: usize, key: &str, salt: &[u8]) -> Vec<u32> {
    let short_hash = |word: &[u8]| -> u32 {
        let mut hasher = Sha256::new();
        hasher.input(key.as_bytes());
        hasher.input(salt);
        hasher.input(word);
        as_u32_be_unsafe(dbg!(&hasher.result()[..]))
    };

    make_n_grams(s, size)
        .iter()
        .map(|ngram| short_hash(&ngram[..]))
        .collect()
}

///
/// If s is empty, the resulting vec will also be empty.
/// If s is shorter than n, space padding will be added to the end.
/// All Vec<u8> inside of the resulting Vec will always be of size `n`.
pub fn make_n_grams(s: &str, n: usize) -> Vec<Vec<u8>> {
    let s_with_special_chars = s._latinise()._lower_case();
    let normalized_string = SPECIAL_CHAR.replace_all(s_with_special_chars.as_str(), "");
    let result = normalized_string
        ._words()
        .into_iter()
        //This is safe because we know that each char can only be a single byte - See Latinise
        .flat_map(|word| match word.as_bytes() {
            [] => vec![],
            //If the word is too short, it must be padded out to the size.
            non_empty_word if non_empty_word.len() < n => {
                let padded = pad_bytes(non_empty_word, n);
                vec![padded]
            }
            non_empty_word => non_empty_word
                .windows(n)
                .map(|bytes| bytes.to_vec())
                .collect(),
        })
        .collect::<Vec<_>>();
    result
}
//Pads the bytes out with spaces at the end.
fn pad_bytes(bytes: &[u8], size: usize) -> Vec<u8> {
    let mut word = vec![32u8; size];
    word.copy_from_slice(bytes);
    word
}

///This is marked as unsafe because it indexes into the arrays directly.
fn as_u32_be_unsafe(slice: &[u8]) -> u32 {
    ((slice[0] as u32) << 24)
        + ((slice[1] as u32) << 16)
        + ((slice[2] as u32) << 8)
        + ((slice[3] as u32) << 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn make_trigrams_string(name: &str) -> Vec<String> {
        bytes_to_chars(make_n_grams(name, 3))
    }
    fn bytes_to_chars(b: Vec<Vec<u8>>) -> Vec<String> {
        b.into_iter()
            .map(|bytes| std::str::from_utf8(&bytes[..]).unwrap().to_string())
            .collect()
    }
    #[test]
    fn make_n_grams_works() {
        let expected = vec![
            "123", "jos", "ose", "nun", "une", "nez", "812", "121", "211", "111", "117", "176",
            "765", "654",
        ];
        assert_eq!(
            make_trigrams_string("123 José Núñez 812-111-7654"),
            expected
        );
    }

    #[test]
    fn make_n_grams_works_non_ascii() {
        assert_eq!(
            make_trigrams_string("TİRYAKİ"),
            ["tir", "iry", "rya", "yak", "aki"]
        );
    }
    #[test]
    fn make_index_works_compute_known_value() {
        let result = make_index("123", "foo", &[0u8; 32]);
        let expected_result = {
            let mut hasher = Sha256::new();
            hasher.input("foo".as_bytes());
            hasher.input([0u8; 32]);
            hasher.input("123");
            as_u32_be_unsafe(&hasher.result()[..])
        };
        assert_eq!(result, vec![expected_result]);
    }
}
