use itertools::*;
use lazy_static::*;
use regex::Regex;
use sha2::{Digest, Sha256};
use unidecode::unidecode_char;
use voca_rs::*;

lazy_static! {
    ///Special chars that should be filtered out.
    static ref SPECIAL_CHAR: Regex = Regex::new(r#"[!@#$%^&*(){}_<>:;,."'`|+=/~\[\]\\-]"#).unwrap_or_else(|e| panic!("Developer error. Bad regex {:?}", e));
}

/// Make an index, for the string s considering all tri-grams.
/// The string will be latinised, lowercased and stripped of special chars before being broken into tri-grams.
/// The values will be prefixed with partition_id and salt before being hashed.
/// Each entry in the Vec will be truncated to 32 bits and will be encoded as a big endian number.
pub fn generate_hashes_for_string(s: &str, partition_id: Option<&str>, salt: &[u8]) -> Vec<u32> {
    let short_hash = |word: &[u8]| -> u32 {
        let mut hasher = Sha256::new();
        partition_id.iter().for_each(|k| hasher.input(k.as_bytes()));
        hasher.input(salt);
        hasher.input(word);
        as_u32_be(&hasher.result().into())
    };

    make_tri_grams(s)
        .iter()
        .map(|tri_gram| short_hash(tri_gram.as_bytes()))
        .collect()
}

/// If s is empty, the resulting vec will also be empty.
/// If s is shorter than 3, '-' padding will be added to the end.
/// All Strings inside of the resulting Vec will always be of size 3.
pub fn make_tri_grams(s: &str) -> Vec<String> {
    let string_without_special_chars = SPECIAL_CHAR.replace_all(s, "");
    let converted_string: String = string_without_special_chars
        .chars()
        .flat_map(|c| {
            let s: String = char_to_trans(c);
            s.chars().collect::<Vec<_>>()
        })
        .collect();
    let result = converted_string
        ._words()
        .into_iter()
        .map(|short_word| {
            let short_word_len = short_word.chars().count();
            if short_word_len < 3 {
                //Pad the short_word with
                format!("{:-<3}", short_word)
            } else {
                short_word.to_string()
            }
        })
        .flat_map(|word| word_to_trigrams(&word))
        .collect::<Vec<_>>();
    result
}

pub fn word_to_trigrams(s: &str) -> Vec<String> {
    s.chars()
        .tuple_windows()
        .map(|(c1, c2, c3)| {
            let mut result = String::with_capacity(3);
            result.push(c1);
            result.push(c2);
            result.push(c3);
            result
        })
        .collect()
}

///Convert the char if we can, if we can't just create a string out of the character.
fn char_to_trans(c: char) -> String {
    let trans_string = unidecode_char(c);
    if trans_string == "" {
        format!("{}", c)
    } else {
        trans_string.to_lowercase()
    }
}

///Interpret the first 4 bytes as a u32
#[inline]
fn as_u32_be(slice: &[u8; 32]) -> u32 {
    ((slice[0] as u32) << 24)
        + ((slice[1] as u32) << 16)
        + ((slice[2] as u32) << 8)
        + ((slice[3] as u32) << 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn make_tri_grams_works_multi_word() {
        assert_eq!(
            make_tri_grams("123 José  Núñez 812-111-7654"),
            vec![
                "123", "jos", "ose", "nun", "une", "nez", "812", "121", "211", "111", "117", "176",
                "765", "654",
            ]
        );
    }

    #[test]
    fn make_tri_grams_works_non_ascii() {
        assert_eq!(
            make_tri_grams("TİRYAKİ"),
            ["tir", "iry", "rya", "yak", "aki"]
        );
    }

    #[test]
    fn make_tri_grams_works_short_non_ascii() {
        assert_eq!(make_tri_grams("Tİ"), ["ti-"]);
    }

    #[test]
    fn make_tri_grams_works_multichar_translate() {
        assert_eq!(make_tri_grams("志    豪 İ"), ["zhi", "hao", "i--"]);
    }

    #[test]
    fn make_tri_grams_works_arabic() {
        assert_eq!(make_tri_grams("شريط فو"), ["shr", "hry", "ryt", "fw-"]);
    }
    #[test]
    fn make_tri_grams_works_short_multibyte() {
        assert_eq!(
            make_tri_grams("\u{102AE}\u{102AF}"),
            ["\u{102AE}\u{102AF}-"]
        );
    }

    #[test]
    fn char_to_trans_latinizable() {
        assert_eq!(char_to_trans('İ'), "i")
    }

    #[test]
    fn char_to_trans_not_latinizable() {
        let c = "\u{102AE}".chars().nth(0).unwrap();
        assert_eq!(char_to_trans(c), "\u{102AE}")
    }
    #[test]
    fn generate_hashes_for_string_compute_known_value() {
        let result = generate_hashes_for_string("123", Some("foo"), &[0u8; 1]);
        //We compute this to catch cases where this computation might change.
        let expected_result = {
            let mut hasher = Sha256::new();
            hasher.input("foo".as_bytes());
            hasher.input([0u8; 1]);
            hasher.input("123");
            as_u32_be(&(hasher.result().into()))
        };
        assert_eq!(result, vec![expected_result]);
    }
}
