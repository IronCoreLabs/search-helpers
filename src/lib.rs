use itertools::*;
use lazy_static::*;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
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
pub fn generate_hashes_for_string(
    s: &str,
    partition_id: Option<&str>,
    salt: &[u8],
) -> HashSet<u32> {
    //Compute a partial sha256 with the partition_id and the salt - We can reuse this for each word
    let partial_sha256 = partition_id
        .map(|k| k.as_bytes())
        .iter()
        .chain([salt].iter())
        .fold(Sha256::new(), |hasher, k| hasher.chain(k));

    let short_hash = |word: &[u8]| -> u32 {
        let sha256_hash = partial_sha256.clone().chain(word);
        as_u32_be(&sha256_hash.result().into())
    };

    make_tri_grams(s)
        .iter()
        .map(|tri_gram| short_hash(tri_gram.as_bytes()))
        .collect()
}

/// If s is empty, the resulting set will also be empty.
/// If s is shorter than 3, '-' padding will be added to the end.
/// All Strings inside of the resulting set will always be of size 3.
fn make_tri_grams(s: &str) -> HashSet<String> {
    let string_without_special_chars = SPECIAL_CHAR.replace_all(s, "");
    let converted_string: String = string_without_special_chars
        .chars()
        .map(char_to_trans)
        .collect();
    converted_string
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
        .collect()
}

fn word_to_trigrams(s: &str) -> HashSet<String> {
    s.chars()
        .tuple_windows()
        .map(|(c1, c2, c3)| format!("{}{}{}", c1, c2, c3))
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

///Interpret the most significant 4 bytes as a bigendian u32
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

    fn make_set(array: &[&str]) -> HashSet<String> {
        array
            .into_iter()
            .map(|&s| From::from(s))
            .collect::<HashSet<_>>()
    }

    #[test]
    fn as_u32_be_known_result() {
        let known_result = 16909060u32; //16777216 + 131072 + 768 + 4
        let mut input = [0u8; 32];
        input[0] = 1;
        input[1] = 2;
        input[2] = 3;
        input[3] = 4;
        let result = as_u32_be(&input);
        assert_eq!(result, known_result);
    }

    #[test]
    fn word_to_trigrams_known() {
        let result = word_to_trigrams("five");
        assert_eq!(result, make_set(&["fiv", "ive"]));
    }

    #[test]
    fn make_tri_grams_works_multi_word() {
        assert_eq!(
            make_tri_grams("123 José  Núñez 812-111-7654"),
            make_set(&[
                "123", "jos", "ose", "nun", "une", "nez", "812", "121", "211", "111", "117", "176",
                "765", "654",
            ])
        );
    }

    #[test]
    fn make_tri_grams_works_non_ascii() {
        assert_eq!(
            make_tri_grams("TİRYAKİ"),
            make_set(&["tir", "iry", "rya", "yak", "aki"])
        );
    }

    #[test]
    fn make_tri_grams_eliminates_duplicates() {
        assert_eq!(
            make_tri_grams("TİRYAKİ TİRYAKİ"),
            make_set(&["tir", "iry", "rya", "yak", "aki"])
        );
    }

    #[test]
    fn make_tri_grams_works_short_non_ascii() {
        assert_eq!(make_tri_grams("Tİ"), make_set(&["ti-"]));
    }

    #[test]
    fn make_tri_grams_works_multichar_translate() {
        assert_eq!(
            make_tri_grams("志    豪 İ"),
            make_set(&["zhi", "hao", "i--"])
        );
    }

    #[test]
    fn make_tri_grams_works_arabic() {
        assert_eq!(
            make_tri_grams("شريط فو"),
            make_set(&["shr", "hry", "ryt", "fw-"])
        );
    }
    #[test]
    fn make_tri_grams_works_short_multibyte() {
        assert_eq!(
            make_tri_grams("\u{102AE}\u{102AF}"),
            make_set(&["\u{102AE}\u{102AF}-"])
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
        assert_eq!(result, [expected_result].iter().map(|x| *x).collect());
    }
}
