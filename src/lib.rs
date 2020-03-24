use itertools::*;
use lazy_static::*;
use rand::distributions::*;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ops::DerefMut;
use std::sync::{Mutex, MutexGuard};
use unicode_segmentation::UnicodeSegmentation;
use unidecode::unidecode_char;
use Result::{Err, Ok};

const FILTERED_CHARS: [char; 31] = [
    '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '{', '}', '_', '<', '>', ':', ';', ',', '.',
    '"', '\'', '`', '|', '+', '=', '/', '~', '[', ']', '\\', '-',
];

///True if we should keep the character is the string.
fn should_keep_char(c: &char) -> bool {
    !FILTERED_CHARS.contains(c)
}
lazy_static! {
    ///Special chars that should be filtered out.
    static ref ALL_U32: Uniform<u32> = Uniform::new_inclusive(0u32, u32::max_value());
    //We use this so we don't have to generate the floating numbers and do comparisons on them. It allows us to do 1/2 percent level scaling.
    static ref ONE_TO_TWO_HUNDRED: Uniform<u8> = Uniform::new_inclusive(1, 200);
}

///Something over 200 chars isn't really suitable for this approach, so we won't accept it.
const MAX_STRING_LEN: usize = 200;

/// Make an index, for the string s considering all tri-grams.
/// The string will be latinised, lowercased and stripped of special chars before being broken into tri-grams.
/// The values will be prefixed with partition_id and salt before being hashed.
/// Each entry in the HashSet will be truncated to 32 bits and will be encoded as a big endian number.
/// This function will also add some random entries to the HashSet to not expose how many tri-grams were actually found.
pub fn generate_hashes_for_string_with_padding<R: Rng + CryptoRng>(
    s: &str,
    partition_id: Option<&str>,
    salt: &[u8],
    rng: &Mutex<R>,
) -> Result<HashSet<u32>, String> {
    let mut hashes = generate_hashes_for_string(s, partition_id, salt)?;

    let prob = take_lock(&rng).deref_mut().sample(*ONE_TO_TWO_HUNDRED);
    let to_add: u8 = {
        //Just take the lock once because we need it in all cases and it makes the code look better.
        let r = &mut *take_lock(&rng);
        if prob <= 1 {
            r.gen_range(1, 200)
        } else if prob <= 5 {
            r.gen_range(1, 30)
        } else if prob <= 50 {
            r.gen_range(1, 10)
        } else {
            r.gen_range(1, 5)
        }
    };
    //This will never be negative because generate_hashes_for_string would error if hashes was going to be larger than and will never be larger than MAX_STRING_LEN.
    //This also ensures we're able to pad by at least 2 since the maximum trigram length is always 2 less than the max string length.
    let pad_len = std::cmp::min(MAX_STRING_LEN - hashes.len(), to_add as usize);
    hashes.extend(
        take_lock(&rng)
            .deref_mut()
            .sample_iter(*ALL_U32)
            .take(pad_len),
    );
    Ok(hashes)
}

/// Make an index, for the string s considering all tri-grams.
/// The string will be latinised, lowercased and stripped of special chars before being broken into tri-grams.
/// The values will be prefixed with partition_id and salt before being hashed.
/// Each entry in the HasheSet will be truncated to 32 bits and will be encoded as a big endian number.
/// If the string is longer than 200 characters, this will return an error.
pub fn generate_hashes_for_string(
    s: &str,
    partition_id: Option<&str>,
    salt: &[u8],
) -> Result<HashSet<u32>, String> {
    if s.len() > MAX_STRING_LEN {
        Err(format!("The input string is too long. This function only supports strings that are no longer than {} chars.", MAX_STRING_LEN))
    } else {
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

        let result: HashSet<_> = make_tri_grams(s)
            .iter()
            .map(|tri_gram| short_hash(tri_gram.as_bytes()))
            .collect();
        Ok(result)
    }
}

/// If s is empty, the resulting set will also be empty.
/// If s is shorter than 3, '-' padding will be added to the end.
/// All Strings inside of the resulting set will always be of size 3.
fn make_tri_grams(s: &str) -> HashSet<String> {
    let converted_string: String = s
        .chars()
        .filter(should_keep_char)
        .map(char_to_trans)
        .collect();
    converted_string
        .unicode_words()
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

/// Acquire mutex in a blocking fashion. If the Mutex is or becomes poisoned, panic.
///
/// The lock is released when the returned MutexGuard falls out of scope.
///
/// # Usage:
/// single statement (mut)
/// `let result = take_lock(&t).deref_mut().call_method_on_t();`
///
/// multi-statement (mut)
///
/// ```ignore
/// let t = T {};
/// let result = {
///     let g = &mut *take_lock(&t);
///     g.call_method_on_t()
/// }; // lock released here
/// ```
///
fn take_lock<T>(m: &Mutex<T>) -> MutexGuard<T> {
    m.lock().unwrap_or_else(|e| {
        let error = format!("Error when acquiring lock: {}", e);
        panic!(error);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::ThreadRng;

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
    fn generate_hashes_for_string_compute_known_value() -> Result<(), String> {
        let result = generate_hashes_for_string("123", Some("foo"), &[0u8; 1])?;
        //We compute this to catch cases where this computation might change.
        let expected_result = {
            let mut hasher = Sha256::new();
            hasher.input("foo".as_bytes());
            hasher.input([0u8; 1]);
            hasher.input("123");
            as_u32_be(&(hasher.result().into()))
        };
        assert_eq!(result, [expected_result].iter().map(|x| *x).collect());
        Ok(())
    }

    #[test]
    fn generate_hashes_for_string_with_padding_adds_at_least_one() -> Result<(), String> {
        let rng = Mutex::new(ThreadRng::default());
        let result = generate_hashes_for_string_with_padding("123", Some("foo"), &[0u8; 1], &rng)?;
        assert!(result.len() > 1);
        Ok(())
    }

    #[test]
    fn generate_hashes_for_string_with_padding_empty_string() -> Result<(), String> {
        let rng = Mutex::new(ThreadRng::default());
        let result = generate_hashes_for_string_with_padding("", Some("foo"), &[0u8; 1], &rng)?;
        assert!(result.len() >= 1);
        Ok(())
    }

    #[test]
    fn generate_hashes_for_string_too_long_errors() -> Result<(), String> {
        let rng = ThreadRng::default();
        let input: String = rng
            .sample_iter(rand::distributions::Alphanumeric)
            .take(201)
            .collect();
        generate_hashes_for_string(&input, Some("foo"), &[0u8; 1]).unwrap_err();
        Ok(())
    }
}
