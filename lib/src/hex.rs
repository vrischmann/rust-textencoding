const LOWER_ALPHABET: &[u8] = b"0123456789abcdef";
const UPPER_ALPHABET: &[u8] = b"0123456789ABCDEF";

const REVERSE_LOWER_ALPHABET: [u8; 256] = compute_reverse_alphabet(LOWER_ALPHABET);
const REVERSE_UPPER_ALPHABET: [u8; 256] = compute_reverse_alphabet(UPPER_ALPHABET);

const fn compute_reverse_alphabet(alphabet: &[u8]) -> [u8; 256] {
    let mut table: [u8; 256] = [0xff; 256];

    let mut i = 0;
    while i < alphabet.len() {
        let index = alphabet[i] as usize;
        table[index] = i as u8;
        i += 1;
    }

    table
}

#[inline]
pub fn encode_upper<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    encode(Alphabet::Upper, input)
}

#[inline]
pub fn encode_lower<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    encode(Alphabet::Lower, input)
}

#[inline]
pub fn encode_lower_slice<T: ?Sized + AsRef<[u8]>>(
    input: &T,
    output: &mut [u8],
) -> Result<(), EncodeError> {
    encode_slice(Alphabet::Lower, input, output)
}

#[inline]
pub fn encode_upper_slice<T: ?Sized + AsRef<[u8]>>(
    input: &T,
    output: &mut [u8],
) -> Result<(), EncodeError> {
    encode_slice(Alphabet::Upper, input, output)
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    #[error("invalid output buffer length {0}")]
    InvalidOutputLength(usize),
}

enum Alphabet {
    Lower,
    Upper,
}

fn encode_slice<T: ?Sized + AsRef<[u8]>>(
    alphabet: Alphabet,
    input: &T,
    output: &mut [u8],
) -> Result<(), EncodeError> {
    let data = input.as_ref();

    if output.len() != data.len() * 2 {
        return Err(EncodeError::InvalidOutputLength(output.len()));
    }

    let alphabet = match alphabet {
        Alphabet::Lower => LOWER_ALPHABET,
        Alphabet::Upper => UPPER_ALPHABET,
    };

    let mut sl = output;

    for b in data {
        assert!(sl.len() >= 2);

        let left = b >> 4;
        let right = b & 0x0F;

        let left_char = alphabet[left as usize];
        let right_char = alphabet[right as usize];

        sl[0] = left_char;
        sl[1] = right_char;
        sl = &mut sl[2..];
    }

    Ok(())
}

fn encode<T: ?Sized + AsRef<[u8]>>(alphabet: Alphabet, input: &T) -> String {
    let data = input.as_ref();

    let mut output = Vec::new();
    output.resize(data.len() * 2, 0);

    encode_slice(alphabet, input, &mut output)
        .expect("should be able to encode to a vec-created slice");

    let result = String::from_utf8_lossy(&output);
    result.to_string()
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid length {0}")]
    InvalidLength(usize),
    #[error("invalid char {0}")]
    InvalidChar(char),
}

#[inline]
fn decode_byte(b: u8) -> Result<u8, DecodeError> {
    let result = REVERSE_LOWER_ALPHABET[b as usize];
    if result != 0xff {
        return Ok(result);
    }

    let result = REVERSE_UPPER_ALPHABET[b as usize];
    if result == 0xff {
        return Err(DecodeError::InvalidChar(b as char));
    }

    Ok(result)
}

pub fn decode(data: &str) -> Result<Vec<u8>, DecodeError> {
    if data.len() % 2 != 0 {
        return Err(DecodeError::InvalidLength(data.len()));
    }

    let mut output: Vec<u8> = Vec::with_capacity(data.len() / 2);

    let bytes = data.as_bytes();

    let mut i = 0;
    while i + 1 < bytes.len() {
        let left = bytes[i];
        let right = bytes[i + 1];

        // D
        let left_byte = decode_byte(left)?;
        let right_byte = decode_byte(right)?;

        let b = left_byte << 4 | right_byte;

        output.push(b);

        i += 2;
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_should_work() {
        let input: Vec<u8> = vec![0xab, 0xad, 0xba, 0xac];

        {
            let expected = "abadbaac";
            let result = encode_lower(&input);
            assert_eq!(result, expected);
        }

        {
            let expected = "ABADBAAC";
            let result = encode_upper(&input);
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn encode_slice_should_work() {
        let input: Vec<u8> = vec![0xab, 0xad, 0xba, 0xac];

        let mut output = vec![0; input.len() * 2];

        {
            let expected = "abadbaac";
            encode_lower_slice(&input, &mut output).unwrap();
            assert_eq!(expected, String::from_utf8_lossy(&output));
        }

        {
            output.clear();
            output.resize(input.len() * 2, 0);

            let expected = "ABADBAAC";
            encode_upper_slice(&input, &mut output).unwrap();
            assert_eq!(expected, String::from_utf8_lossy(&output));
        }
    }

    #[test]
    fn decode_should_work() {
        let inputs = vec!["abadbaac", "ABADBAAC"];
        let expected: Vec<u8> = vec![0xab, 0xad, 0xba, 0xac];

        for input in inputs {
            let result = decode(input).unwrap();
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn decode_of_non_hex_chars_should_fail() {
        {
            let input = "uv";
            let result = decode(input);
            assert_eq!(result.unwrap_err(), DecodeError::InvalidChar('u'));
        }

        {
            let input = "av";
            let result = decode(input);
            assert_eq!(result.unwrap_err(), DecodeError::InvalidChar('v'));
        }
    }

    #[test]
    fn decode_of_invalid_length_string_should_fail() {
        let input = "vvv";
        let result = decode(input);
        assert_eq!(result.unwrap_err(), DecodeError::InvalidLength(3));
    }

    #[test]
    fn rfc4648_test_vectors_should_work() {
        let test_cases = vec![
            ("", ""),
            ("f", "66"),
            ("fo", "666F"),
            ("foo", "666F6F"),
            ("foob", "666F6F62"),
            ("fooba", "666F6F6261"),
            ("foobar", "666F6F626172"),
        ];

        for tc in test_cases {
            {
                let result = encode_upper(tc.0);
                assert_eq!(tc.1, result);

                let decoded = decode(&result).unwrap();
                assert_eq!(tc.0.as_bytes(), &decoded);
            }

            {
                let result = encode_lower(tc.0);
                assert_eq!(tc.1.to_lowercase(), result);

                let decoded = decode(&result).unwrap();
                assert_eq!(tc.0.as_bytes(), &decoded);
            }
        }
    }
}
