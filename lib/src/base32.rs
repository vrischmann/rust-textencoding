use crate::alphabet::{compute_reverse, PaddingConfig};
use std::cmp::min;

const RFC4648_LOWER_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const RFC4648_UPPER_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CROCKFORD_LOWER_ALPHABET: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";
const CROCKFORD_UPPER_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const REVERSE_RFC4648_LOWER_ALPHABET: [u8; 256] = compute_reverse(
    RFC4648_LOWER_ALPHABET,
    Some(PaddingConfig {
        character: PADDING_CHAR,
        sentinel: PADDING_SENTINEL,
    }),
);
const REVERSE_RFC4648_UPPER_ALPHABET: [u8; 256] = compute_reverse(
    RFC4648_UPPER_ALPHABET,
    Some(PaddingConfig {
        character: PADDING_CHAR,
        sentinel: PADDING_SENTINEL,
    }),
);

const PADDING_CHAR: u8 = b'=';
const PADDING_SENTINEL: u8 = 32;

pub enum Alphabet {
    RFC4648Lower,
    RFC4648Upper,
    CrockfordLower,
    CrockfordUpper,
}

struct EncodingConfig {
    alphabet: Alphabet,
    padding: bool,
}

impl Default for EncodingConfig {
    fn default() -> Self {
        Self {
            alphabet: Alphabet::RFC4648Upper,
            padding: true,
        }
    }
}

pub struct Encoding {
    config: EncodingConfig,
}

pub struct EncodingBuilder {
    config: EncodingConfig,
}

impl EncodingBuilder {
    pub fn alphabet(mut self, alphabet: Alphabet) -> Self {
        self.config.alphabet = alphabet;
        self
    }

    pub fn padding(mut self, padding: bool) -> Self {
        self.config.padding = padding;
        self
    }

    pub fn build(self) -> Encoding {
        Encoding {
            config: self.config,
        }
    }
}

const INPUT_BLOCK_SIZE: usize = 5;
const MAX_REMAINDER_SIZE: usize = INPUT_BLOCK_SIZE - 1;
const OUTPUT_BLOCK_SIZE: usize = 8;

#[inline]
fn decode_chars(
    lower_alphabet: &[u8],
    upper_alphabet: &[u8],
    input: &[u8],
) -> Result<[u8; 8], DecodeError> {
    assert!(input.len() == 8);

    let mut bytes: [u8; 8] = [0xff; 8];

    let mut i = 0;
    while i < bytes.len() {
        let b = input[i];

        bytes[i] = {
            let result = lower_alphabet[b as usize];
            if result != 0xff {
                result
            } else {
                let result = upper_alphabet[b as usize];
                if result == 0xff {
                    return Err(DecodeError::InvalidChar(b as char));
                }
                result
            }
        };

        i += 1;
    }

    Ok(bytes)
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid length {0}")]
    InvalidLength(usize),
    #[error("invalid char {0}")]
    InvalidChar(char),
    #[error("invalid padding")]
    InvalidPadding,
}

impl Encoding {
    pub fn builder() -> EncodingBuilder {
        EncodingBuilder {
            config: EncodingConfig::default(),
        }
    }

    pub fn encoded_len(&self, n: usize) -> usize {
        if self.config.padding {
            let max_whole_input_bytes = n + MAX_REMAINDER_SIZE;
            max_whole_input_bytes / INPUT_BLOCK_SIZE * OUTPUT_BLOCK_SIZE
        } else {
            let max_output_size = n * OUTPUT_BLOCK_SIZE + MAX_REMAINDER_SIZE;
            max_output_size / INPUT_BLOCK_SIZE
        }
    }

    fn alphabet(&self) -> &[u8] {
        match self.config.alphabet {
            Alphabet::RFC4648Lower => RFC4648_LOWER_ALPHABET,
            Alphabet::RFC4648Upper => RFC4648_UPPER_ALPHABET,
            Alphabet::CrockfordLower => CROCKFORD_LOWER_ALPHABET,
            Alphabet::CrockfordUpper => CROCKFORD_UPPER_ALPHABET,
        }
    }

    fn reverse_alphabets(&self) -> (&[u8], &[u8]) {
        match self.config.alphabet {
            Alphabet::RFC4648Lower | Alphabet::RFC4648Upper => (
                &REVERSE_RFC4648_LOWER_ALPHABET,
                &REVERSE_RFC4648_UPPER_ALPHABET,
            ),
            Alphabet::CrockfordLower | Alphabet::CrockfordUpper => todo!(),
        }
    }

    pub fn encode<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> String {
        let mut data = input.as_ref();
        let mut output = String::with_capacity(self.encoded_len(data.len()));

        let alphabet = self.alphabet();

        while !data.is_empty() {
            // Each block is 5 bytes or 40 bits. These 40 bits are then split into 5 bits groups.
            // These groups can represent 32 integers (2^5) and are used as index into the base32 alphabet.
            //
            // The following diagram (taken from the RFC4648) shows which input bits are contained in the output chars.
            //
            //     0        1        2        3        4
            //  01234567 89012345 67890123 45678901 23456789
            // +--------+--------+--------+--------+--------+
            // |< 1 >< 2| >< 3 ><|.4 >< 5.|>< 6 ><.|7 >< 8 >|
            // +--------+--------+--------+--------+--------+

            // Initialize all bytes to 0xff because it's not a valid index in the alphabet.
            // That way we can easily identify if we encoded a whole input block or not.
            let mut buf: [u8; 8] = [0xff; 8];

            // Because we use this loop to process incomplete blocks we have to check the length
            // before proceeding.
            //
            // Specifically, chars that overlap two input bytes can't be written at once in the
            // output buffer: indeed, the last byte may not be present (meaning we need to pad with
            // zeroes).
            // This is why the buf[1], buf[3], buf[4] and buf[6] writes are split into two parts.
            //
            // Note: that we use binary literals to see more clearly what parts of the input
            // bytes gets written into the output buffer.

            buf[0] = (data[0] & 0b11111000) >> 3;
            buf[1] = (data[0] & 0b00000111) << 2;
            if data.len() > 1 {
                buf[1] |= (data[1] & 0b11000000) >> 6;
                buf[2] = (data[1] & 0b00111110) >> 1;
                buf[3] = (data[1] & 0b00000001) << 4;
            }
            if data.len() > 2 {
                buf[3] |= (data[2] & 0b11110000) >> 4;
                buf[4] = (data[2] & 0b00001111) << 1;
            }
            if data.len() > 3 {
                buf[4] |= (data[3] & 0b10000000) >> 7;
                buf[5] = (data[3] & 0b01111100) >> 2;
                buf[6] = (data[3] & 0b00000011) << 3;
            }
            if data.len() > 4 {
                buf[6] |= (data[4] & 0b11100000) >> 5;
                buf[7] = data[4] & 0b00011111;
            }

            for b in buf {
                if b != 0xff {
                    let c = alphabet[b as usize] as char;
                    output.push(c);
                } else if self.config.padding {
                    output.push(PADDING_CHAR as char);
                }
            }

            let shift = min(INPUT_BLOCK_SIZE, data.len());

            data = &data[shift..];
        }

        output
    }

    pub fn decode<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Result<Vec<u8>, DecodeError> {
        let mut data = input.as_ref();
        let mut output: Vec<u8> = Vec::with_capacity(data.len()); // TODO(vincent): compute the real length

        if (data.len() % OUTPUT_BLOCK_SIZE) != 0 {
            return Err(DecodeError::InvalidLength(data.len()));
        }

        let (lower_alphabet, upper_alphabet) = self.reverse_alphabets();

        while data.len() >= OUTPUT_BLOCK_SIZE {
            let bytes = decode_chars(lower_alphabet, upper_alphabet, &data[0..OUTPUT_BLOCK_SIZE])?;
            data = &data[OUTPUT_BLOCK_SIZE..];

            let c0 = bytes[0];
            let c1 = bytes[1];
            let c2 = bytes[2];
            let c3 = bytes[3];
            let c4 = bytes[4];
            let c5 = bytes[5];
            let c6 = bytes[6];
            let c7 = bytes[7];

            // Validate the padding if necessary
            if self.config.padding {
                // 1. First two chars can never be a padding char
                if c0 == PADDING_SENTINEL || c1 == PADDING_SENTINEL {
                    return Err(DecodeError::InvalidPadding);
                }

                if data.is_empty() {
                    // 2. If there is no more data following we check that the padding makes sense;
                    // if a byte is the padding sentinel the next byte has to be the sentinel too

                    let mut i = 0;
                    while i + 1 < bytes.len() {
                        if bytes[i] == PADDING_SENTINEL && bytes[i + 1] != PADDING_SENTINEL {
                            return Err(DecodeError::InvalidPadding);
                        }
                        i += 1;
                    }
                } else if bytes.contains(&PADDING_SENTINEL) {
                    // 3. If there is more data we can't have any padding
                    return Err(DecodeError::InvalidPadding);
                }
            }

            // The following diagram (taken from the RFC4648) shows which input bits are contained in the output chars.
            //
            //     0        1        2        3        4
            //  01234567 89012345 67890123 45678901 23456789
            // +--------+--------+--------+--------+--------+
            // |< 1 >< 2| >< 3 ><|.4 >< 5.|>< 6 ><.|7 >< 8 >|
            // +--------+--------+--------+--------+--------+

            let mut buf: [u8; 5] = [0xff; 5];
            buf[0] = ((c0 & 0b11111) << 3) | ((c1 & 0b11100) >> 2);
            buf[1] = ((c1 & 0b00011) << 6) | ((c2 & 0b11111) << 1) | ((c3 & 0b10000) >> 4);
            buf[2] = ((c3 & 0b01111) << 4) | ((c4 & 0b11110) >> 1);
            buf[3] = ((c4 & 0b00001) << 7) | ((c5 & 0b11111) << 2) | ((c6 & 0b11000) >> 3);
            buf[4] = ((c6 & 0b00111) << 5) | (c7 & 0b11111);

            if self.config.padding {
                if c7 != PADDING_SENTINEL {
                    output.extend_from_slice(&buf);
                } else if c7 == PADDING_SENTINEL && c6 != PADDING_SENTINEL {
                    output.extend_from_slice(&buf[0..4]);
                } else if c7 == PADDING_SENTINEL
                    && c6 == PADDING_SENTINEL
                    && c5 == PADDING_SENTINEL
                    && c4 != PADDING_SENTINEL
                {
                    output.extend_from_slice(&buf[0..3]);
                } else if c7 == PADDING_SENTINEL
                    && c6 == PADDING_SENTINEL
                    && c5 == PADDING_SENTINEL
                    && c4 == PADDING_SENTINEL
                    && c3 != PADDING_SENTINEL
                {
                    output.extend_from_slice(&buf[0..2]);
                } else if c7 == PADDING_SENTINEL
                    && c6 == PADDING_SENTINEL
                    && c5 == PADDING_SENTINEL
                    && c4 == PADDING_SENTINEL
                    && c3 == PADDING_SENTINEL
                    && c2 == PADDING_SENTINEL
                    && c1 != PADDING_SENTINEL
                {
                    output.extend_from_slice(&buf[0..1]);
                }
            } else {
                output.extend_from_slice(&buf);
            }
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn encode_crockford_should_work() {
    //     let input: Vec<u8> = vec![0xab, 0xad, 0xba, 0xac];
    //     let expected = "nananana";

    //     let encoding = Encoding::builder()
    //         .alphabet(Alphabet::CrockfordLower)
    //         .build();

    //     let result = encoding.encode(&input);
    //     assert_eq!(result, expected);
    // }

    #[test]
    fn encoded_len_without_padding() {
        let encoding = Encoding::builder().padding(false).build();

        let result = encoding.encoded_len(1);
        assert_eq!(2, result);

        let result = encoding.encoded_len(20);
        assert_eq!(32, result);

        let result = encoding.encoded_len(37);
        assert_eq!(60, result);
    }

    #[test]
    fn encoded_len_with_padding() {
        let test_cases = vec![(1, 8), (20, 32), (37, 64)];

        let encoding = Encoding::builder().build();

        for tc in test_cases {
            let result = encoding.encoded_len(tc.0);
            assert_eq!(tc.1, result);
        }
    }

    #[test]
    fn decode_should_work() {
        let test_cases = vec![
            ("", ""),
            ("MY======", "f"),
            ("MZXQ====", "fo"),
            ("MZXW6===", "foo"),
            ("MZXW6YQ=", "foob"),
            ("MZXW6YTB", "fooba"),
            ("MZXW6YTBOI======", "foobar"),
        ];

        let encoding = Encoding::builder().build();

        for tc in test_cases {
            let decoded = encoding.decode(tc.0).unwrap();
            assert_eq!(tc.1.as_bytes(), &decoded);

            let decoded = encoding.decode(&tc.0.to_uppercase()).unwrap();
            assert_eq!(tc.1.as_bytes(), &decoded);
        }
    }

    #[test]
    fn rfc4648_test_vectors_should_work() {
        let test_cases = vec![
            ("", ""),
            ("f", "MY======"),
            ("fo", "MZXQ===="),
            ("foo", "MZXW6==="),
            ("foob", "MZXW6YQ="),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI======"),
        ];

        let encoding = Encoding::builder().build();

        for tc in test_cases {
            let result = encoding.encode(tc.0);
            assert_eq!(tc.1, result);

            let decoded = encoding.decode(&result).unwrap();
            assert_eq!(tc.0.as_bytes(), &decoded);
        }
    }

    #[test]
    fn rfc4648_test_vectors_without_padding_should_work() {
        let test_cases = vec![
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ];

        let encoding = Encoding::builder().padding(false).build();

        for tc in test_cases {
            let result = encoding.encode(tc.0);
            assert_eq!(tc.1, result);

            // let decoded = encoding.decode(&result).unwrap();
            // assert_eq!(tc.0.as_bytes(), &decoded);
        }
    }

    #[test]
    fn bad_padding_should_fail() {
        let test_cases = vec!["==aaaaaa", "FF=A====", "FFFF=A==", "FFFFF=A="];

        let encoding = Encoding::builder().padding(true).build();

        for tc in test_cases {
            let result = encoding.decode(tc);
            assert_eq!(result, Err(DecodeError::InvalidPadding));
        }
    }
}
