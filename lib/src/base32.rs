use std::cmp::min;

const RFC4648_LOWER_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const RFC4648_UPPER_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CROCKFORD_LOWER_ALPHABET: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";
const CROCKFORD_UPPER_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub enum Alphabet {
    RFC4648Lower,
    RFC4648Upper,
    CrockfordLower,
    CrockfordUpper,
}

struct EncodingConfig {
    alphabet: Alphabet,
    padding: Option<u8>,
}

impl Default for EncodingConfig {
    fn default() -> Self {
        Self {
            alphabet: Alphabet::RFC4648Upper,
            padding: Some(b'='),
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

    pub fn padding(mut self, padding: Option<u8>) -> Self {
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

impl Encoding {
    pub fn builder() -> EncodingBuilder {
        EncodingBuilder {
            config: EncodingConfig::default(),
        }
    }

    pub fn encoded_len(&self, n: usize) -> usize {
        match self.config.padding {
            None => {
                let max_output_size = n * OUTPUT_BLOCK_SIZE + MAX_REMAINDER_SIZE;
                max_output_size / INPUT_BLOCK_SIZE
            }
            Some(_) => {
                let max_whole_input_bytes = n + MAX_REMAINDER_SIZE;
                max_whole_input_bytes / INPUT_BLOCK_SIZE * OUTPUT_BLOCK_SIZE
            }
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

            buf[0] = (data[0] & 0xf8) >> 3;
            buf[1] = (data[0] & 0x07) << 2;
            if data.len() > 1 {
                buf[1] |= (data[1] & 0xc0) >> 6;
                buf[2] = (data[1] & 0x3e) >> 1;
                buf[3] = (data[1] & 0x1) << 4;
            }
            if data.len() > 2 {
                buf[3] |= (data[2] & 0xf0) >> 4;
                buf[4] = (data[2] & 0xf) << 1;
            }
            if data.len() > 3 {
                buf[4] |= (data[3] & 0x80) >> 7;
                buf[5] = (data[3] & 0x7c) >> 2;
                buf[6] = (data[3] & 0x3) << 3;
            }
            if data.len() > 4 {
                buf[6] |= (data[4] & 0xe0) >> 5;
                buf[7] = data[4] & 0x1f;
            }

            for b in buf {
                if b != 0xff {
                    let c = alphabet[b as usize] as char;
                    output.push(c);
                } else if let Some(padding) = self.config.padding {
                    output.push(padding as char);
                }
            }

            let shift = min(INPUT_BLOCK_SIZE, data.len());

            data = &data[shift..];
        }

        output
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
        let encoding = Encoding::builder().padding(None).build();

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

            // let decoded = encoding.decode(&result).unwrap();
            // assert_eq!(tc.0.as_bytes(), &decoded);
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

        let encoding = Encoding::builder().padding(None).build();

        for tc in test_cases {
            let result = encoding.encode(tc.0);
            assert_eq!(tc.1, result);

            // let decoded = encoding.decode(&result).unwrap();
            // assert_eq!(tc.0.as_bytes(), &decoded);
        }
    }
}
