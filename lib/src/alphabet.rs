pub(crate) struct PaddingConfig {
    pub character: u8,
    pub sentinel: u8,
}

pub(crate) const fn compute_reverse(alphabet: &[u8], padding: Option<PaddingConfig>) -> [u8; 256] {
    let mut table: [u8; 256] = [0xff; 256];

    let mut i = 0;
    while i < alphabet.len() {
        let index = alphabet[i] as usize;
        table[index] = i as u8;
        i += 1;
    }

    if let Some(padding) = padding {
        table[padding.character as usize] = padding.sentinel;
    }

    table
}
