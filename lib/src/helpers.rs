pub(crate) const fn compute_reverse_alphabet(alphabet: &[u8]) -> [u8; 256] {
    let mut table: [u8; 256] = [0xff; 256];

    let mut i = 0;
    while i < alphabet.len() {
        let index = alphabet[i] as usize;
        table[index] = i as u8;
        i += 1;
    }

    table
}
