//! The byte framing every format, hash, signature and associated data of Hangar Drive uses.
//!
//! `field(x)` is the length of `x` as a 32-bit big endian number followed by `x`, so no two
//! different field lists form the same byte string. All integers are big endian. The format is
//! the one of the Hangar team crypto, so both products are built from the same parts.
//!
//! [`Reader`] is strict: every method returns `None` on a short or malformed input, and
//! [`Reader::finish`] refuses trailing bytes, so a decoder built on it accepts exactly one byte
//! string per value.

/// The length prefix of a field: `len` as a `u32` big endian.
///
/// # Panics
///
/// For a field of 4 GiB or more (security review, info). Saturating, as before, would give two
/// different field lists the same bytes once a field reaches 4 GiB, so a signature or MAC over
/// one would hold for the other. It is a documented invariant instead of an error value: every
/// field is bounded far below 4 GiB by the protocol limits before it is framed (objects and
/// records at a few MiB, request bodies at 80 MiB), so the panic is unreachable from any input,
/// and an unreachable `Result` would only spread through every format of both crates.
#[track_caller]
pub fn length_prefix(len: usize) -> [u8; 4] {
    match u32::try_from(len) {
        Ok(len) => len.to_be_bytes(),
        Err(_) => panic!("a field of 4 GiB or more cannot be framed"),
    }
}

/// Builds a byte string of length-prefixed fields and raw fixed-width values.
#[derive(Debug, Default, Clone)]
pub struct Writer(Vec<u8>);

impl Writer {
    /// An empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty writer with room for `capacity` bytes.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// `field(part)`: the length as `u32` big endian, then the bytes.
    pub fn field(&mut self, part: &[u8]) -> &mut Self {
        self.0.extend_from_slice(&length_prefix(part.len()));
        self.0.extend_from_slice(part);
        self
    }

    /// `field` of one byte.
    pub fn field_u8(&mut self, value: u8) -> &mut Self {
        self.field(&[value])
    }

    /// `field` of a `u16` big endian.
    pub fn field_u16(&mut self, value: u16) -> &mut Self {
        self.field(&value.to_be_bytes())
    }

    /// `field` of a `u32` big endian.
    pub fn field_u32(&mut self, value: u32) -> &mut Self {
        self.field(&value.to_be_bytes())
    }

    /// `field` of a `u64` big endian.
    pub fn field_u64(&mut self, value: u64) -> &mut Self {
        self.field(&value.to_be_bytes())
    }

    /// Raw bytes without a length prefix (fixed-size parts of a format).
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    /// One raw byte.
    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.0.push(value);
        self
    }

    /// A raw `u16` big endian.
    pub fn u16(&mut self, value: u16) -> &mut Self {
        self.raw(&value.to_be_bytes())
    }

    /// A raw `u32` big endian.
    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.raw(&value.to_be_bytes())
    }

    /// A raw `u64` big endian.
    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.raw(&value.to_be_bytes())
    }

    /// A raw `i64` big endian (two's complement).
    pub fn i64(&mut self, value: i64) -> &mut Self {
        self.raw(&value.to_be_bytes())
    }

    /// Bytes written so far.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Nothing written yet.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The finished byte string.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// `field(p1) || field(p2) || ...`
pub fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let mut writer = Writer::new();
    for part in parts {
        writer.field(part);
    }
    writer.into_bytes()
}

/// Reads what [`Writer`] wrote. Every method returns `None` on a short or malformed input.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// One length-prefixed field.
    pub fn field(&mut self) -> Option<&'a [u8]> {
        let (prefix, rest) = self.rest.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_be_bytes(*prefix)).ok()?;
        if rest.len() < len {
            return None;
        }
        let (part, rest) = rest.split_at(len);
        self.rest = rest;
        Some(part)
    }

    /// A field of exactly `N` bytes.
    pub fn field_fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.field()?.try_into().ok()
    }

    /// A field of one byte.
    pub fn field_u8(&mut self) -> Option<u8> {
        Some(self.field_fixed::<1>()?[0])
    }

    /// A field of a `u16` big endian.
    pub fn field_u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.field_fixed()?))
    }

    /// A field of a `u32` big endian.
    pub fn field_u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.field_fixed()?))
    }

    /// A field of a `u64` big endian.
    pub fn field_u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.field_fixed()?))
    }

    /// `N` raw bytes.
    pub fn raw<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (part, rest) = self.rest.split_first_chunk::<N>()?;
        self.rest = rest;
        Some(*part)
    }

    /// `len` raw bytes.
    pub fn raw_slice(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.rest.len() < len {
            return None;
        }
        let (part, rest) = self.rest.split_at(len);
        self.rest = rest;
        Some(part)
    }

    /// One raw byte.
    pub fn u8(&mut self) -> Option<u8> {
        Some(self.raw::<1>()?[0])
    }

    /// A raw `u16` big endian.
    pub fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.raw()?))
    }

    /// A raw `u32` big endian.
    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.raw()?))
    }

    /// A raw `u64` big endian.
    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.raw()?))
    }

    /// A raw `i64` big endian.
    pub fn i64(&mut self) -> Option<i64> {
        Some(i64::from_be_bytes(self.raw()?))
    }

    /// Bytes not read yet.
    pub fn remaining(&self) -> usize {
        self.rest.len()
    }

    /// The input is used up; trailing bytes make an encoding non-canonical.
    pub fn finish(self) -> Option<()> {
        self.rest.is_empty().then_some(())
    }
}

#[cfg(test)]
mod tests {
    // Security review, info: a field of 4 GiB or more fails instead of saturating to the prefix
    // of a shorter one.
    #[test]
    fn a_field_of_four_gib_is_refused_not_saturated() {
        assert_eq!(super::length_prefix(0xffff_ffff), [0xff; 4]);
        let too_long = usize::try_from(1u64 << 32).unwrap_or(usize::MAX);
        if too_long == usize::MAX {
            return; // a 32-bit target cannot even name such a length
        }
        assert!(std::panic::catch_unwind(|| super::length_prefix(too_long)).is_err());
    }

    use super::*;

    #[test]
    fn fields_round_trip_and_reject_trailing_bytes() {
        let mut writer = Writer::new();
        writer
            .field(b"ab")
            .field_u8(7)
            .field_u16(8)
            .field_u32(9)
            .field_u64(11)
            .field(b"")
            .u8(1)
            .u16(2)
            .u32(3)
            .u64(4)
            .i64(-5)
            .raw(b"xyz");
        let bytes = writer.into_bytes();
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.field(), Some(&b"ab"[..]));
        assert_eq!(reader.field_u8(), Some(7));
        assert_eq!(reader.field_u16(), Some(8));
        assert_eq!(reader.field_u32(), Some(9));
        assert_eq!(reader.field_u64(), Some(11));
        assert_eq!(reader.field(), Some(&b""[..]));
        assert_eq!(reader.u8(), Some(1));
        assert_eq!(reader.u16(), Some(2));
        assert_eq!(reader.u32(), Some(3));
        assert_eq!(reader.u64(), Some(4));
        assert_eq!(reader.i64(), Some(-5));
        assert_eq!(reader.raw_slice(3), Some(&b"xyz"[..]));
        assert_eq!(reader.remaining(), 0);
        assert_eq!(reader.finish(), Some(()));

        let mut longer = bytes.clone();
        longer.push(0);
        let mut reader = Reader::new(&longer);
        assert!(reader.raw_slice(bytes.len()).is_some());
        assert_eq!(reader.finish(), None);
    }

    #[test]
    fn short_and_mis_sized_input_is_refused() {
        // A length prefix that promises more than is there.
        assert_eq!(Reader::new(&[0, 0, 0, 5, 1]).field(), None);
        // A fixed-size field of another size.
        assert_eq!(Reader::new(&framed(&[b"abc"])).field_u32(), None);
        assert_eq!(Reader::new(&[1, 2]).u32(), None);
        assert_eq!(Reader::new(&[1, 2]).raw_slice(3), None);
        assert_eq!(Reader::new(&[0, 0]).field(), None);
    }

    #[test]
    fn framed_is_field_by_field() {
        assert_eq!(framed(&[b"a", b""]), vec![0, 0, 0, 1, b'a', 0, 0, 0, 0]);
    }
}
