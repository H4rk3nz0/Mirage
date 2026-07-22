use super::*;

// MIRAGE FINGERPRINT PATCH.
// RFC 8701 GREASE extension: a reserved (0x?A?A) extension type with a
// zero-length body. Every real Chrome ClientHello carries GREASE; its absence
// is a passive distinguisher. A conformant peer MUST ignore it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExtensionGrease;

impl ExtensionGrease {
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::Grease
    }

    pub fn size(&self) -> usize {
        2
    }

    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Zero-length body.
        writer.write_u16::<BigEndian>(0)?;
        Ok(writer.flush()?)
    }

    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let len = reader.read_u16::<BigEndian>()?;
        // Skip any body bytes (GREASE bodies are empty, but be tolerant).
        for _ in 0..len {
            let _ = reader.read_u8()?;
        }
        Ok(ExtensionGrease)
    }
}
