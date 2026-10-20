use crate::ffi::Constraint;
use winptap_core::*;
/// Aligned constraint storage with every byte, including padding, initialized.
pub struct ConstraintBuffer([u64; 27]);
impl ConstraintBuffer {
    pub fn as_ptr(&self) -> *const Constraint {
        self.0.as_ptr().cast()
    }
}
/// Encode representable predicates; remaining predicates are checked in Rust.
pub fn compile(filter: &Filter) -> Result<ConstraintBuffer> {
    let bytes = encode_constraint(filter)?;
    let mut words = [0; 27];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_ne_bytes(chunk.try_into().unwrap());
    }
    Ok(ConstraintBuffer(words))
}
