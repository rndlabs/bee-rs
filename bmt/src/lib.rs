use tiny_keccak::{Hasher, Keccak};

pub mod chunk;
pub mod file;
pub mod span;

const SEGMENT_SIZE: usize = 32;
const SEGMENT_PAIR_SIZE: usize = 2 * SEGMENT_SIZE;
const HASH_SIZE: usize = 32; // bytes

const DEFAULT_MAX_PAYLOAD_SIZE: usize = 4096; // bytes
const DEFAULT_MIN_PAYLOAD_SIZE: usize = 1;

pub fn keccak256<S>(bytes: S) -> [u8; 32]
where
    S: AsRef<[u8]>,
{
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes.as_ref());
    hasher.finalize(&mut output);
    output
}
