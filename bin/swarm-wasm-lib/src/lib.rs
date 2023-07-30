mod utils;

// Use cases to meet:
// 1. Given a Javascript function that can be used to retrieve a chunk from the bee api, return a tuple of:
//    - the chunk address
//    - the span
//    - the payload data
// 2. Given a Javascript function that can be used to send a chunk(s) to the bee api, a payload in a Uint8Array, a signing key, and a pat,
//    upload the stamped chunk(s) to the bee api and return a tuple of:
//    - the chunk address(es)
//    - the cac for the payload (if spanning more than 1 chunk)

pub mod bmt {
    use std::convert::TryInto;

    use bmt::chunk::{Chunk, Options};
    use js_sys::Function;
    use js_sys::{Promise, Uint8Array};
    use wasm_bindgen::prelude::*;

    pub struct ParsedApiChunk(String, u64, Uint8Array);

    // Asynchronously evaluate the JavaScript Promise
    async fn await_promise(promise: Promise) -> Result<JsValue, JsValue> {
        let future = wasm_bindgen_futures::JsFuture::from(promise);
        future.await.map_err(|err| err.into())
    }

    // Given a function that can be used to retrieve a raw chunk, return a ChunkInfo struct
    #[wasm_bindgen]
    pub async fn get_chunk(address: &str, get_chunk_fn: &Function) -> Result<ChunkInfo, JsValue> {
        // Call the TypeScript function with the provided address
        let promise = get_chunk_fn.call1(&JsValue::NULL, &JsValue::from_str(address))?;

        // Await the JavaScript Promise in Rust
        let ret = await_promise(Promise::from(promise)).await?;

        // Convert the result into a ChunkInfo struct
        Ok(get_chunk_info(&Uint8Array::from(ret)))
    }

    #[derive(Debug, Clone)]
    #[wasm_bindgen(getter_with_clone)]
    pub struct ChunkInfo {
        pub address: String,
        pub span: u64,
        pub data: Uint8Array,
    }

    // Given a Uint8Array, calculate the chunk address, span, and payload data
    #[wasm_bindgen]
    pub fn get_chunk_info(data: &Uint8Array) -> ChunkInfo {
        // The first 8 bytes of the data are the span in little endian
        let span = u64::from_le_bytes(data.slice(0, 8).to_vec().try_into().unwrap());
        // The remainder of the data is the payload
        let mut data = data.slice(8, data.length()).to_vec();

        // Create a new chunk from the data
        let chunk = Chunk::new(&mut data, Some(span), Options::default(), None);

        ChunkInfo {
            address: hex::encode(chunk.address().to_vec()),
            span,
            data: Uint8Array::from(data.as_slice()),
        }
    }
}
