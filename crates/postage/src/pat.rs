use serde::{Deserialize, Serialize};
use std::{borrow::BorrowMut, future::Future, pin::Pin, result};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};
// use serde_json::Result;
use ethers_signers::{LocalWallet, Signer, WalletError};

use crate::{
    batch::{Batch, BatchId, Store},
    stamp::Stamp,
};
use bmt::chunk::Chunk;

/// An error involving Postman Pat 📬
#[derive(Debug, Error)]
pub enum PatError {
    /// The chunk address does not match the bucket
    #[error("bucket full")]
    BucketFull(),
    /// When a batch isn't found in the store
    #[error("batch not found")]
    BatchNotFound(BatchId),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Pat {
    batch_id: BatchId,  // the batch id
    batch_amount: u128, // the amount paid for the batch
    #[serde(skip_serializing)]
    batch_depth: u32, // batch depth: batch size = 2^{batch_depth}
    #[serde(skip_serializing)]
    batch_bucket_depth: u32, // bucket depth: the depth of collision buckets uniformity
    buckets: Vec<u32>, // Collision buckets: counts per neighbourhoods (limited to 2^{batchDepth-bucketDepth})
    max_bucket_depth: u32, // the depth of the fullest bucket
    #[serde(skip_serializing)]
    block_created: Option<u64>, // the block number when this batch was created
    #[serde(skip_serializing)]
    immutable: bool, // whether the batch is immutable
    #[serde(skip_serializing)]
    expired: bool, // whether the batch is expired
    #[serde(skip_serializing)]
    #[serde(skip_deserializing)]
    signer: Option<LocalWallet>, // the signer
}

impl Pat {
    fn new(batch: &Batch, batch_amount: u128, expired: bool, signer: LocalWallet) -> Self {
        Self {
            batch_id: batch.id,
            batch_amount,
            batch_depth: batch.depth,
            batch_bucket_depth: batch.bucket_depth,
            buckets: vec![0; 2usize.pow(batch.bucket_depth as u32)],
            max_bucket_depth: 0,
            block_created: batch.block_created,
            immutable: batch.immutable,
            expired,
            signer: Some(signer),
        }
    }

    pub fn inc(&mut self, chunk: &Chunk) -> std::result::Result<(u32, u32), PatError> {
        // get which bucket the chunk belongs to
        let x = chunk.get_x(self.batch_bucket_depth);
        let upper_bound = self.bucket_upper_bound();
        let count = self.buckets[x as usize].borrow_mut();
        let idx = *count;

        // check if the bucket is full
        if (*count as u32) == upper_bound {
            // check if immutable
            if self.immutable {
                return Err(PatError::BucketFull());
            }

            *count = 0;
        }

        // increment the bucket
        *count += 1;
        if *count > self.max_bucket_depth {
            self.max_bucket_depth = *count;
        }

        return Ok((x, idx));
    }

    pub async fn stamp<'a>(&'a mut self, mut chunk: Chunk, timestamp: Option<u64>) -> std::result::Result<Chunk, PatError> {
        let (x, y) = self.inc(&chunk)?;

        let timestamp = timestamp.unwrap_or_else(|| chrono::Utc::now().timestamp_nanos() as u64);

        let signer = self.signer.as_ref().expect("Signer is not set");

        let stamp = Stamp::new(
            &chunk,
            self.batch_id,
            x,
            y,
            timestamp,
            Box::new(move |digest| {
                let signer = signer.clone();
                Box::pin(async move {
                    let result = signer.sign_message(&digest).await?;
                    let result: [u8; 65] = result.to_vec().as_slice().try_into()?;
                    Ok(result)
                })
                    as Pin<
                        Box<dyn Future<Output = Result<[u8; 65], Box<dyn std::error::Error + 'a>>>>,
                    >
            }),
        )
        .await;

        chunk.add_stamp(stamp.into());
        Ok(chunk)
    }

    pub fn utilization(&self) -> u32 {
        self.max_bucket_depth as u32
    }

    pub fn bucket_upper_bound(&self) -> u32 {
        1 << (self.batch_depth - self.batch_bucket_depth)
    }

    pub fn set_expired(&mut self) {
        self.expired = true;
    }

    pub fn rehydrate(
        &mut self,
        store: &Store,
        signer: LocalWallet,
    ) -> std::result::Result<(), PatError> {
        let batch = store
            .get(self.batch_id)
            .ok_or(PatError::BatchNotFound(self.batch_id))?;
        self.batch_depth = batch.depth;
        self.batch_bucket_depth = batch.bucket_depth;
        self.block_created = batch.block_created;
        self.immutable = batch.immutable;
        Ok(())
    }
}

pub(crate) trait BucketSeeker {
    fn get_x(&self, bucket_depth: u32) -> u32;
}

impl BucketSeeker for Chunk {
    fn get_x(&self, bucket_depth: u32) -> u32 {
        // let i be t interpreted as a big endian integer
        let i = u32::from_be_bytes(self.address()[0..4].to_vec().try_into().unwrap());
        return i >> (32 - bucket_depth);
    }
}

#[cfg(test)]
mod tests {
    use ethers_core::types::Address;
    use hex::ToHex;

    use super::*;
    use bmt::chunk::Options;

    static BATCH_ID: &str = "c3387832bb1b88acbcd0ffdb65a08ef077d98c08d4bee576a72dbe3d36761369";
    static STAMP_MARSHALLED: &str = "c3387832bb1b88acbcd0ffdb65a08ef077d98c08d4bee576a72dbe3d367613690000cbe5000000000000018921ff0dbb29169df9e6364e26c6ca6b17745c10b9d6a36ea38e204f2e3cc64a8373c0661f5bb0a347c61d8d1689b0dcf8354117686a6a18d08cff927f526de5fc61b2b7491b";
    static PAYLOAD: &str = "hello wordl";
    static PRIVATE_KEY: &str = "be52c649a4c560a1012daa572d4e81627bcce20ca14e007aef87808a7fadd3d0";
    static TIMESTAMP: u64 = 1688492510651;

    #[tokio::test]
    async fn valid_stamp() {
        let chunks =
            bmt::file::ChunkedFile::new(PAYLOAD.to_owned().into(), Options::default());
        let chunk = chunks.leaf_chunks()[0].clone();

        // convert BATCH_ID to String with type annotations on into()
        let batch_id =
            hex::decode::<String>(BATCH_ID.to_owned().into())
                .unwrap();

        // convert batch_id to [u8; 32]
        let mut batch_id_arr = [0u8; 32];
        batch_id_arr.copy_from_slice(&batch_id);

        let wallet = PRIVATE_KEY
            .parse::<LocalWallet>()
            .unwrap();

        // create a batch
        let batch = Batch::new(batch_id_arr, 0, None, Address::zero(), 18, 16, false);
        let mut pat = Pat::new(&batch, 0, false, wallet);

        let chunk = pat.stamp(chunk, Some(TIMESTAMP)).await.unwrap();

        println!("chunk address: {}", chunk.address().encode_hex::<String>());
        println!(
            "chunk stamps: {:?}",
            chunk.stamp().unwrap().encode_hex::<String>()
        );

        assert_eq!(chunk.stamp().unwrap().encode_hex::<String>(), STAMP_MARSHALLED.to_owned());
    }
}
