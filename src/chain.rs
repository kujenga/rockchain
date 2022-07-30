extern crate serde;
extern crate serde_json;
extern crate url_serde;

use byteorder::{BigEndian, WriteBytesExt};
use chrono::prelude::*;
use futures::{Future, Stream};
use hyper::{Chunk, Client};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::mem;
use tokio_core::reactor::Core;
use url::Url;

//
// Blockchain data types
//

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blockchain {
    pub chain: Vec<Block>,
    pub current_transactions: Vec<Transaction>,
    pub nodes: HashSet<Node>,
}

impl Default for Blockchain {
    // Create an initialized blockchain.
    fn default() -> Blockchain {
        let mut bc = Blockchain {
            chain: Vec::new(),
            current_transactions: Vec::new(),
            nodes: HashSet::new(),
        };
        // add genesis block
        bc.new_block(100, Some(1));
        bc
    }
}

impl Blockchain {
    // Creates a new Block and adds it to the chain
    pub fn new_block(&mut self, proof: u64, previous_hash: Option<u64>) {
        let previous_hash = previous_hash.unwrap_or_else(|| Blockchain::hash(self.last_block()));

        let mut previous_transactions = Vec::new();
        mem::swap(&mut self.current_transactions, &mut previous_transactions);

        let block = Block {
            index: self.chain.len() + 1,
            timestamp: Utc::now(),
            transactions: previous_transactions,
            proof: proof,
            previous_hash: previous_hash,
        };

        self.chain.push(block);
    }

    // Adds a new transaction to the list of transactions
    pub fn new_transaction(&mut self, transaction: Transaction) -> usize {
        self.current_transactions.push(transaction);
        self.last_block().index + 1
    }

    // Hashes a Block
    fn hash(block: &Block) -> u64 {
        let mut s = DefaultHasher::new();
        block.hash(&mut s);
        s.finish()
    }

    // Returns the last Block in the chain
    pub fn last_block(&self) -> &Block {
        &self.chain[self.chain.len() - 1]
    }

    pub fn proof_of_work(last_proof: u64) -> u64 {
        let mut proof: u64 = 0;
        while Blockchain::valid_proof(last_proof, proof) == false {
            proof += 1;
        }
        proof
    }
    fn valid_proof(last_proof: u64, proof: u64) -> bool {
        let mut wtr = vec![];
        wtr.write_u64::<BigEndian>(last_proof).unwrap();
        wtr.write_u64::<BigEndian>(proof).unwrap();
        let mut hasher = Sha256::default();
        hasher.input(&wtr[..]);
        hasher.result()[..2] == b"00"[..2]
    }

    // register a new node (idempotent)
    pub fn register_node(&mut self, node: Node) {
        self.nodes.insert(node);
    }

    // Consensus

    // Determine if the passed in chain is valid.
    pub fn valid_chain(chain: &Vec<Block>) -> bool {
        for i in 1..chain.len() {
            let last_block = &chain[i - 1];
            let block = &chain[i];
            println!("last_block: {:?}", last_block);
            println!("block: {:?}", block);

            // Check that the hash of the block is correct.
            if block.previous_hash != Blockchain::hash(last_block) {
                return false;
            }

            // Check that the Proof of Work is correct.
            if !Blockchain::valid_proof(last_block.proof, block.proof) {
                return false;
            }
        }
        // If all checks pass, the chain is valid.
        true
    }
    // Consensus algorithm, resolving conflicts by using the longest chain in
    // the network. Performs network calls to all other known nodes.
    pub fn resolve_conflicts(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        let cur_len = self.chain.len();
        let mut max_len = cur_len;

        let mut core = Core::new()?;
        let client = Client::new(&core.handle());

        for node in self.nodes.iter() {
            info!("calling node: {:?}", node);

            let mut target = node.address.to_owned();
            target.set_path("/chain");
            let uri = target.into_string().parse()?;

            let work = client.get(uri).and_then(|res| {
                res.body().concat2().and_then(move |body: Chunk| {
                    #[derive(Debug, Clone, Serialize, Deserialize)]
                    struct ChainResp {
                        chain: Vec<Block>,
                    }
                    // Error handling for passing is handled later.
                    Ok(serde_json::from_slice::<ChainResp>(&body))
                })
            });

            let chain = core.run(work)??.chain;
            let new_len = chain.len();
            if new_len > cur_len && Blockchain::valid_chain(&chain) {
                debug!(
                    "Found a better chain of len {} from: {}",
                    new_len, node.address
                );
                max_len = new_len;
                self.chain = chain;
            }
        }

        info!("max_len: {}, cur_len: {}", max_len, cur_len);

        Ok(max_len > cur_len)
    }
}

#[derive(Hash, Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    index: usize,
    timestamp: DateTime<Utc>,
    transactions: Vec<Transaction>,
    pub proof: u64,
    previous_hash: u64,
}

#[derive(Hash, Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub sender: String,
    pub recipient: String,
    pub amount: i64,
}

#[derive(Hash, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Node {
    #[serde(with = "url_serde")]
    address: Url,
}
