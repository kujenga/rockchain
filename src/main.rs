extern crate chrono;
extern crate sha2;
extern crate byteorder;
#[macro_use]
extern crate iron;
extern crate router;
extern crate logger;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate persistent;
extern crate bodyparser;
extern crate url;
extern crate serde;
extern crate url_serde;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate futures;
extern crate hyper;
extern crate tokio_core;

use std::mem;
use std::env;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::RwLock;
use chrono::prelude::*;
use sha2::{Sha256, Digest};
use byteorder::{BigEndian, WriteBytesExt};
use iron::prelude::*;
use iron::status;
use router::Router;
use logger::Logger;
use iron::typemap::Key;
use persistent::State;
use iron::mime::Mime;
use url::Url;
use futures::{Future, Stream};
use hyper::{Client, Chunk};
use tokio_core::reactor::Core;

fn main() {
    env_logger::init().unwrap();

    let mut router = Router::new();

    router.get("/", index, "index");
    router.get("/mine", mine, "mine");
    router.post("/transactions/new", transactions_new, "transactions_new");
    router.get("/chain", chain, "chain");
    router.post("/nodes/register", nodes_register, "nodes_register");
    router.get("/nodes/resolve", nodes_resolve, "nodes_resolve");

    let mut c = Chain::new(router);
    let (logger_before, logger_after) = Logger::new(None);
    c.link_before(logger_before);
    c.link_after(logger_after);
    c.link(State::<Blockchain>::both(RwLock::new(new_blockchain())));

    let port = env::var("PORT").unwrap_or("3000".to_owned());
    let addr = format!("localhost:{}", port);
    match Iron::new(c).http(addr) {
        Ok(listening) => info!("Started server: {:?}", listening),
        Err(err) => panic!("Unable to start server: {:?}", err),
    };

    // handler definitions

    fn index(_: &mut Request) -> IronResult<Response> {
        Ok(Response::with(
            (status::Ok, "Welcome to the Blockchain server!\n"),
        ))
    }
    fn mine(req: &mut Request) -> IronResult<Response> {
        let arc_rw_lock = req.get::<State<Blockchain>>().unwrap();
        let mut bc = arc_rw_lock.write().unwrap();

        let proof = Blockchain::proof_of_work(bc.last_block().proof);
        bc.new_block(proof, None);

        respond_ok(json!({
            "block":bc.last_block(),
        }))
    }
    fn transactions_new(req: &mut Request) -> IronResult<Response> {
        let arc_rw_lock = req.get::<State<Blockchain>>().unwrap();
        let mut bc = arc_rw_lock.write().unwrap();

        let transaction = iexpect!(itry!(
            req.get::<bodyparser::Struct<Transaction>>(),
            status::BadRequest
        ));
        bc.new_transaction(transaction);

        respond_ok(json!({
            "current_transactions": bc.current_transactions,
        }))
    }
    fn chain(req: &mut Request) -> IronResult<Response> {
        let arc_rw_lock = req.get::<State<Blockchain>>().unwrap();
        let bc = arc_rw_lock.read().unwrap();

        respond_ok(json!({
            "chain": bc.chain,
        }))
    }
    fn nodes_register(req: &mut Request) -> IronResult<Response> {
        let arc_rw_lock = req.get::<State<Blockchain>>().unwrap();
        let mut bc = arc_rw_lock.write().unwrap();

        // TODO: Provide better error responses here.
        #[derive(Clone, Serialize, Deserialize)]
        struct NodeRegisterReq {
            nodes: Vec<Node>,
        }
        let node_req = iexpect!(itry!(
            req.get::<bodyparser::Struct<NodeRegisterReq>>(),
            (status::BadRequest, "Invalid JSON")
        ));

        for node in node_req.nodes {
            bc.register_node(node);
        }

        respond_ok(json!({
            "message": "New nodes have been added",
            "total_nodes": bc.nodes,
        }))
    }
    fn nodes_resolve(req: &mut Request) -> IronResult<Response> {
        let arc_rw_lock = req.get::<State<Blockchain>>().unwrap();
        let mut bc = arc_rw_lock.write().unwrap();

        let replaced = bc.resolve_conflicts()?;

        let msg = if replaced {
            "Our chain was replaced"
        } else {
            "Our chain is authoritative"
        };
        respond_ok(json!({
            "message": msg,
            "chain": bc.chain,
            "replaced": replaced,
        }))
    }
}

// Handler helpers

fn respond_ok<T: serde::Serialize>(data: T) -> IronResult<Response> {
    let content_type = "application/json".parse::<Mime>().unwrap();
    let json = match serde_json::to_string(&data) {
        Ok(json) => json,
        Err(e) => {
            error!("Unable to serialize response: {}", e);
            return Err(IronError::new(e, status::InternalServerError));
        }
    };
    Ok(Response::with((content_type, status::Ok, json)))
}

// Blockchain data types

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Blockchain {
    chain: Vec<Block>,
    current_transactions: Vec<Transaction>,
    nodes: HashSet<Node>,
}

// Create an initialized blockchain.
fn new_blockchain() -> Blockchain {
    let mut bc = Blockchain { ..Default::default() };
    // add genesis block
    bc.new_block(100, Some(1));
    bc
}

impl Default for Blockchain {
    fn default() -> Blockchain {
        Blockchain {
            chain: Vec::new(),
            current_transactions: Vec::new(),
            nodes: HashSet::new(),
        }
    }
}

impl Key for Blockchain {
    type Value = Blockchain;
}

impl Blockchain {
    // Creates a new Block and adds it to the chain
    fn new_block(&mut self, proof: u64, previous_hash: Option<u64>) {
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
    fn new_transaction(&mut self, transaction: Transaction) -> usize {
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
    fn last_block(&self) -> &Block {
        &self.chain[self.chain.len() - 1]
    }

    fn proof_of_work(last_proof: u64) -> u64 {
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
    fn register_node(&mut self, node: Node) {
        self.nodes.insert(node);
    }

    // Consensus

    // Determine if the passed in chain is valid.
    fn valid_chain(chain: &Vec<Block>) -> bool {
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
    fn resolve_conflicts(&mut self) -> IronResult<bool> {

        let cur_len = self.chain.len();
        let mut max_len = cur_len;

        let mut core = itry!(Core::new());
        let client = Client::new(&core.handle());

        for node in self.nodes.iter() {
            info!("calling node: {:?}", node);

            let mut target = node.address.to_owned();
            target.set_path("/chain");
            let uri = itry!(target.into_string().parse());

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

            let chain = itry!(itry!(core.run(work))).chain;
            let new_len = chain.len();
            if new_len > cur_len && Blockchain::valid_chain(&chain) {
                debug!("Found a better chain of len {} from: {}", new_len, node.address);
                max_len = new_len;
                self.chain = chain;
            }
        }

        info!("max_len: {}, cur_len: {}", max_len, cur_len);

        Ok(max_len > cur_len)
    }
}

#[derive(Hash, Debug, Clone, Serialize, Deserialize)]
struct Block {
    index: usize,
    timestamp: DateTime<Utc>,
    transactions: Vec<Transaction>,
    proof: u64,
    previous_hash: u64,
}

#[derive(Hash, Debug, Clone, Serialize, Deserialize)]
struct Transaction {
    sender: String,
    recipient: String,
    amount: i64,
}

#[derive(Hash, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct Node {
    #[serde(with = "url_serde")]
    address: Url,
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let mut bc = new_blockchain();
        assert_eq!(bc.chain.len(), 1);

        // new block
        bc.new_transaction(Transaction {
            sender: "me".to_owned(),
            recipient: "you".to_owned(),
            amount: 5,
        });
        bc.new_transaction(Transaction {
            sender: "you".to_owned(),
            recipient: "me".to_owned(),
            amount: 2,
        });
        assert_eq!(bc.current_transactions.len(), 2);

        let proof = Blockchain::proof_of_work(bc.last_block().proof);
        bc.new_block(proof, None);
        assert_eq!(bc.chain.len(), 2);
    }

    #[test]
    fn consensus() {
        let mut bc = new_blockchain();
        assert!(Blockchain::valid_chain(&bc));

        for _ in 0..2 {
            let proof = Blockchain::proof_of_work(bc.last_block().proof);
            bc.new_block(proof, None);

            assert!(Blockchain::valid_chain(&bc));
        }
    }
}
