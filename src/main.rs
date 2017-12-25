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

use std::env;
use std::sync::RwLock;
use iron::prelude::*;
use iron::status;
use router::Router;
use logger::Logger;
use persistent::State;
use iron::mime::Mime;
// chain
use chain::{new_blockchain, Blockchain, Transaction, Node};

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
        let arc_rw_lock = itry!(req.get::<State<Blockchain>>());
        let mut bc = arc_rw_lock.write().unwrap();

        let proof = Blockchain::proof_of_work(bc.last_block().proof);
        bc.new_block(proof, None);

        respond_ok(json!({
            "block":bc.last_block(),
        }))
    }
    fn transactions_new(req: &mut Request) -> IronResult<Response> {
        let arc_rw_lock = itry!(req.get::<State<Blockchain>>());
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
        let arc_rw_lock = itry!(req.get::<State<Blockchain>>());
        let bc = arc_rw_lock.read().unwrap();

        respond_ok(json!({
            "chain": bc.chain,
        }))
    }
    fn nodes_register(req: &mut Request) -> IronResult<Response> {
        let arc_rw_lock = itry!(req.get::<State<Blockchain>>());
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
        let arc_rw_lock = itry!(req.get::<State<Blockchain>>());
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

mod chain;

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
        assert!(Blockchain::valid_chain(&bc.chain));

        for _ in 0..2 {
            let proof = Blockchain::proof_of_work(bc.last_block().proof);
            bc.new_block(proof, None);

            assert!(Blockchain::valid_chain(&bc.chain));
        }
    }
}
