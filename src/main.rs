extern crate axum;
extern crate axum_macros;
extern crate byteorder;
extern crate bytes;
extern crate chrono;
extern crate futures;
extern crate http;
extern crate hyper;
extern crate serde;
extern crate sha2;
extern crate tracing;
extern crate url;
extern crate url_serde;
#[macro_use]
extern crate log;
extern crate serde_json;

mod chain;

use axum::{
    error_handling::HandleErrorLayer,
    extract::Extension,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    BoxError, Router,
};
use futures::lock::Mutex;
use serde_json::{json, Value};
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use tower::ServiceBuilder;
use tower_http::{trace::TraceLayer, ServiceBuilderExt};
// Neighboring chain module.
use chain::{Blockchain, NodeRegisterReq, Transaction};

async fn handle_errors(err: BoxError) -> impl IntoResponse {
    if err.is::<tower::timeout::error::Elapsed>() {
        (
            StatusCode::REQUEST_TIMEOUT,
            "Request took too long".to_string(),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unhandled internal error: {}", err),
        )
    }
}

type SharedState = Arc<Mutex<Blockchain>>;

#[tokio::main]
async fn main() {
    // Setup tracing
    tracing_subscriber::fmt::init();

    // Setup state
    // c.link(State::<Blockchain>::both(RwLock::new(new_blockchain())));
    let state: SharedState = SharedState::default();

    // Build our middleware stack
    // ref: https://github.com/tower-rs/tower-http/blob/master/examples/axum-key-value-store/src/main.rs
    let middleware = ServiceBuilder::new()
        // Add high level tracing/logging to all requests
        .layer(TraceLayer::new_for_http())
        // Handle errors
        .layer(HandleErrorLayer::new(handle_errors))
        // Set a timeout
        .timeout(Duration::from_secs(10))
        // Share the state with each handler via a request extension
        .add_extension(state)
        // Compress responses
        .compression()
        // Set a `Content-Type` if there isn't one already.
        .insert_response_header_if_not_present(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );

    let app = Router::new()
        .route("/", get(index))
        .route("/mine", get(mine))
        .route("/transactions/new", post(transactions_new))
        .route("/chain", get(chain))
        .route("/nodes/register", post(nodes_register))
        .route("/nodes/resolve", get(nodes_resolve))
        .layer(middleware.into_inner());

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let port = env::var("PORT")
        .unwrap_or("3000".to_owned())
        .parse::<u16>()
        .unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    // handler definitions

    #[axum_macros::debug_handler]
    async fn index() -> String {
        "Welcome to the Blockchain server!\n".to_string()
    }
    #[axum_macros::debug_handler]
    async fn mine(Extension(state): Extension<SharedState>) -> Json<Value> {
        let mut bc = state.lock().await;

        let proof = Blockchain::proof_of_work(bc.last_block().proof);
        bc.new_block(proof, None);

        Json(json!({
            "block":bc.last_block(),
        }))
    }
    #[axum_macros::debug_handler]
    async fn transactions_new(
        Extension(state): Extension<SharedState>,
        Json(transaction): Json<Transaction>,
    ) -> Json<Value> {
        let mut bc = state.lock().await;

        bc.new_transaction(transaction);

        Json(json!({
            "current_transactions": bc.current_transactions,
        }))
    }
    async fn chain(Extension(state): Extension<SharedState>) -> Json<Value> {
        let bc = state.lock().await;

        Json(json!({
            "chain": bc.chain,
        }))
    }
    #[axum_macros::debug_handler]
    async fn nodes_register(
        Extension(state): Extension<SharedState>,
        Json(node_req): Json<NodeRegisterReq>,
    ) -> Json<Value> {
        let mut bc = state.lock().await;

        for node in node_req.nodes {
            bc.register_node(node);
        }

        Json(json!({
            "message": "New nodes have been added",
            "total_nodes": bc.nodes,
        }))
    }
    #[axum_macros::debug_handler]
    async fn nodes_resolve(
        Extension(state): Extension<SharedState>,
    ) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
        let mut bc = state.lock().await;

        let replaced = match bc.resolve_conflicts().await {
            Ok(r) => r,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": e.to_string()})),
                ))
            }
        };

        let msg = if replaced {
            "Our chain was replaced"
        } else {
            "Our chain is authoritative"
        };
        Ok(Json(json!({
            "message": msg,
            "chain": bc.chain,
            "replaced": replaced,
        })))
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let mut bc = Blockchain::default();
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
        let mut bc = Blockchain::default();
        assert!(Blockchain::valid_chain(&bc.chain));

        for _ in 0..2 {
            let proof = Blockchain::proof_of_work(bc.last_block().proof);
            bc.new_block(proof, None);

            assert!(Blockchain::valid_chain(&bc.chain));
        }
    }
}
