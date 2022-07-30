# Rockchain

[![Build Status](https://github.com/kujenga/rockchain/actions/workflows/rust.yml/badge.svg)](https://github.com/kujenga/rockchain/actions)
[![Build Status](https://ci.appveyor.com/api/projects/status/ynq3ue8i6mfokljy?svg=true)](https://ci.appveyor.com/project/kujenga/blockchain)

A blockchain written in Rust.

This project is aimed at furthering my personal understanding of Rust. The
blockchain implementation is based on the following walkthrough, which was
originally done in Python:

https://hackernoon.com/learn-blockchains-by-building-one-117428612f46

Many thanks to the original author!

## Usage

The following command will start the blockchain server.

```sh
RUST_LOG=blockchain,iron,logger=info cargo run
```

View the blockchain in it's empty genesis state:

```sh
curl http://localhost:3000/chain | jq
```

Create a new transaction:

```sh
curl -XPOST http://localhost:3000/transactions/new -H 'Content-Type: application/json' --data '{
  "sender": "me",
  "recipient": "you",
  "amount": 123
}' | jq
```

Trigger mining, creating a new block:

```sh
curl http://localhost:3000/mine | jq
```

View the blockchain again, with the requested transaction now persisted within
a block:

```sh
curl http://localhost:3000/chain | jq
```

### Creating a network

The `PORT` environment variable can be used to set a custom port number. In
another window, another node can be started with the following command.

```sh
RUST_LOG=blockchain,iron,logger=info PORT=3001 cargo run
```

To manually register this node with the original one, the following request
can be performed:

```sh
curl -XPOST http://localhost:3001/nodes/register -H 'Content-Type: application/json' --data '{
  "nodes": [{
    "address": "http://localhost:3000"
  }]
}' | jq
```

Trigger the execution of the consensus protocol, bringing state of the new
node up to date:

```sh
curl http://localhost:3001/nodes/resolve | jq
```

## Status

- [x] Building a blockchain
- [x] Blockchain API
- [x] Distributed Consensus
- [x] More idiomatic error handling
- [x] Refactor blockchain and server into separate modules
- [ ] Auto-register peers using CLI args
- [ ] Move blockchain data types into library crate
