# Atomic Swaps for Meros - Proof of Concept

A proof-of-concept implementation of [Bitcoin-Monero Cross-chain Atomic Swap](https://github.com/h4sh3d/xmr-btc-atomic-swap/raw/master/whitepaper/xmr-btc.pdf), initially targeting Bitcoin and Meros. Despite this being protocol being designed for Monero, the cryptography within is directly applicable to nearly all coins without scripting functionality. In accordance, this implementation was designed to be extremely easy to expand, so adding support for new coins on either side should only take a few days.

Currently, the following coins are supported:
- Bitcoin
- Meros
- Nano
- Monero

While this is designed to be complete and accurate, it offers no security guarantees. This has not been audited and should be used at your own risk.

### Transaction Malleability

It should be noted Bitcoin usually has a major problem with transaction IDs. When this problem is left unresolved, Alice (the person with Meros/Monero) is able to cause Bob (the person with bitcoin) to lose their coins. While Alice would not gain anything in this circumstance, they also would not lose anything. This one-sided disadvantage goes against the safeties atomic swaps offer, and is possible because Bitcoin transaction IDs are malleable. Alice can commit to a refund transaction spending lock X, watch lock X be sent to the network, but then change an 'insignificant' piece of data causing lock X to become lock Y. If lock Y was archived on the blockchain, Alice would have lost nothing, yet Bob's bitcoin would be gone forever.

There's only one type of Bitcoin transaction which does not have this risk; SegWit transactions. SegWit was designed with one of the goals being removing malleability problems, and is therefore used by this library. That said, any Bitcoin-fork without SegWit, or any similar transaction malleability guarantees, will not work securely with this library (any by definition cannot implement this swap protocol atomically).

The whitepaper does directly address this problem.

### Configuration

In addition to the CLI options explained with `--help`, you'll need to specify JSON configs for each cryptocurrency, specifying the RPC info and addresses. You can find examples in the `/config_examples` folder. These configs should be placed in a `config` folder relative to the working directory.
