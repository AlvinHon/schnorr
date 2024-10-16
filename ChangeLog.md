## 0.2.0 (Oct-2024)
- remove custom traits Hash, Sig and Rand. Instead use the traits provided by crates `digest`, `signature` and `rand_core`.
- code refactoring - use a single generic struct instead of using separating structs for different group implementations (i.e. `num-bigint` and `p256`).
- add benches for benchmarking steps in protocols.

## 0.1.0 (Jul-2024)
- initial version of schnorr-rs.