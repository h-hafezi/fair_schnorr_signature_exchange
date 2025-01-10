# Fair Schnorr Signature Exchange

This repository contains implementations and benchmarks for the Fair Schnorr Signature Exchange protocol.

## Running Tests

To run all the tests in the repository, use the following command:

```bash
cargo test
```

This will execute all unit and integration tests.

## Running Benchmarks

The repository includes three benchmark suites:

1. `bench_fse`
2. `bench_bfse`
3. `bench_schnorr`

To run all the benchmarks, use the following commands:

```bash
cargo bench --bench bench_fse
cargo bench --bench bench_bfse
cargo bench --bench bench_schnorr
```

Each command will execute the corresponding benchmark and display the results.

---

Feel free to reach out if you encounter any issues or have suggestions!
