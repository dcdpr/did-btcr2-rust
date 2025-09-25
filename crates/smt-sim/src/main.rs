use smt_sim::smt::{SmtNih, SmtRocks, SmtSled, SmtSqlite};
use smt_sim::{benchmark_proof, benchmark_tree, create_proof};

fn main() {
    // Run the proof creator/printer
    create_proof();

    // Run all the benchmarks
    if std::env::args().nth(1) == Some("--bench-tree".to_string()) {
        benchmark_tree::<SmtNih>();
        benchmark_tree::<SmtSqlite>();
        benchmark_tree::<SmtRocks>();
        benchmark_tree::<SmtSled>();
    }

    if std::env::args().nth(1) == Some("--bench-proof".to_string()) {
        benchmark_proof::<SmtNih>();
    }
}
