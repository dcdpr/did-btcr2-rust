use crate::smt::{Smt, SmtNih, SmtRocks, SmtSled, SmtSqlite, hash_concat};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use smt::Hash;
use std::{cell::RefCell, fmt::Write as _, process::Command, time::Instant};
use std::{collections::BTreeMap, io::Write as _};

mod smt;

// Number of randomized trials to run for SMT simulation.
const TRIALS: u32 = 25;

const DEFAULT_PRNG_SEED: [u8; 32] = [
    // echo -n 'https://xkcd.com/221/' | sha256sum
    0x62, 0xbe, 0xf7, 0x04, 0x85, 0xaf, 0x17, 0x10, 0x26, 0x53, 0x68, 0xee, 0x4d, 0x89, 0x11, 0x22,
    0x8a, 0xc6, 0x3c, 0x93, 0x62, 0x83, 0xa4, 0x19, 0x59, 0x1e, 0xc9, 0x37, 0xb6, 0x79, 0x88, 0xef,
];

thread_local! {
    /// Deterministic PRNG seeded with an arbitrarily chosen SHA-256 hash.
    ///
    /// Because it's thread-local, multiple threads will not be able to deterministically share the
    /// PRNG state.
    static PRNG: RefCell<StdRng> = RefCell::new(StdRng::from_seed(DEFAULT_PRNG_SEED));
}

/// Re-implement [`monotree::utils::random_hash`] with a deterministic PRNG.
fn random_hash() -> Hash {
    PRNG.with(|prng| prng.borrow_mut().r#gen())
}

fn random_size(n: usize) -> usize {
    if n == 1 {
        1
    } else {
        PRNG.with(|prng| prng.borrow_mut().r#gen_range(1..n))
    }
}

/// Re-seed the PRNG with its default settings.
fn reseed_prng() {
    PRNG.with(|prng| prng.replace(StdRng::from_seed(DEFAULT_PRNG_SEED)));
}

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

fn create_kv_pairs(num: usize) -> Vec<(Hash, Hash)> {
    let mut kv_pairs = Vec::with_capacity(num);

    for _ in 0..num {
        kv_pairs.push((random_hash(), random_hash()));
    }
    kv_pairs
}

fn create_proof() {
    reseed_prng();

    let db_path = "./db/smt-sim.sqlite";

    // Remove old DB (if any)
    Command::new("rm").args(["-rf", db_path]).output().unwrap();

    let total_nodes = 32;
    let with_diagrams = false;
    println!(
        "Inserting and verifying proofs for {total_nodes} nodes{}...",
        if with_diagrams { " with diagrams" } else { "" },
    );

    let smt = SmtNih::new(db_path).unwrap();
    let kv_pairs = create_kv_pairs(total_nodes);

    let root = smt_demo(&smt, &kv_pairs, with_diagrams);

    println!("root: {}", hex::encode(root));
    println!();

    let mut excluded_hash = kv_pairs[0].0;
    for byte in &mut excluded_hash {
        // Invert all bytes in the hash.
        *byte ^= 0xff;
    }
    if kv_pairs.iter().all(|(k, _)| k != &excluded_hash) {
        let proof = smt.get_proof(&root, &excluded_hash).unwrap();

        println!("Checking proof of non-inclusion...");
        println!("key: {}", hex::encode(excluded_hash));
        println!("proof: {proof}");

        proof
            .verify_noninclusion(&root)
            .expect("must prove non-inclusion");

        println!("Verified the key is not included in the SMT!");
        println!();
    }

    for (key, value) in kv_pairs {
        let proof = smt.get_proof(&root, &key).unwrap();

        println!("key: {}", hex::encode(key));
        println!("value: {}", hex::encode(value));
        println!("leaf: {}", hex::encode(hash_concat(&key, &value)));
        println!("proof: {proof}");
        // println!("proof: {}", print_proof(&proof)); // for monotree

        proof
            .verify(&root, &key, &value)
            .expect("must prove inclusion");
        proof
            .verify_noninclusion(&root)
            .expect_err("cannot prove both inclusion and non-inclusion");

        println!();
    }

    if let Some(diagram) = smt.render(&root) {
        std::fs::write("smt.mmd", diagram).unwrap();
    }

    println!("All proofs verified!");
    println!();
}

#[allow(dead_code)]
fn print_proof(proof: &[(bool, Vec<u8>)]) -> String {
    let mut pretty = String::new();

    writeln!(&mut pretty, "[").unwrap();
    for (direction, hash) in proof {
        writeln!(
            &mut pretty,
            "    {}: {},",
            if *direction { 1 } else { 0 },
            hex::encode(hash)
        )
        .unwrap();
    }
    writeln!(&mut pretty, "]").unwrap();

    pretty
}

fn benchmark_tree<T>()
where
    T: Smt,
    <T as Smt>::Error: std::fmt::Debug,
{
    reseed_prng();

    // 1 million is effectively beyond the limit for practical purposes. We should include it when
    // running the full benchmark, allowing backends to fail (e.g. don't unwrap, impose timeouts,
    // etc.) It will leave blank spaces in the sequence data for the diagrams. But that's ok.
    //
    // TODO: Is there a nice way to indicate error conditions in diagrams?
    let sizes = [1, 5, 10, 100, 1_000, 10_000, 50_000, 100_000];
    // let sizes = [1, 5, 10, 100, 1_000, 10_000, 50_000, 100_000, 1_000_000];

    for size in sizes {
        let db_path = format!("./db/smt-sim-{}.{}", human_size(size), T::EXT);

        // Remove old DB (if any)
        Command::new("rm").args(["-rf", &db_path]).output().unwrap();

        let start = Instant::now();

        let smt = T::new(&db_path).unwrap();
        let kv_pairs = create_kv_pairs(size);

        smt_demo(&smt, &kv_pairs, false);

        println!(
            "Created `{db_path}` in {:?}",
            Instant::now().duration_since(start),
        );
    }

    println!();

    for size in sizes {
        let dbpath = format!("./db/smt-sim-{}.{}", human_size(size), T::EXT);

        // Get the DB's size on disk
        let db_size = Command::new("du").args(["-hs", &dbpath]).output().unwrap();
        println!("{}", String::from_utf8_lossy(&db_size.stdout).trim());
    }

    println!();
}

fn benchmark_proof<T>()
where
    T: Smt,
    <T as Smt>::Error: std::fmt::Debug,
{
    reseed_prng();

    // Get the raw size of proofs for:
    // - N = cohort size
    // - M = %mine
    // - U = average updates per block by others (i.e., how many updates in the tree)
    //   - NOTE: When "use-nonce" is true, U = 1.0 (every user always updates)

    // let sizes = [5, 10, 100, 1_000, 10_000, 50_000, 100_000, 1_000_000];
    let sizes = [1_000];

    println!("Running proof size benchmark...");

    for size in sizes {
        println!("Cohort size: {}", human_size(size));

        let mut surface = Surface::new(size as u64);
        let db_path = format!("./db/smt-sim-{}.{}", human_size(size), T::EXT);

        for m in [0.0, 0.01, 0.05, 0.1, 0.25, 0.5, 0.75] {
            if size > 1_000 {
                println!("Running simulation with {}% mine...", m * 100.0);
            }

            let my_did_count = (size as f64 * m) as usize;
            let kv_pairs = create_kv_pairs(size);
            let mut i = 0;
            let (mine, not_mine): (Vec<_>, Vec<_>) = kv_pairs.into_iter().partition(|_| {
                i += 1;

                i < my_did_count
            });
            let max_possible_updates = size as f64 * (1.0 - m);

            // TODO: Run two simulations:
            //
            // 1. Proofs of non-inclusion without nonce (done below)
            // 2. Proofs of inclusion with nonce
            //
            // When plotting the diagram, pass both surfaces. The color is determined by the
            // difference sampled from both surfaces.

            // Run some randomized trials to collect rough averages
            for _trial in 0..TRIALS {
                if size > 10_000 {
                    // println!("Running trial {} of {TRIALS}", trial + 1);
                    print!(".");
                    std::io::stdout().lock().flush().unwrap();
                }

                // todo: is currently Uniform sampling, we want Gaussian?
                let avg_num_updates = random_size(max_possible_updates as usize);

                // Insert all updates into the tree
                let smt = T::new(&db_path).unwrap();
                let root = smt_demo(&smt, &not_mine[..avg_num_updates], false);

                // Create all of my proofs of non-inclusion
                let my_proofs = mine
                    .iter()
                    .map(|(key, _)| smt.get_proof(&root, key))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();

                // TODO: Compress proofs into a prefix tree.
                // Write all proofs to memory
                let mut writer = Vec::new();
                bincode::encode_into_std_write(my_proofs, &mut writer, bincode::config::standard())
                    .unwrap();
                let byte_count = writer.len() as u64;

                // Insert the proof size into the surface
                surface.insert((m * 100.0) as u64, avg_num_updates as u64, byte_count);

                // Write all proofs to disk
                let p_path = format!("./db/smt-sim-{size}-{m}.proof");
                std::fs::write(&p_path, &writer).unwrap();

                // Show proof's size on disk
                let proof_size = Command::new("du").args(["-hs", &p_path]).output().unwrap();
                println!("{}", String::from_utf8_lossy(&proof_size.stdout).trim());
            }

            if size > 10_000 {
                println!();
            }
        }

        draw_chart(&surface);

        println!();
    }
}

fn smt_demo<T>(smt: &T, kv_pairs: &[(Hash, Hash)], diagrams: bool) -> Hash
where
    T: Smt,
    <T as Smt>::Error: std::fmt::Debug,
{
    let mut root = None;

    let tx = smt.prepare();
    for (i, (key, value)) in kv_pairs.iter().enumerate() {
        root = smt.insert(root.as_ref(), key, value).unwrap();

        if diagrams && let Some(diagram) = smt.render(&root.unwrap()) {
            std::fs::write(format!("smt.{i}.mmd"), diagram).unwrap();
        }
    }
    smt.commit(tx);

    root.unwrap()
}

fn human_size(size: usize) -> String {
    match size {
        0..1_000 => format!("{size}"),
        1_000..1_000_000 => format!("{}K", size / 1_000),
        1_000_000..1_000_000_000 => format!("{}M", size / 1_000_000),
        _ => panic!("My spoon is too big!"),
    }
}

fn draw_chart(surface: &Surface) {
    use plotters::prelude::*;

    let cohort_size = surface.cohort_size;
    let max_bytes = surface.max_bytes;
    let filename = format!("./db/surface_{}.svg", human_size(cohort_size as usize));
    let drawing_area = SVGBackend::new(&filename, (800, 600)).into_drawing_area();

    // Draw background.
    drawing_area.fill(&WHITE).unwrap();

    let mut chart_context = ChartBuilder::on(&drawing_area)
        .margin(25)
        .x_label_area_size(50)
        .y_label_area_size(70)
        .build_cartesian_2d(0..100_u64, 0..cohort_size)
        .unwrap();

    // Green: 0% difference. Red: 100% difference.
    let hue = |x, y| (1.0 - (surface.sample(x, y) as f64 / max_bytes as f64)) * 0.36;

    // // Rainbow
    // let hue = |x, y| surface.sample(x, y) as f64 / max_bytes as f64;

    // Draw surface.
    let v = cohort_size / 100.min(cohort_size);
    chart_context
        .draw_series((0..cohort_size).step_by(v as usize).flat_map(|y| {
            (0..100).map(move |x| {
                Rectangle::new(
                    [(x, y), (x + 1, y + v)],
                    HSLColor(hue(x, y), 1.0, 0.5).filled(),
                )
            })
        }))
        .unwrap();

    let label_style = ("Calibri", 25, &BLACK).into_text_style(&drawing_area);

    // Draw axes.
    chart_context
        .configure_mesh()
        .label_style(label_style)
        .x_desc("M: Percentage that are My DIDs")
        .y_desc("U: Average updates by others")
        .y_label_formatter(&|y| human_size(*y as usize).to_string())
        .draw()
        .unwrap();

    // TODO: Draw color legend.

    println!("Phase transition diagram written to {filename}");
}

/// A sparse surface for representing the SMT simulation's phase transition diagram.
struct Surface {
    /// Samples are stored sparsely as discrete points in a 2D [`BTreeMap`].
    ///
    /// - The outer dimension is `M` (Percentage of DIDs in the tree that are "mine").
    /// - The inner dimension is `U` (Average number of updates from other DIDs in the tree).
    samples: BTreeMap<u64, BTreeMap<u64, u64>>,

    /// Cohort size for the simulation.
    cohort_size: u64,

    /// Stores the maximum byte size seen in all samples.
    max_bytes: u64,
}

impl Surface {
    fn new(cohort_size: u64) -> Self {
        Self {
            samples: BTreeMap::new(),
            cohort_size,
            max_bytes: 0,
        }
    }

    /// Insert a surface height `d` at surface coordinate `[m,u]`.
    fn insert(&mut self, m: u64, u: u64, d: u64) {
        self.samples.entry(m).or_default().insert(u, d);

        self.max_bytes = self.max_bytes.max(d);
    }

    /// Get the surface height `d` at coordinates `[m,u]`.
    fn sample(&self, m: u64, u: u64) -> u64 {
        // To make the sparse surface continuous: Sample two points along each axis then linearly
        // interpolate between them.

        let b = self.max_bytes as f64;

        // Coordinates at "previous M".
        let (x0, z0) = self
            .samples
            .range(..=m)
            .next_back()
            .map(|(x0, mine)| {
                (
                    *x0 as f64 / 100.0,
                    mine.range(..=u)
                        .next_back()
                        .map(|(_, bytes)| *bytes as f64 / b)
                        .unwrap_or_default(),
                )
            })
            .unwrap_or_default();

        // Coordinates at "next M".
        let (x1, z1) = self
            .samples
            .range(m..)
            .next()
            .map(|(x1, mine)| {
                (
                    *x1 as f64 / 100.0,
                    mine.range(..=u)
                        .next_back()
                        .map(|(_, bytes)| *bytes as f64 / b)
                        .unwrap_or(z0),
                )
            })
            .unwrap_or((1.0, z0));

        // Calculate the "time" for interpolation across M axis.
        let xd = x1 - x0;
        let x = m as f64 / 100.0;
        let t = if xd > 0.0 { (x - x0) / xd } else { 0.0 };

        // Interpolate and scale back to byte range.
        (lerp(z0, z1, t) * b) as u64
    }
}

/// Linear interpolation between `a` and `b` at time `t`.
fn lerp(a: f64, b: f64, t: f64) -> f64 {
    t.mul_add(b - a, a)
}
