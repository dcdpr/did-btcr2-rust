use crate::smt::{Hash, Smt, SmtNih, hash_concat};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use std::{cell::RefCell, process::Command, time::Instant};
use std::{collections::BTreeMap, io::Write as _};
use ultraviolet::{DVec2, DVec3};

pub mod smt;

// Number of randomized trials to run for SMT simulation.
const TRIALS: u32 = 25;

const DEFAULT_PRNG_SEED: [u8; 32] = [
    // echo -n 'https://xkcd.com/221/' | sha256sum
    0x62, 0xbe, 0xf7, 0x04, 0x85, 0xaf, 0x17, 0x10, 0x26, 0x53, 0x68, 0xee, 0x4d, 0x89, 0x11, 0x22,
    0x8a, 0xc6, 0x3c, 0x93, 0x62, 0x83, 0xa4, 0x19, 0x59, 0x1e, 0xc9, 0x37, 0xb6, 0x79, 0x88, 0xef,
];

const MY_PERCENTAGES: [f64; 10] = [0.01, 0.05, 0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.975, 0.99];

// 1 million is effectively beyond the limit for practical purposes. We should include it when
// running the full benchmark, allowing backends to fail (e.g. don't unwrap, impose timeouts,
// etc.) It will leave blank spaces in the sequence data for the diagrams. But that's ok.
// const SIZES: [usize; 7] = [10, 100, 1_000, 10_000, 50_000, 100_000, 1_000_000];
const SIZES: [usize; 6] = [10, 100, 1_000, 10_000, 50_000, 100_000];

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
    if n <= 1 {
        1
    } else {
        PRNG.with(|prng| prng.borrow_mut().r#gen_range(1..n))
    }
}

/// Re-seed the PRNG with its default settings.
fn reseed_prng() {
    PRNG.with(|prng| prng.replace(StdRng::from_seed(DEFAULT_PRNG_SEED)));
}

fn create_kv_pairs(num: usize) -> Vec<(Hash, Hash)> {
    let mut kv_pairs = Vec::with_capacity(num);

    for _ in 0..num {
        kv_pairs.push((random_hash(), random_hash()));
    }
    kv_pairs
}

pub fn create_proof() {
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

pub fn benchmark_tree<T>()
where
    T: Smt,
    <T as Smt>::Error: std::fmt::Debug,
{
    reseed_prng();

    for size in SIZES {
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

    for size in SIZES {
        let dbpath = format!("./db/smt-sim-{}.{}", human_size(size), T::EXT);

        // Get the DB's size on disk
        let db_size = Command::new("du").args(["-hs", &dbpath]).output().unwrap();
        println!("{}", String::from_utf8_lossy(&db_size.stdout).trim());
    }

    println!();
}

pub fn benchmark_proof<T>()
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

    println!("Running proof size benchmark...");

    for size in SIZES {
        println!("Cohort size: {}", human_size(size));

        let surface_wo = create_surface_without_nonce::<T>(size);
        let surface_w = create_surface_with_nonce::<T>(size);

        println!("Without Nonce max_bytes: {}", surface_wo.max_bytes);
        println!("With Nonce max_bytes:    {}", surface_w.max_bytes);

        let diff = surface_w.difference(&surface_wo);
        println!("Diff  max_bytes: {}", diff.max_bytes);

        draw_chart(&surface_wo, "wo");
        draw_chart(&surface_w, "w");
        draw_chart(&diff, "diff");

        println!();
    }
}

fn create_surface_without_nonce<T>(size: usize) -> Surface
where
    T: Smt,
    <T as Smt>::Error: std::fmt::Debug,
{
    let mut surface = Surface::new(size as u64);
    let db_path = format!("./db/smt-sim-{}.{}", human_size(size), T::EXT);

    for m in MY_PERCENTAGES {
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
            if size <= 10_000 {
                let proof_size = Command::new("du").args(["-hs", &p_path]).output().unwrap();
                println!("{}", String::from_utf8_lossy(&proof_size.stdout).trim());
            }
        }

        if size > 10_000 {
            println!();
        }
    }

    surface
}

fn create_surface_with_nonce<T>(size: usize) -> Surface
where
    T: Smt,
    <T as Smt>::Error: std::fmt::Debug,
{
    let mut surface = Surface::new(size as u64);
    let db_path = format!("./db/smt-sim-{}.{}", human_size(size), T::EXT);

    for m in MY_PERCENTAGES {
        if size > 1_000 {
            println!("Running simulation with {}% mine...", m * 100.0);
        }

        let my_did_count = (size as f64 * m) as usize;
        let kv_pairs = create_kv_pairs(size);
        let smt = T::new(&db_path).unwrap();
        let root = smt_demo(&smt, &kv_pairs, false);

        let mut i = 0;
        let (mine, not_mine): (Vec<_>, Vec<_>) = kv_pairs.into_iter().partition(|_| {
            i += 1;

            i < my_did_count
        });

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
        surface.insert((m * 100.0) as u64, 0, byte_count);
        surface.insert(
            (m * 100.0) as u64,
            (mine.len() + not_mine.len() - 1) as u64,
            byte_count,
        );

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

    surface
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

fn draw_chart(surface: &Surface, name: &str) {
    use plotters::prelude::*;

    let cohort_size = surface.cohort_size;
    let max_bytes = surface.max_bytes;
    let filename = format!(
        "./db/surface_{name}_{}.svg",
        human_size(cohort_size as usize)
    );
    let drawing_area = SVGBackend::new(&filename, (800, 600)).into_drawing_area();

    // Draw background.
    drawing_area.fill(&WHITE).unwrap();

    let mut chart_context = ChartBuilder::on(&drawing_area)
        .margin(25)
        .x_label_area_size(50)
        .y_label_area_size(70)
        .build_cartesian_2d(0..100_u64, 0..cohort_size)
        .unwrap();

    let v = cohort_size / 100.min(cohort_size);

    // Green: 0% difference. Red: 100% difference.
    let hue = |x, y| (1.0 - (surface.sample(x, y) as f64 / max_bytes as f64)) * 0.36;
    // // TODO: Same as above, but draws the location of samples in purple for debugging.
    // let hue = |x, y| {
    //     if surface.has_point(x, y..y + v) {
    //         0.8
    //     } else {
    //         (1.0 - (surface.sample(x, y) as f64 / max_bytes as f64)) * 0.36
    //     }
    // };

    // Draw surface.
    chart_context
        .draw_series((0..cohort_size).step_by(v as usize).flat_map(|y| {
            (0..100).map(move |x| {
                Rectangle::new(
                    [(x, y), (x + 1, y + v)],
                    HSLColor(hue(x, y), 1.0, 0.5).filled(),
                )
            })
        }))
        .unwrap()
        .label(format!(
            "proof bytes: {}",
            human_size(surface.min_bytes as usize)
        ))
        .legend(|(x, y)| Rectangle::new([(x, y - 8), (x + 16, y + 8)], GREEN.filled()));

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

    // Draw color legend.
    chart_context
        .draw_series(LineSeries::new([(0_u64, 0_u64); 0], RED))
        .unwrap()
        .label(format!(
            "proof bytes: {}",
            human_size(surface.max_bytes as usize)
        ))
        .legend(|(x, y)| Rectangle::new([(x, y - 8), (x + 16, y + 8)], RED.filled()));
    if let Some((min_percent, max_percent)) = surface.percent() {
        chart_context
            .draw_series(LineSeries::new([(0_u64, 0_u64); 0], RED))
            .unwrap()
            .label(format!("percent difference: {min_percent}%"))
            .legend(|(x, y)| Rectangle::new([(x, y - 8), (x + 16, y + 8)], GREEN.filled()));
        chart_context
            .draw_series(LineSeries::new([(0_u64, 0_u64); 0], RED))
            .unwrap()
            .label(format!("percent difference: {max_percent}%"))
            .legend(|(x, y)| Rectangle::new([(x, y - 8), (x + 16, y + 8)], RED.filled()));
    }
    chart_context
        .configure_series_labels()
        .legend_area_size(20)
        .position(SeriesLabelPosition::UpperRight)
        .background_style(WHITE.mix(0.8))
        .border_style(BLACK)
        .draw()
        .unwrap();

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

    /// Stores the minimum byte size seen in all samples.
    min_bytes: u64,

    /// Stores the maximum byte size seen in all samples.
    max_bytes: u64,

    /// Stores the minimum percentage difference seen in all samples.
    min_percent: u8,

    /// Stores the maximum percentage difference seen in all samples.
    max_percent: u8,
}

impl Surface {
    fn new(cohort_size: u64) -> Self {
        Self {
            samples: BTreeMap::new(),
            cohort_size,
            max_bytes: 0,
            min_bytes: u64::MAX,
            min_percent: 255,
            max_percent: 0,
        }
    }

    /// Insert a surface height `d` at surface coordinate `[m,u]`.
    fn insert(&mut self, m: u64, u: u64, d: u64) {
        self.samples.entry(m).or_default().insert(u, d);

        self.max_bytes = self.max_bytes.max(d);
        self.min_bytes = self.min_bytes.min(d);
    }

    // /// Check if the surface has a sample within the given range.
    // ///
    // /// Only used by debug drawing.
    // fn has_point(&self, m: u64, u: std::ops::Range<u64>) -> bool {
    //     self.samples
    //         .get(&m)
    //         .map(|tree| tree.range(u).count())
    //         .map(|count| count > 0)
    //         .unwrap_or_default()
    // }

    /// Get the percentage differences (if this surface was created by [`Self::difference`]).
    fn percent(&self) -> Option<(u8, u8)> {
        if self.min_percent != 255 && self.max_percent != 0 {
            Some((self.min_percent, self.max_percent))
        } else {
            None
        }
    }

    /// Get the surface height `d` at coordinates `[m,u]`.
    fn sample(&self, m: u64, u: u64) -> u64 {
        // To make the sparse surface continuous: Sample two points along each axis then linearly
        // interpolate between them.

        fn folder(
            init: DVec3,
            upper: bool,
        ) -> impl Fn(DVec3, (&u64, &BTreeMap<u64, u64>)) -> DVec3 {
            move |acc, (m, tree)| {
                let mut range = tree.range(..);
                let (u, height) = if upper {
                    range.next_back()
                } else {
                    range.next()
                }
                .unwrap();

                let v = DVec3::new(*m as f64, *u as f64, *height as f64);

                if (init - v).mag_sq() < (init - acc).mag_sq() {
                    v
                } else {
                    acc
                }
            }
        }

        let c = self.cohort_size as f64;

        // compute default values for extent corners
        let corner = DVec3::new(0.0, 0.0, 0.0);
        let lower_left_height = self.samples.iter().fold(corner, folder(corner, false)).z;
        let corner = DVec3::new(100.0, 0.0, 0.0);
        let lower_right_height = self.samples.iter().fold(corner, folder(corner, false)).z;
        let corner = DVec3::new(0.0, c, 0.0);
        let upper_left_height = self.samples.iter().fold(corner, folder(corner, true)).z;
        let corner = DVec3::new(100.0, c, 0.0);
        let upper_right_height = self.samples.iter().fold(corner, folder(corner, true)).z;

        // Coordinates at "previous M".
        let (x0, (y0, z0), (y1, z1)) = self
            .samples
            .range(..=m)
            .next_back()
            .map(|(x0, mine)| {
                let lower_left = mine
                    .range(..=u)
                    .next_back()
                    .map(|(y0, bytes)| (*y0 as f64, *bytes as f64))
                    .unwrap_or((0.0, lower_left_height));

                (
                    *x0 as f64,
                    lower_left,
                    mine.range((u + 1)..)
                        .next()
                        .map(|(y1, bytes)| (*y1 as f64, *bytes as f64))
                        .unwrap_or((c, lower_left.1)),
                )
            })
            .unwrap_or((0.0, (0.0, lower_left_height), (c, upper_left_height)));

        // Coordinates at "next M".
        let (x1, (y2, z2), (y3, z3)) = self
            .samples
            .range((m + 1)..)
            .next()
            .map(|(x1, mine)| {
                let lower_right = mine
                    .range(..=u)
                    .next_back()
                    .map(|(y2, bytes)| (*y2 as f64, *bytes as f64))
                    .unwrap_or((0.0, lower_right_height));

                (
                    *x1 as f64,
                    lower_right,
                    mine.range((u + 1)..)
                        .next()
                        .map(|(y3, bytes)| (*y3 as f64, *bytes as f64))
                        .unwrap_or((c, lower_right.1)),
                )
            })
            .unwrap_or((100.0, (0.0, lower_right_height), (c, upper_right_height)));

        // Lower left, upper left, lower right.
        let v0 = DVec3::new(x0, y1, z1);
        let v1 = DVec3::new(x0, y0, z0);
        let v2 = DVec3::new(x1, y3, z3);
        let mut tri = Tri::new(v0, v1, v2);

        let mut barycentric = tri.barycentric(DVec2::new(m as f64, u as f64));
        if barycentric.x < 0.0 || barycentric.y < 0.0 || barycentric.z < 0.0 {
            // Upper left, upper right, lower right.
            let v0 = DVec3::new(x0, y0, z0);
            let v1 = DVec3::new(x1, y2, z2);
            let v2 = DVec3::new(x1, y3, z3);
            tri = Tri::new(v0, v1, v2);

            barycentric = tri.barycentric(DVec2::new(m as f64, u as f64));
        }

        assert!(barycentric.x >= 0.0 && barycentric.y >= 0.0 && barycentric.z >= 0.0);

        // Interpolate depth over the triangle
        let depth = tri.interpolate(barycentric);

        // Scale back to byte range.
        depth as u64
    }

    fn difference(&self, other: &Self) -> Self {
        assert_eq!(self.cohort_size, other.cohort_size);

        let mut surface = Surface::new(self.cohort_size);

        let step = self.cohort_size / 10.min(self.cohort_size);
        // TODO: Starting at u=1/10 to remove the outliers
        for u in (step..self.cohort_size).step_by(step as usize) {
            for m in (10..110).step_by(10) {
                let sample1 = self.sample(m, u);
                let sample2 = other.sample(m, u);
                let diff = sample1.abs_diff(sample2);
                surface.insert(m, u, diff);

                let percent = ((diff as f64 / sample1.max(sample2) as f64) * 100.0) as u8;
                surface.min_percent = surface.min_percent.min(percent);
                surface.max_percent = surface.max_percent.max(percent);
            }
        }

        surface
    }
}

/// Just a triangle. Used for interpolating surfaces.
#[derive(Debug)]
struct Tri {
    v0: DVec3,
    v1: DVec3,
    v2: DVec3,
}

impl Tri {
    fn new(v0: DVec3, v1: DVec3, v2: DVec3) -> Self {
        Self { v0, v1, v2 }
    }

    /// Get the barycentric coordinates for a given 2D position (screen space) that may overlap the
    /// triangle.
    ///
    /// The coordinates returned should sum (component-wise) to 1.0. If any component is negative,
    /// it means the 2D position is outside of the triangle bounds.
    fn barycentric(&self, position: DVec2) -> DVec3 {
        let x = DVec3::new(
            self.v2.x - self.v0.x,
            self.v1.x - self.v0.x,
            self.v0.x - position.x,
        );
        let y = DVec3::new(
            self.v2.y - self.v0.y,
            self.v1.y - self.v0.y,
            self.v0.y - position.y,
        );
        let u = x.cross(y);

        if u.z.abs() < 1.0 {
            return DVec3::new(-1.0, 1.0, 1.0);
        }

        DVec3::new(1.0 - (u.x + u.y) / u.z, u.y / u.z, u.x / u.z)
    }

    /// Interpolate the height at the given barycentric coordinate.
    fn interpolate(&self, barycentric: DVec3) -> f64 {
        DVec3::new(self.v0.z, self.v1.z, self.v2.z).dot(barycentric)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample() {
        let mut surface = Surface::new(100);

        surface.insert(0, 0, 2);
        surface.insert(0, 100, 25);
        surface.insert(100, 0, 3);
        surface.insert(100, 100, 35);

        assert_eq!(surface.sample(0, 0), 2);
        assert_eq!(surface.sample(0, 99), 24);
        assert_eq!(surface.sample(99, 0), 2);
        assert_eq!(surface.sample(99, 99), 34);

        assert_eq!(surface.sample(0, 50), (2 + 24) / 2);
        assert_eq!(surface.sample(50, 0), (2 + 2) / 2);
        assert_eq!(surface.sample(99, 50), (2 + 34) / 2);
        assert_eq!(surface.sample(50, 99), (24 + 34) / 2);
    }
}
