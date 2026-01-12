use std::{
    fs,
    sync::{
        atomic::AtomicU8,
        mpsc, Arc, Mutex,
    },
    thread,
    time,
};

use chrono::{SecondsFormat, Utc};
use cust::{
    context::Context,
    device::Device,
    error::CudaResult,
    module::Module,
    stream::Stream,
    memory::{DeviceBuffer, CopyDestination},
};
use rand::RngCore;
use rayon::prelude::*;
use regex::Regex;

use crate::{handler::handle_keypair, Args};

#[derive(Clone, Copy)]
pub struct GpuOptions {
    pub device_idx: usize,
    pub threads: usize,
    pub local_work_size: Option<u32>, // CUDA uses u32 for block size
    pub global_work_size: Option<u32>, // CUDA uses u32 for grid size
}

pub struct Gpu {
    _context: Context, // Context needs to be held by the Gpu struct to keep it alive
    _device: Device,
    module: Module,
    stream: Stream,
    results_buffer: DeviceBuffer<u8>,
    keys_buffer: DeviceBuffer<u8>,
    threads: usize,
}

impl Gpu {
    pub fn new(opts: GpuOptions) -> CudaResult<Gpu> {
        cust::init(cust::CudaFlags::empty())?;

        // Changed: Device::get -> Device::get_device
        let device = Device::get_device(opts.device_idx as u32)?;
        
        // Changed: Context::new now takes only device
        let _context = Context::new(device)?;
        let stream = Stream::new(cust::stream::StreamFlags::NON_BLOCKING, None)?;

        eprintln!("Initializing CUDA GPU {} {}", device.name()?, device.total_memory()?);

        // Load PTX modules from embedded bytes
        let ptx_bytes = include_bytes!(env!("PTX_PATH_KERNELS"));
        
        // Convert PTX bytes to string for Module::from_ptx
        let ptx_string = String::from_utf8_lossy(ptx_bytes);

        // Changed: Module::load_from_bytes -> Module::from_ptx (expects &str)
        let module = Module::from_ptx(ptx_string, &[])?;

        // Changed: DeviceBuffer::new -> DeviceBuffer::zeroed
        let results_buffer = DeviceBuffer::zeroed(32 * opts.threads)?;
        let keys_buffer = DeviceBuffer::zeroed(32 * opts.threads)?;

        Ok(Gpu {
            _context,
            _device: device,
            module,
            stream,
            results_buffer,
            keys_buffer,
            threads: opts.threads,
        })
    }

    pub fn compute(&mut self) -> CudaResult<()> {
        let block_size = self.threads as u32;
        let grid_size = 1;

        unsafe {
            // Get the function from the module
            let function = self.module.get_function("generate_pubkey")?;
            
            let results_ptr = self.results_buffer.as_device_ptr();
            let keys_ptr = self.keys_buffer.as_device_ptr();
            
            // The macro needs identifiers, so bind stream to a local variable
            let stream = &self.stream;
            
            // Launch using the macro with local identifiers
            cust::launch!(function<<<grid_size, block_size, 0, stream>>>(
                results_ptr.as_raw(),
                keys_ptr.as_raw()
            ))?;
        }
        Ok(())
    }

    pub fn read_keys(&mut self, results: &mut [u8]) -> CudaResult<()> {
        // Changed: Added CopyDestination import for copy_to method
        self.results_buffer.copy_to(results)?;
        self.stream.synchronize()?; // Synchronize to ensure data is transferred
        Ok(())
    }

    pub fn write_seeds(&mut self, keys: &[u8]) -> CudaResult<()> {
        // Changed: Added CopyDestination import for copy_from method
        self.keys_buffer.copy_from(keys)?;
        Ok(())
    }
}

pub fn run_cuda(
    args: &Args,
    regexes: &[String],
    compiled_regexes: Vec<Regex>,
    csv_file: &Option<Mutex<fs::File>>,
) -> CudaResult<()> {
    let pubkeys = Arc::new(Mutex::new(vec![0; 32 * args.threads]));
    let next_seeds = Arc::new(Mutex::new(vec![0; 32 * args.threads]));
    let current_seeds = Arc::new(Mutex::new(vec![0; 32 * args.threads]));

    let mut gpu = Gpu::new(GpuOptions {
        device_idx: args.device_idx,
        threads: args.threads,
        local_work_size: args.local_work_size.map(|x| x as u32),
        global_work_size: args.global_work_size.map(|x| x as u32),
    })?;

    let (start_write_compute_tx, start_write_compute_rx) = mpsc::channel::<()>();
    let (seeds_wrote_tx, seeds_wrote_rx) = mpsc::channel::<()>();
    let (start_keys_read_tx, start_keys_read_rx) = mpsc::channel::<()>();
    let (keys_read_tx, pubkeys_read_rx) = mpsc::channel::<()>();

    let _gpu_thread = {
        let seeds = next_seeds.clone();
        let pubkeys = pubkeys.clone();
        thread::spawn(move || {
            loop {
                keys_read_tx.send(()).unwrap();
                start_write_compute_rx.recv().unwrap();

                gpu.write_seeds(&seeds.lock().unwrap()).unwrap();
                seeds_wrote_tx.send(()).unwrap();

                gpu.compute().unwrap();

                start_keys_read_rx.recv().unwrap();
                gpu.read_keys(&mut pubkeys.lock().unwrap()).unwrap();
            }
        })
    };

    let max_leading_zeros: Vec<AtomicU8> = (0..(compiled_regexes.len()))
        .map(|_| AtomicU8::new(0))
        .collect();
    let mut first_run = true;

    gen_random_seeds(&mut next_seeds.lock().unwrap());

    let mut start = time::Instant::now();
    let mut iters = 0u64;

    loop {
        start_write_compute_tx.send(()).unwrap();

        pubkeys_read_rx.recv().unwrap();
        if !first_run {
            handle_keypairs(
                &current_seeds.lock().unwrap(),
                &pubkeys.lock().unwrap(),
                regexes,
                &compiled_regexes,
                &max_leading_zeros,
                csv_file,
            );
        }
        start_keys_read_tx.send(()).unwrap();

        gen_random_seeds(&mut current_seeds.lock().unwrap());
        std::mem::swap(
            &mut *current_seeds.lock().unwrap(),
            &mut *next_seeds.lock().unwrap(),
        );
        seeds_wrote_rx.recv().unwrap();

        iters += args.threads as u64;
        let elapsed = start.elapsed();
        if !first_run && elapsed.as_secs() >= args.log_interval {
            let hashrate = iters as f64 / elapsed.as_secs_f64() / 1_000_000.0;
            eprintln!(
                "{} Hashrate: {:.2} MH/s",
                Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                hashrate
            );
            start = time::Instant::now();
            iters = 0;
        }
        if first_run {
            first_run = false;
        }
    }
}

fn handle_keypairs(
    seeds: &[u8],
    pubkeys: &[u8],
    regex_sources: &[String],
    regexes: &[Regex],
    max_leading_zeros: &[AtomicU8],
    csv_file: &Option<Mutex<fs::File>>,
) {
    pubkeys
        .par_chunks_exact(32)
        .zip(seeds.par_chunks_exact(32))
        .for_each(|(pk, seed)| {
            handle_keypair(
                seed,
                pk,
                regex_sources,
                regexes,
                max_leading_zeros,
                csv_file,
            )
        });
}

fn gen_random_seeds(seeds: &mut [u8]) {
    seeds.par_chunks_exact_mut(128 * 1024).for_each(|seed| {
        rand::thread_rng().fill_bytes(seed);
    })
}
