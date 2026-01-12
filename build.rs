use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let kernel_dir = PathBuf::from("kernel");

    let cuda_files: Vec<PathBuf> = fs::read_dir(&kernel_dir)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            if path.extension().map_or(false, |ext| ext == "cu") {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    if cuda_files.is_empty() {
        println!("cargo:warning=No CUDA .cu files found in kernel directory. Skipping CUDA compilation.");
        return;
    }

    if let Err(e) = Command::new("nvcc").arg("--version").output() {
        eprintln!("nvcc is not found or not in PATH: {:?}", e);
        eprintln!("Please ensure CUDA Toolkit is installed and nvcc is accessible.");
        panic!("nvcc not found");
    }

    // Compile all .cu files into a single PTX file
    let combined_ptx_file = out_dir.join("kernels.ptx");

    // Tell Cargo to re-run this build script if any CUDA file changes.
    for cuda_file in &cuda_files {
        println!("cargo:rerun-if-changed={}", cuda_file.display());
    }

    let mut command = Command::new("nvcc");
    for cuda_file in cuda_files {
        command.arg(cuda_file.to_str().unwrap());
    }
    command
        .arg("-ptx") // Compile to PTX
        .arg("-arch=sm_35") // Specify a minimum CUDA architecture (adjust as needed)
        .arg("-o")
        .arg(&combined_ptx_file);

    let output = command.output().expect("Failed to execute nvcc");

    if !output.status.success() {
        eprintln!(
            "Failed to compile combined CUDA kernels: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        panic!("nvcc compilation failed");
    } else {
        println!("Compiled combined CUDA kernels to {}", combined_ptx_file.display());
        println!(
            "cargo:rustc-env=PTX_PATH_KERNELS={}",
            combined_ptx_file.display()
        );
    }
}