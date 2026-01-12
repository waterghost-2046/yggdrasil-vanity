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

    // Tell Cargo to re-run this build script if any CUDA file changes.
    for cuda_file in &cuda_files {
        println!("cargo:rerun-if-changed={}", cuda_file.display());
    }

    // Option 1: Combine all .cu files into one, then compile
    let combined_cu_file = out_dir.join("combined_kernels.cu");
    let mut combined_content = String::new();
    
    for cuda_file in &cuda_files {
        let content = fs::read_to_string(cuda_file)
            .expect(&format!("Failed to read {}", cuda_file.display()));
        combined_content.push_str(&format!("// From: {}\n", cuda_file.display()));
        combined_content.push_str(&content);
        combined_content.push_str("\n\n");
    }
    
    fs::write(&combined_cu_file, combined_content)
        .expect("Failed to write combined CUDA file");

    // Now compile the single combined file
    let combined_ptx_file = out_dir.join("kernels.ptx");
    
    let mut command = Command::new("nvcc");
    command
        .arg(combined_cu_file.to_str().unwrap())
        .arg("-ptx") // Compile to PTX
        .arg("-o")
        .arg(&combined_ptx_file)
        .arg("-Wno-deprecated-gpu-targets"); // Suppress the warning

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
