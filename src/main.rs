use std::fs::File;
use std::io::{BufReader, BufRead, Read, Write};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use walkdir::WalkDir;
use colored::{self, Colorize};
use clap::{Arg, Command};

enum FileStatus {
    Ok,
    Mismatch,
    NotFound,
    Extra
}

fn main() {
    let cli = cli();
    let matches = cli.get_matches();
    match matches.subcommand() {
        Some(("snapshot", snapshot_matches)) => {
            let directory = snapshot_matches.get_one::<String>("directory").unwrap();
            let reference_file = snapshot_matches.get_one::<String>("reference_file").unwrap();
            snapshot(directory, reference_file);
        },
        Some(("validate", validate_matches)) => {
            let directory = validate_matches.get_one::<String>("directory").unwrap();
            let reference_file = validate_matches.get_one::<String>("reference_file").unwrap();
            validate(directory, reference_file);
        },
        _ => {
            println!("Unknown command");
            println!("Usage: snapshot <snapshot|validate> [options]");
        }
    }
}

fn cli() -> Command {
    Command::new("snapshot")
        .about("Create a snapshot of the directory")
        .subcommand(
            Command::new("snapshot")
                .about("Create a snapshot of the directory")
                .arg(Arg::new("directory")
                    .required(true)
                    .long("directory")
                    .short('d')
                )
                .arg(Arg::new("reference_file")
                    .long("reference")
                    .short('r')
                )
        )
        .subcommand(
            Command::new("verify")
                .about("Verify the directory")
                .arg(Arg::new("directory")
                    .required(true)
                    .long("directory")
                    .short('d')
                )
                .arg(Arg::new("reference_file")
                    .long("reference")
                    .short('r')
                )
        )
        
}

fn snapshot(in_dir: &String, ref_file: &String) {
    // scan the directory
    // for each file recursively
    // calculate the sha256
    // store the result in a result.txt file

    println!("[Snapshot] Scanning the directory: {}", in_dir);

    let mut output_file = File::create(ref_file).unwrap();

    for entry in WalkDir::new(in_dir) {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            // remove root_path from the path
            let path = entry.path().display().to_string();
            let relative_path = path.replacen(in_dir, "", 1);
            let hash = calculate_sha256(path.as_str())
                .unwrap_or("".to_string());
            if hash.len() > 0 {
                match output_file.write_all(format!("{}:{}\n", relative_path, hash).as_bytes()) {
                    Ok(_) => (),
                    Err(e) => println!("Error: {}", e),
                }
            }
            println!("[Snapshot] [{}]: {}", "SCAN".green(), entry.path().display());
        }
    }
    println!("[Snapshot] Store the result in {}", ref_file);
    println!("[Snapshot] Done");
}

fn validate(target_dir : &String, ref_file : &String) {
    let output_file = File::open(ref_file).unwrap();
    let mut ref_map = HashMap::new();

    // read the result.txt file line by line
    for line in BufReader::new(output_file).lines() {
        let line = line.unwrap();
        let parts: Vec<&str> = line.split(":").collect();
        let file = parts[0].to_string();
        let hash = parts[1].to_string();
        ref_map.insert(file, hash);
    }

    let mut result_map = HashMap::new();

    for entry in WalkDir::new(target_dir) {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            // remove root_path from the path
            let path = entry.path().display().to_string();
            let relative_path = path.replacen(target_dir, "", 1).to_string();
            if !ref_map.contains_key(&relative_path) {
                result_map.insert(relative_path.to_string(), FileStatus::Extra);
                print!("[Validate] [{}]: {}\n", "EXTRA".yellow(), relative_path);
                continue;
            }

            let ref_hash = ref_map.get(&relative_path).unwrap();
            let cur_hash = calculate_sha256(path.as_str())
                .unwrap_or("".to_string());

            if ref_hash == &cur_hash {
                result_map.insert(relative_path.to_string(), FileStatus::Ok);
                print!("[Validate] [{}]: {}\n", "OK".green(), relative_path);
            } else {
                result_map.insert(relative_path.to_string(), FileStatus::Mismatch);
                print!("[Validate] [{}]: {}\n", "MISMATCH".red(), relative_path);
            }
            ref_map.remove(&relative_path);
        }
    }

    // left over files in refMap are not found
    for (key, _) in ref_map.iter() {
        result_map.insert(key.to_string(), FileStatus::NotFound);
        print!("[Validate] [{}]: {}\n", "NOT FOUND".red(), key);
    }
}

fn calculate_sha256(file_path: &str) -> Option<String> {
    let file = File::open(file_path).ok()?;
    let mut reader = BufReader::new(file);

    let mut sha256 = Sha256::new();
    let mut buffer = [0; 1024];

    loop {
        let n = reader.read(&mut buffer).unwrap_or(0);
        if n == 0 {
            break;
        }
        sha256.update(&buffer[..n]);
    }

    let sha256_hash = sha256.finalize();

    let mut result = String::new();
    for byte in sha256_hash {
        result.push_str(&format!("{:02x}", byte));
    }

    Some(result)
}