mod config;

#[macro_use]
extern crate clap;
#[macro_use]
extern crate pest;
extern crate serde_json;

use clap::{App};
use glob;
use std::path::{Path, PathBuf};
use crate::config::parse_config;
use std::collections::{HashMap, HashSet};
use std::process::{exit, Command};
use crc::{Crc, CRC_32_CKSUM};
use std::iter::FromIterator;
use std::fs::{File, OpenOptions};
use std::io::{Write, Read, BufWriter};
use humantime::{format_duration};
use std::time::{SystemTime, Duration};

use unrealscriptplus::parser::{parse_file, ParsingError, ProgramErrorSeverity, ProgramError};
use pest::error::{ErrorVariant, LineColLocation};

struct UccError {
    path: String,
    severity: ProgramErrorSeverity,
    line: Option<usize>,
    message: String
}

impl UccError {
    pub fn new_from_program_error(path: &str, error: ProgramError) -> UccError {
        UccError {
            path: String::from(path),
            severity: error.severity,
            line: error.span.line,
            message: error.message,
        }
    }

    pub fn new_from_parsing_error(path: &str, error: ParsingError) -> UccError {
        let (line, message) = match error {
            ParsingError::IoError(error) => {
                (None, error.to_string())
            }
            ParsingError::EncodingError(message) => {
                (None, message)
            }
            ParsingError::PestError(error) => {
                let line = match error.line_col {
                    LineColLocation::Pos((line, _col)) => line,
                    LineColLocation::Span((line, _col), _) => line
                };
                match error.variant {
                    ErrorVariant::CustomError { message } => {
                        (Some(line), message)
                    }
                    ErrorVariant::ParsingError { positives, negatives: _ } => {
                        let positives: Vec<String> = positives.into_iter().map(|r| format!("{:?}", r).to_string()).collect();
                        let positives = positives.join(", ");
                        let message = format!("Expected one of [{}]", positives);
                        (Some(line), message)
                    }
                }
            }
        };
        UccError {
            path: String::from(path),
            severity: ProgramErrorSeverity::Error,
            line,
            message
        }
    }
}

impl ToString for UccError {
    fn to_string(&self) -> String {
        format!("{:?}: {} ({}) : {}", self.severity, self.path, self.line.unwrap_or(0), self.message)
    }
}

#[derive(PartialEq, Eq, Copy, Clone)]
enum PackageStatus {
    Ok,
    SourceMismatch,
    Cascade
}

impl ToString for PackageStatus {
    fn to_string(&self) -> String {
        String::from(match &self {
            PackageStatus::Ok => "Up-to-date",
            PackageStatus::SourceMismatch => "Out-of-date",
            PackageStatus::Cascade => "Dependency out-of-date",
        })
    }
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let args = App::from_yaml(yaml).get_matches();
    let mod_name = args.value_of("mod").unwrap();

    // root directory
    let dir_string = args.value_of("dir").unwrap_or(".");
    let mut dir = Path::new(dir_string)
        .canonicalize()
        .expect(format!("directory {:?} could not be made canonical", dir_string).as_str());
    let d = dir.to_str().unwrap().to_string();
    dir = PathBuf::from(Path::new(d.trim_start_matches(r"\\?\")));
    assert!(dir.exists(), "error: {:?} is not a directory", dir);

    // system directory
    let sys_path = dir.join("System");
    assert!(sys_path.exists(), "error: could not resolve System directory");

    // mod directory
    let mod_path = dir.join(args.value_of("mod").unwrap());
    assert!(mod_path.exists(), "error: could not resolve mod directory");

    // mod system directory
    let mod_sys_path = mod_path.join("System");
    assert!(mod_sys_path.exists(), "error: could not resolve mod system directory");

    // read the default config
    let default_config_path = mod_sys_path.join("Default.ini");
    assert!(default_config_path.is_file(), "error: could not resolve mod default config file");
    let mut default_packages = vec![];
    let config = parse_config(default_config_path.as_path()).unwrap();
    if let Some(section) = config.section("Editor.EditorEngine") {
        for package in section.values("+EditPackages") {
            default_packages.push(package)
        }
    }

    // read the paths and make sure that there are no ambiguous file names
    let config_path = mod_sys_path.join(format!("{}.ini", mod_name).as_str());
    let mut paths = vec![];
    if config_path.is_file() {
        let config = parse_config(config_path.as_path()).unwrap();
        if let Some(section) = config.section("Core.System") {
            for path in section.values("Paths") {
                paths.push(path)
            }
        }
    }

    let mut filename_paths = HashMap::new();
    for path in &paths {
        let pathname = mod_path.join(path);
        for paths in glob::glob(pathname.to_str().unwrap()).expect("failed to read glob pattern") {
            for path in paths {
                let basename = path.file_name().unwrap().to_str().unwrap();
                if !filename_paths.contains_key(basename) {
                    filename_paths.insert(basename.to_string(), vec![]);
                }
                filename_paths.get_mut(basename.to_string().as_str()).unwrap().push(path)
            }
        }
    }

    let mut did_error = false;

    for (filename, paths) in &filename_paths {
        if paths.len() > 1 {
            did_error = true;
            println!("ERROR: Ambiguous file resolution for {:?}", filename);
            println!("    Files with that file name were found in the following paths:");
            for path in paths {
                println!("        {:?}", path);
            }
            println!("This is likely the result of saving a file to the wrong folder.");
        }
    }

    if did_error {
        exit(1);
    }

    // delete ALL mod packages from the root system folder
    for package in &default_packages {
        let package_path = sys_path.join(format!("{}.u", package).as_str());
        if package_path.is_file() {
            assert!(
                std::fs::remove_file(package_path).is_ok(),
                "error: failed to remove {:?} (is the client, server, or editor running?)",
                package
            )
        }
    }

    // mod config path
    let config_path = mod_sys_path.join(format!("{}.ini", mod_name));

    if args.is_present("clean") && config_path.is_file() {
        // clean build deletes the existing mod config
        std::fs::remove_file(config_path.as_path()).expect("failed to remove config file!")
    }

    // get packages from generated INI?
    let packages = default_packages.clone();

    let mut package_statuses: HashMap<String, PackageStatus> = HashMap::new();
    let mut changed_packages = HashSet::new();
    let mut package_crcs: HashMap<String, u32> = HashMap::new();

    let manifest_path = mod_path.join(".make");

    // if we are doing a clean build, remove the manifest file
    if args.is_present("clean") && manifest_path.is_file() {
        std::fs::remove_file(manifest_path.as_path()).expect("could not delete manifest file");
    }

    // store the old CRCs before we overwrite them
    let mut old_package_crcs: HashMap<String, u32> = HashMap::new();

    if let Ok(contents) = std::fs::read_to_string(manifest_path.as_path()) {
        package_crcs = serde_json::from_str(contents.as_str()).expect("malformed JSON in manifest file");
        for (key, value) in package_crcs.iter() {
            old_package_crcs.insert(key.clone(), *value);
        }
    }

    let mut package_build_count = 0usize;
    for package in packages.iter() {
        let sys_package_path = sys_path.join(format!("{}.ini", package));
        if sys_package_path.is_file() {
            continue
        }
        let mut package_status = PackageStatus::Ok;
        if !args.is_present("no-cascade") && package_build_count > 0 {
            package_status = PackageStatus::Cascade;
        }
        let package_src_dir = dir.join(package.clone()).join("Classes");
        let crc = Crc::<u32>::new(&CRC_32_CKSUM);
        let mut digest = crc.digest();

        // NOTE: I would prefer to use glob here to be more succinct, but Windows long-paths do not
        // work with the glob module.
        for entry in std::fs::read_dir(package_src_dir).unwrap() {
            let path = entry.unwrap().path();
            if let Some(extension) = path.extension() {
                if extension == "uc" {
                    let bytes = std::fs::read(path).unwrap();
                    digest.update(&bytes[..]);
                }
            }
        }
        let package_crc = digest.finalize();

        let saved_package_crc = package_crcs.get(package.as_str());
        if saved_package_crc.is_none() || saved_package_crc.unwrap() != &package_crc {
            changed_packages.insert(format!("{}.u", package.as_str()));
            package_status = PackageStatus::SourceMismatch;
        }

        package_statuses.insert(format!("{}.u", package), package_status);
        package_crcs.insert(package.clone(), package_crc);

        if package_status != PackageStatus::Ok {
            package_build_count += 1;
        }
    }

    let up_to_date_packages: HashSet<String> = HashSet::from_iter(package_statuses.iter()
        .filter(|(_, status)| **status == PackageStatus::Ok)
        .map(|(package, _)| package.clone())
        .collect::<Vec<String>>());
    let packages_to_compile: HashSet<String> = HashSet::from_iter(package_statuses.iter()
        .filter(|(_, status)| **status != PackageStatus::Ok)
        .map(|(package, _)| package.clone())
        .collect::<Vec<String>>());
    let mut compiled_packages: HashSet<String> = HashSet::new();

    let ucc_log_path = sys_path.join("ucc.log");

    if packages_to_compile.is_empty() {
        println!("No packages were marked for compilation (no changes detected)");
        let mut file = OpenOptions::new().write(true).open(&ucc_log_path).expect("could not write UCC.log");
        write!(file, "Warning: No packages were marked for compilation").unwrap();
        exit(0);
    }

    let mut ucc_log_contents: Vec<u8> = Vec::new();

    let read_ucc_log_contents = || -> Vec<u8> {
        let mut contents = Vec::new();
        if let Ok(mut file) = File::open(&ucc_log_path) {
            file.read_to_end(&mut contents).unwrap();
        }
        contents
    };

    if !args.is_present("no-usp") {
        println!("Scanning files with UnrealScriptPlus...");

        let mut manifest_mtime = None;
        if let Ok(metadata) = std::fs::metadata(&manifest_path) {
            if let Ok(modified) = metadata.modified() {
                manifest_mtime = Some(modified)
            }
        }

        // Build a list of the files to be scanned with USP
        let mut paths = Vec::new();
        for package in package_statuses
            .iter()
            .filter(|(_, status)| **status == PackageStatus::SourceMismatch)
            .map(|(package, _)| package.clone()) {
            let (package_name, _) = package.split_at(package.len() - 2);
            let package_src_dir = dir.join(package_name).join("Classes");
            for entry in std::fs::read_dir(&package_src_dir).unwrap() {
                let path = entry.unwrap().path();
                match path.extension() {
                    None => continue,
                    Some(extension) => {
                        if extension != "uc" {
                            continue
                        }
                    }
                }
                if let Ok(metadata) = std::fs::metadata(&path) {
                    if metadata.modified().unwrap() >= manifest_mtime.unwrap_or(SystemTime::UNIX_EPOCH) {
                        paths.push(path)
                    }
                }
            }
        }

        let usp_start_time = SystemTime::now();

        // Process all the relevant files using a thread pool.
        let (tx, rx) = std::sync::mpsc::channel();
        let pool  = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();

        for path in &paths {
            let path = path.clone();
            let tx = tx.clone();
            pool.spawn(move|| {
                let result = parse_file(path.to_str().unwrap());
                match result {
                    Ok(result) => {
                        for error in result.errors {
                            tx.send(UccError::new_from_program_error(path.to_str().unwrap(), error)).unwrap()
                        }
                    }
                    Err(error) => {
                        tx.send(UccError::new_from_parsing_error(path.to_str().unwrap(), error)).unwrap()
                    }
                }
            });
        }
        // Drop the sender.
        drop(tx);

        // Iterate over errors emitted from the worker threads.
        let errors: Vec<UccError> = rx.into_iter().collect();

        // Write all errors that were encountered out to the UCC log
        if let Ok(mut ucc_log_file) = std::fs::OpenOptions::new()
            .write(true)
            .append(true)
            .open(&ucc_log_path) {
            // Print the errors to the console and to the UCC file
            for error in &errors {
                let error_string = error.to_string();
                println!("{}", error_string);
                ucc_log_file.write(format!("{}\n", error_string).as_bytes()).unwrap();
            }
        }

        // Display the time it took to process all the files with USP.
        if !paths.is_empty() {
            let duration = usp_start_time.elapsed().unwrap_or(Duration::new(0, 0));
            println!("Processed {} files(s) in {}", paths.len(), format_duration(duration));
        }

        // If any of the errors are fatal, exit the process.
        let should_exit = errors.iter().any(|e| e.severity == ProgramErrorSeverity::Error);
        if should_exit {
            exit(1)
        }

        ucc_log_contents = read_ucc_log_contents();
    }

    if args.is_present("no-ucc") {
        println!("Skipping compilation because -skip_ucc was passed as an argument to the program");
        exit(0);
    }

    fn print_header(header: &str) {
        let mut output: String = std::iter::repeat("-").take(70).collect::<String>();
        let i = (output.len() / 2) - (header.len() / 2);
        output.replace_range(i..i+header.len(), header);
        println!("{}", output);
    }

    print_header(format!("Build started for mod: {}", mod_name).as_str());

    let sorted_package_statuses: Vec<(String, PackageStatus)> = packages
        .iter()
        .map(|p| (p.clone(), package_statuses.get(format!("{}.u", p).as_str()).unwrap_or(&PackageStatus::Ok).clone()))
        .filter(|(_, status)| *status != PackageStatus::Ok)
        .collect();

    for (package, status) in sorted_package_statuses {
        println!("{}", format!("{}: {}", package, status.to_string()).as_str());
    }

    // delete packages marked for compiling from both the root AND mod system folder
    let sys_paths = vec![&sys_path, &mod_sys_path];
    for package in &packages_to_compile {
        for sys_path in &sys_paths {
            let package_path = sys_path.join(package);
            if package_path.is_file() {
                if std::fs::remove_file(package_path).is_err() {
                    println!("error: failed to remove '{}' (is the client, server, or editor running?", package);
                    exit(1);
                }
            }
        }
    }

    // Remove the UNC path specifier from the system path.
    std::env::set_current_dir(&sys_path).unwrap();

    let ucc_path = PathBuf::from("ucc.exe");

    if !ucc_path.is_file() {
        println!("error: compiler executable not found (do you have the SDK installed?)");
        exit(1)
    }

    // run ucc make
    {
        let mut ucc_command = Command::new(&ucc_path);
        ucc_command.arg("make");
        ucc_command.arg(format!("-mod={}", mod_name));
        if args.is_present("debug") {
            ucc_command.arg("-debug");
        }
        if args.is_present("quiet") {
            ucc_command.arg("-silentbuild");
        }
        let mut output = ucc_command.spawn().expect("ucc command failed to spawn");
        output.wait().unwrap();
    }

    // store contents of ucc.log before it's overwritten
    let mut new_ucc_log_contents = read_ucc_log_contents();
    ucc_log_contents.extend(String::from("\n").as_bytes());
    ucc_log_contents.append(&mut new_ucc_log_contents);

    // move compiled packages to mod directory
    for entry in std::fs::read_dir(&sys_path).unwrap() {
        let path = entry.unwrap().path();
        let file_name = path.file_name().unwrap().to_str().unwrap();
        if packages_to_compile.contains(file_name) {
            std::fs::copy(&path, mod_sys_path.join(path.file_name().unwrap())).unwrap();
            std::fs::remove_file(&path).unwrap();
            compiled_packages.insert(String::from(path.file_name().unwrap().to_str().unwrap()));
        }
    }

    // run ucc dumpint on all compiled & changed packages, if specified
    if args.is_present("dumpint") {
        println!("Running ucc dumpint (note: output may be garbled due to ucc writing to stdout in parallel)");
        let mut threads = vec![];
        for package in compiled_packages.intersection(&changed_packages) {
            let mut command = Command::new(&ucc_path);
            command.arg("dumpint")
                .arg(package)
                .arg(format!("-mod={}", mod_name));
            threads.push(std::thread::spawn(move|| {
                let mut result = command.spawn().unwrap();
                result.wait().unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        // move localization files to mod directory
        for entry in std::fs::read_dir(&sys_path).unwrap() {
            let path = entry.unwrap().path();
            if let Some(extension) = path.extension() {
                if extension == "int" {
                    let mut package_path = path.clone();
                    package_path.set_extension("u");
                    let file_name = package_path.file_name().unwrap().to_str().unwrap();
                    if packages_to_compile.contains(file_name) {
                        std::fs::copy(&path, mod_sys_path.join(path.file_name().unwrap())).unwrap();
                        std::fs::remove_file(&path).unwrap();
                    }
                }
            }
        }
    }

    // rewrite ucc.log to be the contents of the original ucc make command (so that WOTgreal can parse it correctly)
    if let Ok(mut file) = File::create(&ucc_log_path) {
        file.write(&ucc_log_contents[..]).unwrap();
    }

    for package_name in &compiled_packages {
        let package_name = package_name.strip_suffix(".u").unwrap();
        old_package_crcs.insert(package_name.to_string(), *package_crcs.get(package_name).unwrap());
    }

    // delete the CRCs of changed packages that failed to compile
    let failed_packages: HashSet<String> = HashSet::from_iter(packages_to_compile.difference(&compiled_packages).cloned().into_iter());
    for package_name in failed_packages.intersection(&changed_packages) {
        let package_name = package_name.strip_suffix(".u").unwrap();
        old_package_crcs.remove(package_name).unwrap();
    }

    // write package manifest
    let manifest_file = File::create(manifest_path).unwrap();
    let mut writer = BufWriter::new(manifest_file);
    serde_json::to_writer(&mut writer, &old_package_crcs).expect("could not write mod make manifest");
    writer.flush().unwrap();

    print_header(format!("Build: {} succeeded, {} failed, {} skipped, {} up-to-date",
                         compiled_packages.len(),
                         packages_to_compile.len() - compiled_packages.len(),
                         0,
                         up_to_date_packages.len()
                        ).as_str());

    // exit with an error code if the build fails
    let did_build_succeed = compiled_packages.len() == packages_to_compile.len();
    if !did_build_succeed {
        exit(1);
    }
}