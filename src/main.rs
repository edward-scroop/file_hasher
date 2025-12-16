use std::{
    env,
    fs::File,
    io::{self, BufReader, Read},
    process,
};

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut counter = 2;

    if args.len() <= 2 {
        eprintln!("Error no file arguments passed to program.");
        process::exit(1);
    }

    while counter < args.len() {
        let file_handler = match File::open(&args[counter]) {
            Err(e) => {
                eprintln!("Error loading file {}: {}", args[counter], e);
                process::exit(1);
            }
            Ok(f) => f,
        };

        match hash_file(file_handler) {
            Err(e) => {
                eprintln!("Error hashing file {}: {}", args[counter], e);
                process::exit(1);
            }
            Ok(_) => (),
        };

        counter += 1;
    }
}

const FILE_BUFFER: usize = 512 * /*1MiB*/(1024 * 1024);
fn hash_file(file_handle: File) -> io::Result<()> {
    let mut reader = BufReader::with_capacity(FILE_BUFFER, file_handle);
    let mut buffer = [0_u8; 512];
    let mut bytes_read: usize;
    let mut blocks_processed = false;

    while !blocks_processed {
        bytes_read = reader.read(&mut buffer)?;
        print!("{}", str::from_utf8(&buffer[0..bytes_read]).unwrap());

        if bytes_read < buffer.len() {
            blocks_processed = true;
        }
        use std::{thread, time};
        thread::sleep(time::Duration::from_millis(2000));
    }

    return Ok(());
}
