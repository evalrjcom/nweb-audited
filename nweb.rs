// nweb.rs — Rust port of the hardened nweb (v26)
// Static-file only, extension whitelist, simple GET, path safety, privilege drop on Unix.
// Compile: rustc -O nweb.rs -o nweb
// Run: ./nweb 8181 /path/to/webroot

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process;
use std::thread;

const VERSION: i32 = 26;
const BUFSIZE: usize = 65536;

const EXTENSIONS: &[(&str, &str)] = &[
    ("gif", "image/gif"),
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("png", "image/png"),
    ("ico", "image/x-icon"),
    ("zip", "application/zip"),
    ("gz", "application/gzip"),
    ("tar", "application/x-tar"),
    ("htm", "text/html"),
    ("html", "text/html"),
];

fn log_msg(msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("nweb.log")
    {
        let _ = writeln!(f, "{}", msg);
    }
}

fn send_response(stream: &mut TcpStream, status: &str, body: &str) {
    let resp = format!(
        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n{}",
        status,
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
}

fn handle_client(mut stream: TcpStream, hit: i32) {
    let mut buf = [0u8; BUFSIZE];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => {
            let body = "<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>Failed to read request.</p></body></html>\n";
            send_response(&mut stream, "403 Forbidden", body);
            log_msg(&format!("FORBIDDEN: failed to read browser request hit={}", hit));
            return;
        }
    };

    let req = String::from_utf8_lossy(&buf[..n]);
    let req_flat = req.replace(['\r', '\n'], "*");
    log_msg(&format!(" INFO: request:{}:{}", req_flat, hit));

    if !req.starts_with("GET ") && !req.starts_with("get ") {
        let body = "<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>Only simple GET supported.</p></body></html>\n";
        send_response(&mut stream, "403 Forbidden", body);
        log_msg(&format!("FORBIDDEN: Only simple GET operation supported {}", req_flat));
        return;
    }

    let url = req[4..]
        .split_whitespace()
        .next()
        .unwrap_or("/")
        .to_string();

    // Path safety: must start with /, no .., no %
    if !url.starts_with('/') || url.contains("..") || url.contains('%') {
        let body = "<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>Illegal path.</p></body></html>\n";
        send_response(&mut stream, "403 Forbidden", body);
        log_msg(&format!("FORBIDDEN: Illegal path characters or .. {}", url));
        return;
    }

    let path = if url == "/" { "/index.html".to_string() } else { url };

    let mut ftype = None;
    for (ext, mime) in EXTENSIONS {
        if path.ends_with(ext) {
            ftype = Some(*mime);
            break;
        }
    }
    if ftype.is_none() {
        let body = "<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>File type not supported.</p></body></html>\n";
        send_response(&mut stream, "403 Forbidden", body);
        log_msg(&format!("FORBIDDEN: file extension type not supported {}", path));
        return;
    }
    let ftype = ftype.unwrap();

    let file_path = path.trim_start_matches('/');
    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => {
            let body = "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\n";
            send_response(&mut stream, "404 Not Found", body);
            log_msg(&format!("NOT FOUND: failed to open file {}", file_path));
            return;
        }
    };

    log_msg(&format!(" INFO: SEND:{}:{}", file_path, hit));

    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let header = format!(
        "HTTP/1.1 200 OK\r\nServer: nweb/{}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: {}\r\n\r\n",
        VERSION, len, ftype
    );
    log_msg(&format!(" INFO: Header:{}", header.replace('\r', "").replace('\n', " ")));
    let _ = stream.write_all(header.as_bytes());

    let mut chunk = [0u8; BUFSIZE];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if stream.write_all(&chunk[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 || args.get(1).map(|s| s.as_str()) == Some("-?") {
        println!("hint: nweb Port-Number Top-Directory\t\tversion {}", VERSION);
        println!("\tnweb is a small and very safe mini web server");
        println!("\tnweb only serves files with these extensions:");
        for (e, _) in EXTENSIONS {
            print!(" {}", e);
        }
        println!("\n\tNot Supported: URLs containing \"..\" or % encoding, CGI, etc.");
        println!("\tExample: nweb 8181 /path/to/webroot");
        process::exit(0);
    }

    let port: u16 = match args[1].parse() {
        Ok(p) if (1..=60000).contains(&p) => p,
        _ => {
            eprintln!("ERROR: Invalid port number (try 1->60000)");
            process::exit(3);
        }
    };
    let topdir = &args[2];

    if topdir == "/"
        || topdir.starts_with("/etc")
        || topdir.starts_with("/bin")
        || topdir.starts_with("/lib")
        || topdir.starts_with("/tmp")
        || topdir.starts_with("/usr")
        || topdir.starts_with("/dev")
        || topdir.starts_with("/sbin")
    {
        eprintln!("ERROR: Bad top directory {}, see nweb -?", topdir);
        process::exit(3);
    }

    // Change to topdir
    if std::env::set_current_dir(topdir).is_err() {
        eprintln!("ERROR: Can't Change to directory {}", topdir);
        process::exit(4);
    }

    // Privilege drop on Unix if root (best-effort)
    #[cfg(unix)]
    {
        if unsafe { libc_geteuid() } == 0 {
            let _ = unsafe { libc_setgid(65534) };
            let _ = unsafe { libc_setuid(65534) };
        }
    }

    log_msg(&format!(" INFO: nweb starting:{}:{}", args[1], process::id()));

    let listener = TcpListener::bind(("0.0.0.0", port)).unwrap_or_else(|e| {
        eprintln!("ERROR: bind failed: {}", e);
        process::exit(3);
    });

    println!("nweb v{} listening on port {} (serving from {})", VERSION, port, topdir);

    let mut hit = 1i32;
    for stream in listener.incoming() {
        if let Ok(s) = stream {
            let h = hit;
            hit += 1;
            thread::spawn(move || handle_client(s, h));
        }
    }
}

// Minimal Unix privilege helpers
#[cfg(unix)]
fn libc_geteuid() -> u32 {
    unsafe { libc::geteuid() }
}
#[cfg(unix)]
fn libc_setuid(uid: u32) -> i32 {
    unsafe { libc::setuid(uid) }
}
#[cfg(unix)]
fn libc_setgid(gid: u32) -> i32 {
    unsafe { libc::setgid(gid) }
}

#[cfg(unix)]
mod libc {
    use std::os::raw::c_int;
    extern "C" {
        pub fn geteuid() -> u32;
        pub fn setuid(uid: u32) -> c_int;
        pub fn setgid(gid: u32) -> c_int;
    }
}
