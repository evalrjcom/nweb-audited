// nweb25.rs — Rust port of Nigel Griffiths' nweb25.c
// Static-file only, extension whitelist, simple GET.
// Unix: chroot + background. Windows: foreground, no chroot.
// No external crates. Compile: rustc -O nweb25.rs -o nweb

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process;
use std::thread;

const VERSION: i32 = 25;
const BUFSIZE: usize = 65536;

const EXTENSIONS: &[(&str, &str)] = &[
    ("gif", "image/gif"),
    ("jpg", "image/jpg"),
    ("jpeg", "image/jpeg"),
    ("png", "image/png"),
    ("ico", "image/ico"),
    ("zip", "image/zip"),
    ("gz", "image/gz"),
    ("tar", "image/tar"),
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

fn send_error(stream: &mut TcpStream, code: &str, body: &str, log: &str) {
    let resp = format!(
        "HTTP/1.1 {}\nContent-Length: {}\nConnection: close\nContent-Type: text/html\n\n{}",
        code,
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
    log_msg(log);
    process::exit(3);
}

fn handle_client(mut stream: TcpStream, hit: i32) {
    let mut buf = [0u8; BUFSIZE];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => {
            send_error(
                &mut stream,
                "403 Forbidden",
                "<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>Failed to read request.</p></body></html>\n",
                &format!("FORBIDDEN: failed to read browser request hit={}", hit),
            );
            return;
        }
    };

    let req = String::from_utf8_lossy(&buf[..n]).replace(['\r', '\n'], "*");
    log_msg(&format!(" INFO: request:{}:{}", req, hit));

    if !req.starts_with("GET ") && !req.starts_with("get ") {
        send_error(
            &mut stream,
            "403 Forbidden",
            "<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>Only simple GET supported.</p></body></html>\n",
            &format!("FORBIDDEN: Only simple GET operation supported {}", req),
        );
        return;
    }

    let url = req[4..]
        .split_whitespace()
        .next()
        .unwrap_or("/")
        .to_string();

    if url.contains("..") {
        send_error(
            &mut stream,
            "403 Forbidden",
            "<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>Parent directory (..) not supported.</p></body></html>\n",
            &format!("FORBIDDEN: Parent directory (..) path names not supported {}", url),
        );
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
        send_error(
            &mut stream,
            "403 Forbidden",
            "<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>File type not supported.</p></body></html>\n",
            &format!("FORBIDDEN: file extension type not supported {}", path),
        );
        return;
    }
    let ftype = ftype.unwrap();

    let file_path = path.trim_start_matches('/');
    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => {
            send_error(
                &mut stream,
                "404 Not Found",
                "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\n",
                &format!("NOT FOUND: failed to open file {}", file_path),
            );
            return;
        }
    };

    log_msg(&format!(" INFO: SEND:{}:{}", file_path, hit));

    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let header = format!(
        "HTTP/1.1 200 OK\nServer: nweb/{}.0\nContent-Length: {}\nConnection: close\nContent-Type: {}\n\n",
        VERSION, len, ftype
    );
    log_msg(&format!(" INFO: Header:{}", header.replace('\n', " ")));
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
        println!("\n\tNot Supported: URLs including \"..\", CGI, etc.");
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

    // Change to topdir (chroot equivalent for non-privileged use)
    if std::env::set_current_dir(topdir).is_err() {
        eprintln!("ERROR: Can't Change to directory {}", topdir);
        process::exit(4);
    }

    log_msg(&format!(" INFO: nweb starting:{}:{}", args[1], process::id()));

    let listener = TcpListener::bind(("0.0.0.0", port)).unwrap_or_else(|e| {
        eprintln!("ERROR: bind failed: {}", e);
        process::exit(3);
    });

    println!("nweb listening on port {} (serving from {})", port, topdir);

    let mut hit = 1i32;
    for stream in listener.incoming() {
        if let Ok(s) = stream {
            let h = hit;
            hit += 1;
            thread::spawn(move || handle_client(s, h));
        }
    }
}
