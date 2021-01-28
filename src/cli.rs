use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf, MAIN_SEPARATOR};
use std::process::{Command, Stdio};

use age::{
    armor::{ArmoredReader, ArmoredWriter, Format},
    Decryptor, Encryptor, IdentityFile,
};
use clap::{Clap, ValueHint};
use serde::Deserialize;

#[derive(Clap, Debug)]
struct Agenix {
    /// The file to edit.
    #[clap(parse(from_os_str), value_hint = ValueHint::FilePath)]
    path: PathBuf,
    /// Whether to re-encrypt the specified file.
    #[clap(short, long)]
    rekey: bool,
    /// The identity to use for decryption.
    ///
    /// If unspecified, ~/.ssh/id_rsa or ~/.ssh/id_ed25519 will be used, if
    /// either exist.
    #[clap(short, long)]
    identity: Option<String>,
    // TODO: verbose
}

#[derive(Debug, Deserialize)]
struct Config {
    identities: HashMap<String, String>,
    paths: Vec<PathSpec>,
}

#[derive(Debug, Deserialize)]
struct PathSpec {
    glob: String,
    identities: Vec<String>,
}

pub type Result<T, E = Box<dyn Error + Send + Sync + 'static>> = core::result::Result<T, E>;

pub fn run() -> Result<()> {
    let opts = Agenix::parse();
    let conf = toml::from_str::<Config>(&read_config()?)?;
    let mut recipients: Vec<Box<dyn age::Recipient>> = Vec::new();

    for path in conf.paths {
        let glob = glob::Pattern::new(&path.glob)?;

        if glob.matches(&normalize_path(&opts.path).display().to_string()) {
            for key in path.identities {
                let key = &conf.identities[&key];
                dbg!(&key);

                if let Ok(pk) = key.parse::<age::x25519::Recipient>().map(Box::new) {
                    recipients.push(pk);
                } else if let Some(pk) = key.parse::<age::ssh::Recipient>().ok().map(Box::new) {
                    recipients.push(pk);
                }
            }

            break;
        }
    }

    if recipients.is_empty() {
        panic!();
    }

    let decrypted = if opts.path.exists() && opts.path.is_file() {
        let f = File::open(&opts.path)?;
        let mut b = BufReader::new(f);
        let mut contents = Vec::new();
        b.read_to_end(&mut contents)?;

        let dec = match Decryptor::new(ArmoredReader::new(&contents[..]))? {
            Decryptor::Recipients(d) => {
                let mut decrypted = Vec::new();
                let ids = IdentityFile::from_file(
                    get_identity(opts.identity).ok_or("no usable identity")?,
                )?
                .into_identities();
                let mut reader = d.decrypt(
                    ids.into_iter()
                        .map(|i| Box::new(i) as Box<dyn age::Identity>),
                )?;
                reader.read_to_end(&mut decrypted)?;

                decrypted
            }
            _ => unimplemented!(),
        };

        Some(dec)
    } else {
        None
    };

    let editor = match env::var("VISUAL") {
        Ok(editor) => editor,
        Err(_) => match env::var("EDITOR") {
            Ok(editor) => editor,
            Err(e) => panic!(e),
        },
    };

    let mut tmpfile = create_temp_file(&opts.path)?;

    if let Some(ref dec) = decrypted {
        tmpfile.write_all(&dec)?;
    }

    if !opts.rekey {
        Command::new(editor)
            .arg(&tmpfile.path())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;
    }

    {
        let mut tmpfile = fs::OpenOptions::new().read(true).open(&tmpfile.path())?;

        let mut new = Vec::new();
        tmpfile.seek(SeekFrom::Start(0))?;
        tmpfile.read_to_end(&mut new)?;

        if let Some(ref dec) = decrypted {
            if !opts.rekey && dec == &new {
                panic!(); // same
            }
        }

        let f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&opts.path)?;
        let encryptor = Encryptor::with_recipients(recipients);
        let mut output =
            encryptor.wrap_output(ArmoredWriter::wrap_output(f, Format::AsciiArmor)?)?;
        // TODO: allow Format::Binary as well

        output.write_all(&new)?;
        output.finish().and_then(|armor| armor.finish())?;
    }

    Ok(())
}

/// Read the config file and return its contents.
fn read_config() -> Result<String> {
    let conf_path = find_config_dir().ok_or("unable to find config dir")?;
    let f = File::open(conf_path.join(".agenix.toml"))?;
    let mut b = BufReader::new(f);
    let mut contents = String::new();

    b.read_to_string(&mut contents)?;

    Ok(contents)
}

/// Find an acceptable identity to use for decryption.
fn get_identity(ident: Option<String>) -> Option<String> {
    if let Some(ref id) = ident {
        if std::fs::metadata(&id).is_ok() {
            return ident;
        }
    } else {
        let home = env::var("HOME").ok()?;

        for file in &[
            format!("{}/.ssh/id_rsa", home),
            format!("{}/.ssh/id_ed25519", home),
        ] {
            if fs::metadata(&file).is_ok() {
                return Some(String::from(file));
            }
        }
    }

    None
}

const MAX_DEPTH: usize = 100;

/// Looks for the directory that contains the config file. Used for resolving
/// the contained paths.
fn find_config_dir() -> Option<PathBuf> {
    let mut p = env::current_dir().ok()?;

    for _ in 0..MAX_DEPTH {
        let found = p.join(".agenix.toml");

        if !found.exists() {
            p.push("..");
        } else {
            return Some(p);
        }
    }

    None
}

/// Create a tempfile in $XDG_RUNTIME_DIR (if set; falling back to $TMPDIR or
/// /tmp if unset).
fn create_temp_file(filename: &Path) -> io::Result<tempfile::NamedTempFile> {
    let filename = format!("{}-", filename.display());
    let filename = filename.replace(MAIN_SEPARATOR, "-");
    let temp_dir = match env::var("XDG_RUNTIME_DIR") {
        Ok(v) => PathBuf::from(v),
        Err(_) => match env::var("TMPDIR") {
            Ok(v) => PathBuf::from(v),
            Err(_) => PathBuf::from("/tmp"),
        },
    };
    let tempfile = tempfile::Builder::new()
        .prefix(&filename)
        .tempfile_in(&temp_dir);

    tempfile
}

// TODO: credit cargo: https://github.com/rust-lang/cargo/blob/fede83ccf973457de319ba6fa0e36ead454d2e20/src/cargo/util/paths.rs#L61
fn normalize_path(path: &Path) -> PathBuf {
    let mut components = path.components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(..) => unreachable!(),
            Component::RootDir | Component::ParentDir => {
                // TODO: nice error
                panic!("not allowed >:(");
            }
            Component::CurDir => {}
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}
