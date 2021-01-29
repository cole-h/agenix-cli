use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf, MAIN_SEPARATOR};
use std::process::{Command, Stdio};

use age::{
    armor::{ArmoredReader, ArmoredWriter, Format},
    Decryptor, Encryptor,
};
use clap::{Clap, ValueHint};
use eyre::{eyre, Result, WrapErr};
use serde::Deserialize;

/// The maximum number of directories `agenix` is allowed to ascend in search of
/// the `.agenix.toml` configuration.
const MAX_DEPTH: usize = 100;

/// The `agenix` command-line options.
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
    /// If unspecified, falls back to ~/.ssh/id_rsa and then ~/.ssh/id_ed25519,
    /// whichever (if any) exists.
    #[clap(short, long)]
    identity: Option<String>,
    /// Whether or not to save encrypted files in binary format. Defaults to
    /// ASCII-armored output.
    #[clap(short, long)]
    binary: bool,
    // TODO: verbose?
}

/// The `.agenix.toml` configuration schema.
///
/// # Example configuration
///
/// ```toml
/// [identities]
/// user1 = "age1szr8hp9lrjvc2d2hnr9c56fcj6f5ngnjy8gldnu6qtejnjrp6pmsc47jw8"
/// machine1 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBKD0YBA9vjNiIhBMVZgIjFjY282BfR6JM84HwcemN3Xt/vWaH1k53QzJqAF3LqJBisP9/xCSy+BL8cUV0z9goei3xOrWIfRTk0Hp5xYsVo7POvq1aQ3x+fFj3LAO/7HMYX/VD0jfHilv49HD0eQOiNp0T/OK3NuuFJmh2Wq45GibWRN6zdP42tB+4eKsJf7rIV+kcdybDlYYEiyCbGAcKMqcpzF+3CSQSbqA+XWPiyagUTucnoakjcJvZC6KPfK189t1KYV+1pKB1lD1MLJp+5jiaZFFyFASJ6jCIBO+il9XrCMDVO9RucxY89TBJBp24fd+hYwsH3YxIPN/esnftRePkIFbwIHout/9JVkFNpWeG6vORdAlnkyYmr8lNsodiGAmnGN3diAYNcmPqQ/9m9uovptFZWDB8yXEbnd3DZmTbuyhlrnaqqSE72p2a8WSqFr6aT2F1fk7AKLzJGT6/Grhk/7mXkqF5W7FnKP6D/XqYeNZA1NizUdxZopSJE6c="
///
/// [[paths]]
/// glob = "secrets/user1/*"
/// identities = [ "user1" ]
///
/// [[paths]]
/// glob = "secrets/machine1/*"
/// identities = [ "machine1" ]
///
/// [[paths]]
/// glob = "secrets/misc/*"
/// identities = [ "user1", "machine1" ]
///
/// [[paths]]
/// glob = "secrets/user2/*"
/// identities = [
///   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKbG8+IyUzm2v37k+SihwJ59JgZYsgU9/cJDUzeZUvgs"
/// ]
///
/// [[paths]]
/// glob = "secrets/machine2/*"
/// identities = [
///   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICY1Zxf4TBam5LYfFhOv3D9aFvtBrfn+rKHPzprCzv5b"
/// ]
/// ```
#[derive(Debug, Deserialize)]
struct Config {
    /// A list of names and their associated identities.
    identities: HashMap<String, String>,
    /// A list of paths managed by `agenix`.
    paths: Vec<PathSpec>,
}

/// The `paths` array-of-tables.
#[derive(Debug, Deserialize)]
struct PathSpec {
    /// All paths matching this glob (relative to the `.agenix.toml` file) will
    /// be encrypted to the associated list of identities.
    glob: String,
    /// A list of identities with access to the files matched by the associated
    /// glob. Can either be a name from the identities table, or a bare key
    /// (e.g. `age...` or `ssh-ed25519 ...` or `ssh-rsa ...`).
    identities: Vec<String>,
}

/// The main `agenix` command-line interface.
pub fn run() -> Result<()> {
    let opts = Agenix::parse();
    let conf = toml::from_str::<Config>(&read_config()?)?;
    let recipients = get_recipients_from_config(conf, &opts.path)?;

    if recipients.is_empty() {
        return Err(eyre!(
            "file '{}' has no valid recipients",
            &opts.path.display()
        ));
    }

    let editor = match env::var("EDITOR") {
        Ok(editor) => editor,
        Err(_) => env::var("VISUAL")
            .map_err(|e| eyre!(e))
            .wrap_err("failed to find suitable editor")?,
    };

    let decrypted = try_decrypt_target_with_identity(&opts.path, opts.identity)?;
    let mut temp_file = create_temp_file(&opts.path)?;

    if let Some(ref dec) = decrypted {
        temp_file.write_all(&dec)?;
    }

    if !opts.rekey {
        Command::new(editor)
            .arg(&temp_file.path())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .wrap_err("failed to spawn editor")?;
    }

    let mut temp_file = fs::OpenOptions::new()
        .read(true)
        .open(&temp_file.path())
        .wrap_err("failed to open temporary file for reading")?;

    let mut new = Vec::new();
    temp_file.seek(SeekFrom::Start(0))?;
    temp_file.read_to_end(&mut new)?;

    if new.is_empty() {
        writeln!(io::stderr(), "contents unchanged")?;
        return Ok(());
    }

    if let Some(ref dec) = decrypted {
        if !opts.rekey && dec == &new {
            writeln!(io::stderr(), "contents unchanged")?;
            return Ok(());
        }
    }

    // TODO: create dirs when doing e.g. agenix secrets/a/b/c/d (see passrs)
    try_encrypt_target_with_recipients(&opts.path, recipients, new, opts.binary)?;

    Ok(())
}

/// Try to encrypt the given contents into the target path for the specified
/// recipients, optionally in binary format (as opposed to ASCII-armored
/// output).
fn try_encrypt_target_with_recipients(
    target: &Path,
    recipients: Vec<Box<dyn age::Recipient>>,
    contents: Vec<u8>,
    binary: bool,
) -> Result<()> {
    let target = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&target)?;
    let format = match binary {
        true => Format::Binary,
        false => Format::AsciiArmor,
    };
    let encryptor = Encryptor::with_recipients(recipients);
    let mut output = encryptor.wrap_output(ArmoredWriter::wrap_output(target, format)?)?;

    output.write_all(&contents)?;
    output.finish().and_then(|armor| armor.finish())?;

    Ok(())
}

/// Try to decrypt the given target path with the specified identity.
///
/// Uses [`get_identity`](get_identity) to find a valid identity.
fn try_decrypt_target_with_identity(
    target: &Path,
    identity: Option<String>,
) -> Result<Option<Vec<u8>>> {
    if target.exists() && target.is_file() {
        let f = File::open(&target)?;
        let mut b = BufReader::new(f);
        let mut contents = Vec::new();
        b.read_to_end(&mut contents)?;

        let dec = match Decryptor::new(ArmoredReader::new(&contents[..]))? {
            Decryptor::Recipients(d) => {
                let mut decrypted = Vec::new();
                let id = get_identity(identity)?;
                let mut reader = d.decrypt(id.into_iter())?;
                reader.read_to_end(&mut decrypted)?;

                decrypted
            }
            _ => unimplemented!(),
        };

        Ok(Some(dec))
    } else {
        // TODO: logging here that specified path wasn't a file or didn't exist
        Ok(None)
    }
}

/// Parses the recipients of a specified path from the `.agenix.toml`
/// configuration.
fn get_recipients_from_config(conf: Config, target: &Path) -> Result<Vec<Box<dyn age::Recipient>>> {
    let mut recipients: Vec<Box<dyn age::Recipient>> = Vec::new();

    for path in conf.paths {
        let glob = glob::Pattern::new(&path.glob)?;

        if glob.matches(&normalize_path(&target)?.display().to_string()) {
            for key in path.identities {
                let key = match conf.identities.get(&key) {
                    Some(key) => key,
                    None => &key,
                };

                if let Ok(pk) = key.parse::<age::x25519::Recipient>().map(Box::new) {
                    recipients.push(pk);
                } else if let Ok(pk) = key.parse::<age::ssh::Recipient>().map(Box::new) {
                    recipients.push(pk);
                } else {
                    // TODO: log that &key wasn't an age or ssh key, or didn't
                    // reference the identities table
                }
            }

            break;
        }
    }

    Ok(recipients)
}

/// Find an acceptable identity to use for decryption.
fn get_identity(ident: Option<String>) -> Result<Vec<Box<dyn age::Identity>>> {
    match ident {
        Some(ref id) => {
            if std::fs::metadata(&id).is_ok() {
                return age::cli_common::read_identities(
                    vec![id.to_string()],
                    |s| eyre!(s),
                    |s, e| eyre!("{}: {:?}", s, e),
                );
            }
        }
        None => {
            let home = env::var("HOME")?;

            for file in &[
                format!("{}/.ssh/id_rsa", home),
                format!("{}/.ssh/id_ed25519", home),
            ] {
                if fs::metadata(&file).is_ok() {
                    return age::cli_common::read_identities(
                        vec![file.to_string()],
                        |s| eyre!(s),
                        |s, e| eyre!("{}: {:?}", s, e),
                    );
                }
            }
        }
    }

    Err(eyre!("no usable identity"))
}

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

/// Read the config file and return its contents as a `String`.
fn read_config() -> Result<String> {
    let conf_path = find_config_dir()
        .ok_or("failed to find config dir")
        .map_err(|e| eyre!(e))?;
    let f = File::open(conf_path.join(".agenix.toml"))?;
    let mut b = BufReader::new(f);
    let mut contents = String::new();

    b.read_to_string(&mut contents)?;

    Ok(contents)
}

/// Create a tempfile in `$XDG_RUNTIME_DIR` (if set; falling back to `$TMPDIR`
/// or `/tmp` if unset).
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
    let temp_file = tempfile::Builder::new()
        .prefix(&filename)
        .tempfile_in(&temp_dir);

    temp_file
}

// https://github.com/rust-lang/cargo/blob/fede83ccf973457de319ba6fa0e36ead454d2e20/src/cargo/util/paths.rs#L61-L86
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/// Normalize the specified path by stripping `./` and disallowing access to the
/// root or a parent directory.
fn normalize_path(path: &Path) -> Result<PathBuf> {
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
                return Err(eyre!("glob may not refer to the filesystem root (`/`) or the parent directory (`../`)"));
            }
            Component::CurDir => {}
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }

    Ok(ret)
}
