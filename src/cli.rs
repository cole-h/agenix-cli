//! The `agenix` command-line interface.

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
use clap::Parser;
use color_eyre::{
    eyre::{bail, eyre, Result, WrapErr},
    Section, SectionExt,
};
use env_logger::{fmt::Color, WriteStyle};
use log::{debug, error, info, trace, warn, Level, LevelFilter};
use serde::Deserialize;

/// The maximum number of directories `agenix` is allowed to ascend in search of
/// the `.agenix.toml` configuration.
const MAX_DEPTH: u8 = 100;

#[doc(hidden)]
const LF: [u8; 1] = [0x0a];
#[doc(hidden)]
const CRLF: [u8; 2] = [0x0d, 0x0a];

/// The `agenix` command-line options.
#[derive(Parser, Debug)]
struct Agenix {
    /// The file to edit.
    ///
    /// Optional when used with `--rekey` to rekey everything or validating the
    /// config, required otherwise.
    path: Option<String>,
    /// Whether to re-encrypt the specified file or all files, if no `path` is given.
    #[clap(short, long)]
    rekey: bool,
    /// The identity or identities to use for decryption. May be specified
    /// multiple times.
    ///
    /// If unspecified, falls back to `~/.ssh/id_rsa` and `~/.ssh/id_ed25519`,
    /// whichever (if any) exists.
    #[clap(short, long, number_of_values = 1, action = clap::ArgAction::Append)]
    identity: Vec<String>,
    /// Whether or not to save encrypted files in binary format.
    ///
    /// By default, output files are ASCII-armored.
    #[clap(short, long)]
    binary: bool,
    /// Whether or not to encrypt a plaintext file in-place.
    #[clap(short, long)]
    encrypt_in_place: bool,
    /// The verbosity of logging.
    ///
    /// By default, only warnings and errors are printed.
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Whether or not to read contents from stdin.
    ///
    /// NOTE: This does not support writing to an existing file.
    ///
    /// By default, an editor is spawned.
    #[clap(short, long)]
    stdin: bool,
    /// Validate the config file.
    #[clap(long)]
    validate_config: bool,
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
/// [groups]
/// machine1Admins = [
///   "user1",
///   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKbG8+IyUzm2v37k+SihwJ59JgZYsgU9/cJDUzeZUvgs"
/// ]
///
/// [[paths]]
/// glob = "secrets/user1/*"
/// identities = [ "user1" ]
///
/// [[paths]]
/// glob = "secrets/machine1/*"
/// identities = [ "machine1" ]
/// groups = [ "machine1Admins" ]
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
struct AgenixConfig {
    /// A list of names and their associated identities. Optional.
    #[serde(default)]
    identities: HashMap<String, String>,
    /// A list of group names and their associated identities. Optional.
    #[serde(default)]
    groups: HashMap<String, Vec<String>>,
    /// A list of paths managed by `agenix`. Required.
    paths: Vec<PathSpec>,
}

/// The `[[paths]]` array-of-tables.
///
/// One of `identities` or `groups` must be specified, and both may be specified
/// at the same time.
#[derive(Debug, Deserialize)]
struct PathSpec {
    /// All paths matching this glob (relative to the `.agenix.toml` file) will
    /// be encrypted to the associated list of identities. Required.
    glob: String,
    /// A list of identities with access to the files matched by the associated
    /// glob. Can either be a name from the identities table, or a bare key
    /// (e.g. `age...` or `ssh-ed25519 ...` or `ssh-rsa ...`).
    #[serde(default)]
    identities: Vec<String>,
    /// A list of groups with access to the files matched by the associated
    /// glob. Must be a name from the `[groups]` table.
    #[serde(default)]
    groups: Vec<String>,
    // TODO:  keyfile: Vec<PathBuf>? to sidestep the necessity of -i for age keys
}

/// A structure that contains the `.agenix.toml` configuration and the root
/// directory of that configuration.
#[derive(Debug)]
struct Config {
    /// The `.agenix.toml` configuration.
    agenix: AgenixConfig,
    /// The root directory of the configuration.
    root: PathBuf,
}

const MATCH_OPTS: glob::MatchOptions = glob::MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

/// Run `agenix`.
pub fn run() -> Result<()> {
    let opts = Agenix::parse();

    match &opts.path {
        None => {
            if !opts.rekey && !opts.validate_config {
                bail!("agenix requires a path argument (unless rekeying or validating the config).")
            }
        }
        Some(path) => {
            if path.ends_with('/') || Path::new(&path).is_dir() {
                bail!("agenix cannot operate on a directory. Please specify a filename (whether or not it exists).");
            }

            if opts.rekey && !Path::new(&path).exists() {
                bail!("agenix cannot rekey a nonexistent file.");
            }

            if opts.stdin && Path::new(&path).exists() {
                bail!("agenix does not allow writing contents from stdin to an existing file.");
            }
        }
    }

    env_logger::Builder::new()
        .format(|buf, record| {
            let mut style = buf.style();

            match record.level() {
                Level::Trace => style.set_color(Color::Cyan),
                Level::Debug => style.set_color(Color::Blue),
                Level::Info => style.set_color(Color::Green),
                Level::Warn => style.set_color(Color::Yellow),
                Level::Error => style.set_color(Color::Red).set_bold(true),
            };

            writeln!(buf, "{:<5} {}", style.value(record.level()), record.args())
        })
        .filter(
            Some(env!("CARGO_PKG_NAME")), // only log for agenix
            match opts.verbose {
                0 => LevelFilter::Warn,
                1 => LevelFilter::Info,
                2 => LevelFilter::Debug,
                _ => LevelFilter::Trace,
            },
        )
        .write_style(WriteStyle::Auto)
        .try_init()
        .wrap_err("Failed to initialize logging")?;

    let conf_path = self::find_config_dir()?.ok_or_else(|| eyre!("Failed to find config root"))?;
    let agenix_conf = toml::from_str::<AgenixConfig>(
        &self::read_config(&conf_path).wrap_err("Failed to read config file")?,
    )
    .wrap_err("Failed to parse config as TOML")?;

    let current_path = env::current_dir().wrap_err("Failed to get current directory")?;
    let conf = Config {
        agenix: agenix_conf,
        root: conf_path,
    };

    trace!("validate_config? {}", opts.validate_config);
    trace!("rekey? {}", opts.rekey);
    trace!("path.is_none()? {}", opts.path.is_none());
    if opts.validate_config {
        self::validate_config(&conf)?;
    } else if opts.rekey && opts.path.is_none() {
        let mut paths = Vec::new();
        for pathspec in &conf.agenix.paths {
            for path in glob::glob_with(&pathspec.glob, MATCH_OPTS)
                .wrap_err_with(|| format!("Failed to match glob pattern '{}'", &pathspec.glob))?
            {
                let path = path.wrap_err_with(|| {
                    format!("Failed to iterate over glob pattern '{}'", &pathspec.glob)
                })?;
                paths.push(path);
            }
        }

        for path in paths {
            if let Err(e) = self::try_process_file(&conf, &path, &opts, &current_path) {
                error!("Failed to rekey file '{}': {}", path.display(), e);
            } else {
                info!("Successfully rekeyed file '{}'", path.display());
            }
        }
    } else {
        // This `unwrap()` is safe because we verify that the path is specified if we're not in
        // `rekey` mode.
        self::try_process_file(&conf, &opts.path.clone().unwrap(), &opts, &current_path)?;
    }

    Ok(())
}

/// Validates the config and logs any errors found in the config.
fn validate_config(conf: &Config) -> Result<()> {
    // validate keys
    for (identity, key) in &conf.agenix.identities {
        if self::try_parse_key_to_recipient(&key).is_none() {
            warn!(
                "Identity '{}' is not a valid age, ssh-rsa, or ssh-ed25591 public key",
                &identity
            );
        }
    }

    for (group, identities) in &conf.agenix.groups {
        // check for empty groups
        if identities.is_empty() {
            warn!("Group '{}' contains no identities", group);
        }

        // check for groups with unknown identites
        for identity in identities {
            if !conf.agenix.identities.contains_key(identity) {
                warn!("Group '{}' contains unknown identity '{}'", group, identity);
            }
        }
    }

    let mut patterns_by_path = HashMap::new();
    for pathspec in &conf.agenix.paths {
        // collect patterns matching each path
        for path in glob::glob_with(&pathspec.glob, MATCH_OPTS)
            .wrap_err_with(|| format!("Failed to match glob pattern '{}'", &pathspec.glob))?
        {
            let path = path.wrap_err_with(|| {
                format!("Failed to iterate over glob pattern '{}'", &pathspec.glob)
            })?;
            let patterns = patterns_by_path.entry(path).or_insert_with(|| Vec::new());
            patterns.push(pathspec.glob.clone());
        }

        // check for paths without group or identity
        if pathspec.identities.is_empty() && pathspec.groups.is_empty() {
            warn!(
                "Path glob '{}' has no associated identities or groups",
                pathspec.glob
            );
        }

        // check for unkown identities
        for identity in &pathspec.identities {
            if !conf.agenix.identities.contains_key(identity)
                && self::try_parse_key_to_recipient(identity).is_none()
            {
                warn!(
                        "Path glob '{}' has associated identity '{}' which is neither a valid key nor a name of an identity",
                        pathspec.glob, identity
                    );
            }
        }

        // check for unkown groups
        for group in &pathspec.groups {
            if !conf.agenix.groups.contains_key(group) {
                warn!(
                    "Path glob '{}' has unknown associated group '{}'",
                    pathspec.glob, group
                );
            }
        }
    }

    // check for paths matched by multiple patterns
    for (path, patterns) in patterns_by_path {
        if 1 < patterns.len() {
            warn!(
                "Path '{}' is matched by {} glob patterns ('{}')",
                &path.display(),
                &patterns.len(),
                &patterns.join("', '")
            );
        }
    }

    Ok(())
}

/// Try to process the specified path in order to decrypt and encrypt its contents.
fn try_process_file<P>(conf: &Config, path: P, opts: &Agenix, current_path: &Path) -> Result<()>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    let relative_path = current_path.strip_prefix(&conf.root).unwrap_or(&env::current_dir()?).join(path);
    let recipients = self::get_recipients_from_config(&conf, &relative_path)
        .wrap_err("Failed to get recipients from config file")?;

    if recipients.is_empty() {
        bail!(
            "File '{}' has no valid recipients",
            &relative_path.display()
        );
    }

    let decrypted =
        self::try_decrypt_target_with_identities(path, &opts.identity, opts.encrypt_in_place)
            .wrap_err_with(|| format!("Failed to decrypt file '{}'", &path.display()))?;
    let mut temp_file =
        self::create_temp_file(&relative_path).wrap_err("Failed to create temporary file")?;

    if let Some(ref dec) = decrypted {
        temp_file
            .write_all(&dec)
            .wrap_err("Failed to write decrypted contents to temporary file")?;
    }

    trace!("rekey? {}", opts.rekey);
    trace!("encrypt_in_place? {}", opts.encrypt_in_place);
    if !opts.rekey && !opts.encrypt_in_place && !opts.stdin {
        self::try_edit_file(&temp_file.path())?;
    }

    let contents = if opts.stdin {
        let mut input = Vec::new();

        for byte in io::stdin().bytes() {
            let b = byte?;
            input.push(b);
        }

        input
    } else {
        let mut new_contents = Vec::new();
        let mut temp_file = fs::OpenOptions::new()
            .read(true)
            .open(&temp_file.path())
            .wrap_err("Failed to open temporary file for reading")?;

        // Ensure the cursor is at the beginning of the file.
        temp_file.seek(SeekFrom::Start(0))?;
        temp_file
            .read_to_end(&mut new_contents)
            .wrap_err("Failed to read new contents from temporary file")?;

        if new_contents.is_empty() || new_contents == LF || new_contents == CRLF {
            warn!("contents empty, not saving");
            return Ok(());
        }

        if let Some(ref dec) = decrypted {
            if !(opts.rekey || opts.encrypt_in_place) && dec == &new_contents {
                warn!("contents unchanged, not saving");
                return Ok(());
            }
        }

        new_contents
    };

    self::try_encrypt_target_with_recipients(&path, recipients, contents, opts.binary)
        .wrap_err_with(|| format!("Failed to encrypt file '{}'", &path.display()))?;

    Ok(())
}

/// A light wrapper around [`fs::create_dir_all`] that creates all directories
/// that would allow the specified `file` to be created.
///
/// [`fs::create_dir_all`]: https://doc.rust-lang.org/std/fs/fn.create_dir_all.html
fn create_dirs_to_file(file: &Path) -> Result<()> {
    if file.exists() {
        return Ok(());
    }

    let dir = file
        .parent()
        .ok_or_else(|| eyre!("Path '{}' had no parent", file.display()))?;

    fs::create_dir_all(dir)
        .wrap_err_with(|| format!("Failed to create directories to '{}'", &dir.display()))?;

    Ok(())
}

/// Try to encrypt the given contents into the `target` path for the specified
/// `recipients`, optionally in `binary` format (as opposed to the default of
/// ASCII-armored text).
fn try_encrypt_target_with_recipients(
    target: &Path,
    recipients: Vec<Box<dyn age::Recipient>>,
    contents: Vec<u8>,
    binary: bool,
) -> Result<()> {
    self::create_dirs_to_file(&target)
        .wrap_err_with(|| format!("Failed to create directories to '{}'", &target.display()))?;

    let target = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&target)
        .wrap_err_with(|| format!("Failed to open '{}' for writing", &target.display()))?;

    trace!("binary format? {}", binary);
    let format = match binary {
        true => Format::Binary,
        false => Format::AsciiArmor,
    };

    let encryptor = Encryptor::with_recipients(recipients);
    let mut output = encryptor
        .wrap_output(
            ArmoredWriter::wrap_output(target, format)
                .wrap_err("Failed to wrap output with age::ArmoredWriter")?,
        )
        .wrap_err("Failed to wrap output with age::Encryptor")?;

    output
        .write_all(&contents)
        .wrap_err("Failed to write encrypted contents")?;
    output
        .finish()
        .and_then(|armor| armor.finish())
        .wrap_err("Failed to finish age transaction")?;

    Ok(())
}

/// Open `target` for editing and wait for the user to complete the editing.
fn try_edit_file(target: &Path) -> Result<()> {
    let (editor, args) = self::find_suitable_editor().wrap_err("Failed to find suitable editor")?;
    debug!("editor: '{}'", &editor);
    debug!("args: '{:?}'", &args);

    let cmd = Command::new(&editor)
        .args(if let Some(args) = args {
            args
        } else {
            Vec::new()
        })
        .arg(&target)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .output()
        .wrap_err_with(|| format!("Failed to spawn editor '{}'", &editor))?;

    if !cmd.status.success() {
        let stderr = String::from_utf8_lossy(&cmd.stderr);

        return Err(eyre!(
            "Editor '{}' exited with non-zero status code",
            &editor
        ))
        .with_section(|| stderr.trim().to_string().header("Stderr:"));
    } else {
        Ok(())
    }
}

/// Try to decrypt the given target path with the specified identity.
///
/// Uses [`get_identities`](get_identities) to find a valid identity.
fn try_decrypt_target_with_identities(
    target: &Path,
    identities: &[String],
    encrypt_in_place: bool,
) -> Result<Option<Vec<u8>>> {
    if target.exists() && target.is_file() {
        let f = File::open(&target)
            .wrap_err_with(|| format!("Failed to open '{}'", &target.display()))?;
        let mut b = BufReader::new(f);
        let mut contents = Vec::new();

        b.read_to_end(&mut contents)
            .wrap_err_with(|| format!("Failed to read '{}'", &target.display()))?;

        let dec = match Decryptor::new(ArmoredReader::new(&contents[..])) {
            Ok(_) if encrypt_in_place => {
                bail!(
                    "File '{}' is already encrypted; refusing to encrypt in place",
                    &target.display()
                );
            }
            Err(_) if encrypt_in_place => contents,
            Ok(decryptor) => match decryptor {
                Decryptor::Recipients(d) => {
                    let mut decrypted = Vec::new();
                    let ids = self::get_identities(identities.to_vec())
                        .wrap_err("Failed to get usable identity or identities")?;
                    let mut reader = d
                        .decrypt(ids.iter().map(|i| i.as_ref() as &dyn age::Identity))
                        .wrap_err("Failed to decrypt contents")?;

                    reader
                        .read_to_end(&mut decrypted)
                        .wrap_err("Failed to read decrypted contents")?;

                    decrypted
                }
                Decryptor::Passphrase(_) => {
                    bail!("Age password-encrypted files are not supported");
                }
            },
            Err(e) => Err(e)
                .wrap_err_with(|| format!("Failed to parse header of '{}'", &target.display()))?,
        };

        Ok(Some(dec))
    } else {
        info!(
            "specified path '{}' does not exist; not decrypting",
            target.display()
        );

        Ok(None)
    }
}

/// Tries parsing the given key into a Recipient. Returns None if parsing fails
fn try_parse_key_to_recipient(key: &str) -> Option<Box<dyn age::Recipient>> {
    if let Ok(pk) = key.parse::<age::x25519::Recipient>().map(Box::new) {
        trace!("got valid age identity '{}'", &key);
        Some(pk)
    } else if let Ok(pk) = key.parse::<age::ssh::Recipient>().map(Box::new) {
        trace!("got valid ssh identity '{}'", &key);
        Some(pk)
    } else {
        None
    }
}

/// Parses the recipients of a specified path from the `.agenix.toml`
/// configuration.
fn get_recipients_from_config(
    conf: &Config,
    target: &Path,
) -> Result<Vec<Box<dyn age::Recipient>>> {
    let mut recipients: Vec<Box<dyn age::Recipient>> = Vec::new();
    let mut matches = 0;

    for path in &conf.agenix.paths {
        if path.identities.is_empty() && path.groups.is_empty() {
            warn!(
                "Path '{}' has no associated identities or groups",
                &target.display()
            );
        }

        let target = self::normalize_path(&target);
        let glob = glob::Pattern::new(&path.glob)
            .wrap_err_with(|| format!("Failed to construct glob pattern from '{}'", &path.glob))?;

        if glob.matches_path_with(&target, MATCH_OPTS) {
            let identities = {
                let mut ids = path.identities.clone();

                for group in &path.groups {
                    if let Some(i) = conf.agenix.groups.get(group) {
                        ids.extend(i.clone());
                    } else {
                        warn!("group '{}' doesn't reference the [groups] table", group);
                    }
                }

                ids
            };

            for key in identities {
                let key = match conf.agenix.identities.get(&key) {
                    Some(key) => key,
                    None => &key,
                };

                match self::try_parse_key_to_recipient(&key) {
                    Some(pk) => recipients.push(pk),
                    None => {
                        warn!("identity '{}' either:", &key);
                        warn!("  * isn't a valid age, ssh-rsa, or ssh-ed25519 public key; or");
                        warn!("  * doesn't reference the [identities] table");
                    }
                }
            }

            matches += 1;
        }
    }

    if matches == 0 {
        warn!(
            "Path '{}' is not matched by any configured glob pattern",
            &target.display()
        );
    } else if 1 < matches {
        warn!(
            "Path '{}' is matched by more than one configured glob pattern",
            &target.display()
        );
    }

    Ok(recipients)
}

/// Find an acceptable identity or identities to use for decryption.
fn get_identities(mut identities: Vec<String>) -> Result<Vec<Box<dyn age::Identity>>> {
    let home = env::var("HOME").wrap_err("Failed to get $HOME")?;

    // Always try id_rsa and id_ed25519. This is consistent with the Go
    // implementation of `age`:
    // https://github.com/FiloSottile/age/blob/b47610677cea90662979854d63473c3cbdd5315f/cmd/age/age.go#L299-L314
    identities.extend_from_slice(&[
        format!("{}/.ssh/id_rsa", home),
        format!("{}/.ssh/id_ed25519", home),
    ]);

    identities.retain(|id| fs::metadata(&id).is_ok());

    if !identities.is_empty() {
        debug!("using {:?} as identity file(s)", &identities);
        return age::cli_common::read_identities(
            identities,
            |s| eyre!(s),
            |s, e| eyre!("{}: {:?}", s, e),
        );
    }

    Err(eyre!("No usable identity or identities"))
}

/// Looks for the directory that contains the config file. Used for resolving
/// the contained paths.
///
/// One can specify the `$AGENIX_ROOT` environment variable to set the root
/// of the `agenix` configuration (requires `.agenix.toml` in this directory).
/// This will prevent `agenix` from ascending the filesystem in search of
/// `.agenix.toml`.
fn find_config_dir() -> Result<Option<PathBuf>> {
    let mut path = env::current_dir().wrap_err("Failed to get current directory")?;

    if let Ok(root) = env::var("AGENIX_ROOT") {
        let dir = Path::new(&root)
            .canonicalize()
            .wrap_err_with(|| format!("Failed to canonicalize AGENIX_ROOT ('{}')", &root))?;

        if dir.is_dir() {
            return Ok(Some(dir));
        } else {
            warn!("AGENIX_ROOT ('{}') isn't a directory", dir.display())
        }
    } else {
        for _ in 0..MAX_DEPTH {
            debug!("checking '{}' for .agenix.toml config", path.display());
            let found = path.join(".agenix.toml");

            if !found.exists() {
                path = path.join("..").canonicalize()?;
            } else {
                debug!("found config at '{}'", found.display());
                return Ok(Some(path));
            }
        }
    }

    Ok(None)
}

/// Read the config file and return its contents as a `String`.
fn read_config(conf_path: &Path) -> Result<String> {
    let file = File::open(&conf_path.join(".agenix.toml"))
        .wrap_err_with(|| format!("Failed to find .agenix.toml in '{}'", &conf_path.display()))?;
    let mut buf = BufReader::new(file);
    let mut contents = String::new();

    buf.read_to_string(&mut contents).wrap_err_with(|| {
        format!(
            "Failed to read contents of .agenix.toml in '{}'",
            &conf_path.display()
        )
    })?;

    Ok(contents)
}

/// Create a tempfile in `$XDG_RUNTIME_DIR` (if set; falling back to `$TMPDIR`
/// or `/tmp` if unset).
fn create_temp_file(filename: &Path) -> Result<tempfile::NamedTempFile> {
    let filename = self::normalize_path(&filename);
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
        .tempfile_in(&temp_dir)
        .wrap_err_with(|| {
            format!(
                "Failed to create temporary file '{}' in '{}'",
                &filename,
                &temp_dir.display()
            )
        })?;

    Ok(temp_file)
}

/// Parse the `EDITOR` and / or `VISUAL` environment variables to find
/// a suitable editor. If the editor contains whitespace, split on it
/// and treat the first split as the binary, and all following splits
/// as arguments.
fn find_suitable_editor() -> Result<(String, Option<Vec<String>>)> {
    let editor = env::var("EDITOR")
        .or_else(|_| env::var("VISUAL"))
        .map_err(|e| eyre!(e))?;

    if editor.contains(' ') {
        let mut split = editor.split_ascii_whitespace();
        let editor = split.next();
        let args = split.map(String::from).collect::<Vec<String>>();

        Ok((
            String::from(editor.ok_or_else(|| eyre!("EDITOR or VISUAL was empty"))?),
            Some(args),
        ))
    } else {
        Ok((editor, None))
    }
}

// https://github.com/rust-lang/cargo/blob/fede83ccf973457de319ba6fa0e36ead454d2e20/src/cargo/util/paths.rs#L61-L86
//
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

/// Normalize the specified path by stripping `./` and resolving `../`, without
/// actually resolving the path (like
/// [`fs::canonicalize`](std::fs::canonicalize) does).
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
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::ParentDir => {
                ret.pop();
            }
            Component::CurDir => {}
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }

    ret
}
