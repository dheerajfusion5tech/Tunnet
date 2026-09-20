use std::fs;
use std::io::{self, Write};
use std::path::Path;

use atomic_write_file::{AtomicWriteFile, OpenOptions};

pub fn atomic_write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    write_with_options(OpenOptions::new(), path.as_ref(), contents.as_ref())
}

pub fn atomic_write_private(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    #[cfg(not(unix))]
    let options = OpenOptions::new();
    #[cfg(unix)]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use atomic_write_file::unix::OpenOptionsExt as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        options.preserve_mode(false).mode(0o600);
    }
    write_with_options(options, path.as_ref(), contents.as_ref())
}

pub fn atomic_copy(source: impl AsRef<Path>, destination: impl AsRef<Path>) -> io::Result<u64> {
    let source = source.as_ref();
    let mut input = fs::File::open(source)?;
    let mut output = AtomicWriteFile::open(destination)?;
    let copied = io::copy(&mut input, &mut output)?;
    output
        .as_file()
        .set_permissions(input.metadata()?.permissions())?;
    output.sync_all()?;
    output.commit()?;
    Ok(copied)
}

fn write_with_options(options: OpenOptions, path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    file.commit()
}

#[cfg(test)]
mod tests {
    use super::atomic_write;
    #[cfg(unix)]
    use super::atomic_write_private;

    #[test]
    fn atomic_write_replaces_existing_contents() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        std::fs::write(&path, b"old state").unwrap();

        atomic_write(&path, b"new state").unwrap();

        assert_eq!(std::fs::read(path).unwrap(), b"new state");
    }

    #[cfg(unix)]
    #[test]
    fn private_write_replaces_symlink_with_mode_0600() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secret");
        let victim = directory.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o666)).unwrap();
        symlink(&victim, &path).unwrap();

        atomic_write_private(&path, b"secret").unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
        let metadata = std::fs::symlink_metadata(path).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn private_write_does_not_preserve_permissive_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secret");
        std::fs::write(&path, b"old secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        atomic_write_private(&path, b"new secret").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new secret");
        assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o777, 0o600);
    }
}
