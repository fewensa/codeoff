use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path};

use codeoff_config::ScheduledCodexConfig;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, fstat};
use nix::unistd::{getegid, geteuid, getgroups};
use sha2::{Digest, Sha256};

use crate::scheduled::RequestedCapabilityProfile;

#[cfg_attr(
  not(test),
  allow(
    dead_code,
    reason = "used only by the disabled local verifier test seam"
  )
)]
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_ATTESTATION_BYTES: u64 = 64 * 1024;
const MAX_TRUST_BUNDLE_BYTES: u64 = 64 * 1024;

pub(super) struct VerifiedScheduledArtifacts {
  pub program: File,
  pub codex_home: File,
  pub cwd: File,
  #[allow(
    dead_code,
    reason = "retains the verified config inode for the executor lifetime"
  )]
  config: File,
  #[allow(
    dead_code,
    reason = "retains the verified MCP artifact inode for the executor lifetime"
  )]
  github_mcp_artifact: File,
  #[allow(
    dead_code,
    reason = "retains the verified attestation inode for the executor lifetime"
  )]
  attestation: File,
  #[cfg_attr(
    not(test),
    allow(
      dead_code,
      reason = "used only by the disabled local verifier test seam"
    )
  )]
  pub attestation_contents: String,
  #[allow(
    dead_code,
    reason = "retains the verified trust bundle inode for the executor lifetime"
  )]
  trust_bundle: File,
  #[cfg_attr(
    not(test),
    allow(
      dead_code,
      reason = "used only by the disabled local verifier test seam"
    )
  )]
  pub trust_bundle_contents: String,
}

#[derive(Clone, Copy)]
struct ArtifactTrustPolicy {
  trusted_uid: u32,
  trusted_gid: u32,
  runtime_uid: u32,
  runtime_gid: u32,
}

#[derive(Clone, Copy)]
#[cfg_attr(
  not(test),
  allow(
    dead_code,
    reason = "executable verification is retained only for tests"
  )
)]
enum ArtifactKind {
  Directory { immutable: bool },
  ReadOnlyFile,
  Executable,
}

pub(super) fn read_verified_scheduled_authority_material(
  config: &ScheduledCodexConfig,
) -> Result<(String, String), String> {
  let policy = observed_trust_policy(config)?;
  let attestation = open_verified(
    &config.isolation_attestation_path,
    ArtifactKind::ReadOnlyFile,
    policy,
  )?;
  let attestation_contents = read_utf8(
    &attestation,
    MAX_ATTESTATION_BYTES,
    "scheduled_isolation_attestation",
  )?;
  let trust_bundle = open_verified(
    &config.isolation_trust_bundle_path,
    ArtifactKind::ReadOnlyFile,
    policy,
  )?;
  let trust_bundle_contents = read_utf8(
    &trust_bundle,
    MAX_TRUST_BUNDLE_BYTES,
    "scheduled_isolation_trust_bundle",
  )?;
  Ok((attestation_contents, trust_bundle_contents))
}

pub(super) fn read_trusted_owner_scheduled_authority_material(
  config: &ScheduledCodexConfig,
) -> Result<(String, String), String> {
  if geteuid().as_raw() != config.trusted_owner_uid
    || getegid().as_raw() != config.trusted_owner_gid
    || config.trusted_owner_uid == config.runtime_uid
    || config.trusted_owner_gid == config.runtime_gid
  {
    return Err("scheduled_trusted_owner_identity_mismatch".to_owned());
  }
  let policy = ArtifactTrustPolicy {
    trusted_uid: config.trusted_owner_uid,
    trusted_gid: config.trusted_owner_gid,
    runtime_uid: config.runtime_uid,
    runtime_gid: config.runtime_gid,
  };
  let attestation = open_verified(
    &config.isolation_attestation_path,
    ArtifactKind::ReadOnlyFile,
    policy,
  )?;
  let trust_bundle = open_verified(
    &config.isolation_trust_bundle_path,
    ArtifactKind::ReadOnlyFile,
    policy,
  )?;
  Ok((
    read_utf8(
      &attestation,
      MAX_ATTESTATION_BYTES,
      "scheduled_isolation_attestation",
    )?,
    read_utf8(
      &trust_bundle,
      MAX_TRUST_BUNDLE_BYTES,
      "scheduled_isolation_trust_bundle",
    )?,
  ))
}

fn observed_trust_policy(config: &ScheduledCodexConfig) -> Result<ArtifactTrustPolicy, String> {
  let supplementary_groups =
    getgroups().map_err(|error| format!("read scheduled runtime supplementary groups: {error}"))?;
  trust_policy_for_identity(
    config,
    geteuid().as_raw(),
    getegid().as_raw(),
    &supplementary_groups
      .into_iter()
      .map(nix::unistd::Gid::as_raw)
      .collect::<Vec<_>>(),
  )
}

#[allow(
  clippy::similar_names,
  reason = "uid and gid are distinct security identities checked together"
)]
fn trust_policy_for_identity(
  config: &ScheduledCodexConfig,
  observed_uid: u32,
  observed_gid: u32,
  supplementary_gids: &[u32],
) -> Result<ArtifactTrustPolicy, String> {
  if observed_uid != config.runtime_uid || observed_gid != config.runtime_gid {
    return Err("scheduled_runtime_identity_mismatch".to_owned());
  }
  if config.runtime_uid == config.trusted_owner_uid
    || config.runtime_gid == config.trusted_owner_gid
    || supplementary_gids.contains(&config.trusted_owner_gid)
  {
    return Err("scheduled_runtime_must_not_own_trusted_artifacts".to_owned());
  }
  Ok(ArtifactTrustPolicy {
    trusted_uid: config.trusted_owner_uid,
    trusted_gid: config.trusted_owner_gid,
    runtime_uid: config.runtime_uid,
    runtime_gid: config.runtime_gid,
  })
}

fn verify_scheduled_artifacts_with_policy(
  config: &ScheduledCodexConfig,
  profile: &RequestedCapabilityProfile,
  policy: ArtifactTrustPolicy,
) -> Result<VerifiedScheduledArtifacts, String> {
  let program = open_verified(&profile.codex_program, ArtifactKind::Executable, policy)?;
  verify_digest(
    &program,
    &profile.codex_program_sha256,
    "scheduled_codex_program_digest_mismatch",
  )?;
  let codex_home = open_verified(
    &profile.codex_home,
    ArtifactKind::Directory { immutable: true },
    policy,
  )?;
  let cwd = open_verified(
    &profile.cwd,
    ArtifactKind::Directory { immutable: false },
    policy,
  )?;
  let config_file = open_verified(
    &profile.codex_home.join("config.toml"),
    ArtifactKind::ReadOnlyFile,
    policy,
  )?;
  let config_contents = read_utf8(&config_file, MAX_CONFIG_BYTES, "scheduled_config")?;
  if config_contents != profile.dedicated_config()
    || sha256_hex(config_contents.as_bytes()) != profile.config_sha256
  {
    return Err("scheduled_config_content_mismatch_at_startup".to_owned());
  }
  let github_mcp_artifact = open_verified(
    &config.github_mcp_artifact_path,
    ArtifactKind::Executable,
    policy,
  )?;
  verify_digest(
    &github_mcp_artifact,
    &profile.github_mcp_artifact_sha256,
    "github_mcp_artifact_digest_mismatch_at_startup",
  )?;
  let attestation = open_verified(
    &config.isolation_attestation_path,
    ArtifactKind::ReadOnlyFile,
    policy,
  )?;
  let attestation_contents = read_utf8(
    &attestation,
    MAX_ATTESTATION_BYTES,
    "scheduled_isolation_attestation",
  )?;
  let trust_bundle = open_verified(
    &config.isolation_trust_bundle_path,
    ArtifactKind::ReadOnlyFile,
    policy,
  )?;
  let trust_bundle_contents = read_utf8(
    &trust_bundle,
    MAX_TRUST_BUNDLE_BYTES,
    "scheduled_isolation_trust_bundle",
  )?;
  Ok(VerifiedScheduledArtifacts {
    program,
    codex_home,
    cwd,
    config: config_file,
    github_mcp_artifact,
    attestation,
    attestation_contents,
    trust_bundle,
    trust_bundle_contents,
  })
}

pub(super) fn verify_scheduled_artifacts(
  config: &ScheduledCodexConfig,
  profile: &RequestedCapabilityProfile,
) -> Result<VerifiedScheduledArtifacts, String> {
  verify_scheduled_artifacts_with_policy(config, profile, observed_trust_policy(config)?)
}

#[cfg(test)]
pub(super) fn verify_scheduled_artifacts_for_test(
  config: &ScheduledCodexConfig,
  profile: &RequestedCapabilityProfile,
) -> Result<VerifiedScheduledArtifacts, String> {
  let policy = trust_policy_for_identity(config, config.runtime_uid, config.runtime_gid, &[])?;
  verify_scheduled_artifacts_with_policy(config, profile, policy)
}

#[cfg(test)]
pub(super) fn test_artifacts(
  program: &Path,
  codex_home: &Path,
  cwd: &Path,
) -> VerifiedScheduledArtifacts {
  let program = File::open(program).expect("test program");
  let codex_home = File::open(codex_home).expect("test CODEX_HOME");
  let cwd = File::open(cwd).expect("test cwd");
  let trust_bundle = program.try_clone().expect("test trust bundle placeholder");
  VerifiedScheduledArtifacts {
    config: codex_home.try_clone().expect("test config placeholder"),
    github_mcp_artifact: program.try_clone().expect("test MCP placeholder"),
    attestation: program.try_clone().expect("test attestation placeholder"),
    program,
    codex_home,
    cwd,
    attestation_contents: String::new(),
    trust_bundle,
    trust_bundle_contents: String::new(),
  }
}

fn open_verified(
  path: &Path,
  kind: ArtifactKind,
  policy: ArtifactTrustPolicy,
) -> Result<File, String> {
  if !path.is_absolute() {
    return Err(format!(
      "scheduled_artifact_path_not_absolute:{}",
      path.display()
    ));
  }
  let mut current =
    File::open("/").map_err(|error| format!("open scheduled artifact root: {error}"))?;
  verify_metadata(
    &current,
    ArtifactKind::Directory { immutable: false },
    policy,
    "/",
  )?;
  let components = path
    .components()
    .filter_map(|component| match component {
      Component::RootDir => None,
      Component::Normal(value) => Some(Ok(value)),
      _ => Some(Err(format!(
        "scheduled_artifact_path_component_invalid:{}",
        path.display()
      ))),
    })
    .collect::<Result<Vec<_>, _>>()?;
  if components.is_empty() {
    return Err(format!(
      "scheduled_artifact_path_invalid:{}",
      path.display()
    ));
  }
  for (index, component) in components.iter().enumerate() {
    let final_component = index + 1 == components.len();
    let component_kind = if final_component {
      kind
    } else {
      ArtifactKind::Directory { immutable: false }
    };
    let flags = match component_kind {
      ArtifactKind::Directory { .. } => {
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
      }
      ArtifactKind::ReadOnlyFile | ArtifactKind::Executable => {
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
      }
    };
    let opened = openat(&current, *component, flags, Mode::empty()).map_err(|error| {
      format!(
        "open verified scheduled artifact component {}: {error}",
        component.to_string_lossy()
      )
    })?;
    let opened = File::from(opened);
    verify_metadata(&opened, component_kind, policy, component)?;
    current = opened;
  }
  Ok(current)
}

fn verify_metadata(
  file: &File,
  kind: ArtifactKind,
  policy: ArtifactTrustPolicy,
  name: impl AsRef<OsStr>,
) -> Result<(), String> {
  let stat = fstat(file).map_err(|error| format!("fstat scheduled artifact: {error}"))?;
  let mode = stat.st_mode;
  let label = name.as_ref().to_string_lossy();
  if stat.st_uid != policy.trusted_uid || stat.st_gid != policy.trusted_gid {
    return Err(format!("scheduled_artifact_owner_mismatch:{label}"));
  }
  let file_type = file
    .metadata()
    .map_err(|error| format!("metadata verified scheduled artifact: {error}"))?
    .file_type();
  match kind {
    ArtifactKind::Directory { .. } if !file_type.is_dir() => {
      return Err(format!("scheduled_artifact_not_directory:{label}"));
    }
    ArtifactKind::ReadOnlyFile | ArtifactKind::Executable if !file_type.is_file() => {
      return Err(format!("scheduled_artifact_not_regular_file:{label}"));
    }
    _ => {}
  }
  if file_type.is_symlink() || file_type.is_socket() {
    return Err(format!("scheduled_artifact_special_file_rejected:{label}"));
  }
  if runtime_has(mode, stat.st_uid, stat.st_gid, policy, 0o2) {
    return Err(format!("scheduled_artifact_runtime_writable:{label}"));
  }
  let immutable = matches!(kind, ArtifactKind::ReadOnlyFile | ArtifactKind::Executable)
    || matches!(kind, ArtifactKind::Directory { immutable: true });
  if immutable && mode & 0o222 != 0 {
    return Err(format!("scheduled_artifact_not_immutable:{label}"));
  }
  let required = match kind {
    ArtifactKind::Directory { .. } | ArtifactKind::Executable => 0o1,
    ArtifactKind::ReadOnlyFile => 0o4,
  };
  if !runtime_has(mode, stat.st_uid, stat.st_gid, policy, required) {
    return Err(format!("scheduled_artifact_runtime_access_denied:{label}"));
  }
  Ok(())
}

#[allow(
  clippy::similar_names,
  reason = "uid and gid are distinct security identities checked together"
)]
fn runtime_has(
  mode: u32,
  artifact_uid: u32,
  artifact_gid: u32,
  policy: ArtifactTrustPolicy,
  permission: u32,
) -> bool {
  let shift = if policy.runtime_uid == artifact_uid {
    6
  } else if policy.runtime_gid == artifact_gid {
    3
  } else {
    0
  };
  mode & (permission << shift) != 0
}

#[cfg_attr(
  not(test),
  allow(
    dead_code,
    reason = "production remote backend is intentionally not wired"
  )
)]
fn verify_digest(file: &File, expected: &str, error: &str) -> Result<(), String> {
  let mut file = file
    .try_clone()
    .map_err(|source| format!("clone verified scheduled artifact: {source}"))?;
  file
    .seek(SeekFrom::Start(0))
    .map_err(|source| format!("seek verified scheduled artifact: {source}"))?;
  let mut hasher = Sha256::new();
  let mut buffer = [0_u8; 8 * 1024];
  loop {
    let read = file
      .read(&mut buffer)
      .map_err(|source| format!("hash verified scheduled artifact: {source}"))?;
    if read == 0 {
      break;
    }
    hasher.update(&buffer[..read]);
  }
  if format!("{:x}", hasher.finalize()) != expected {
    return Err(error.to_owned());
  }
  Ok(())
}

fn read_utf8(file: &File, limit: u64, label: &str) -> Result<String, String> {
  let mut file = file
    .try_clone()
    .map_err(|error| format!("clone {label}: {error}"))?;
  file
    .seek(SeekFrom::Start(0))
    .map_err(|error| format!("seek {label}: {error}"))?;
  let mut bytes = Vec::new();
  file
    .take(limit + 1)
    .read_to_end(&mut bytes)
    .map_err(|error| format!("read {label}: {error}"))?;
  if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
    return Err(format!("{label}_too_large"));
  }
  String::from_utf8(bytes).map_err(|_| format!("{label}_not_utf8"))
}

#[cfg_attr(
  not(test),
  allow(
    dead_code,
    reason = "production remote backend is intentionally not wired"
  )
)]
fn sha256_hex(bytes: &[u8]) -> String {
  format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
  use std::fs;
  use std::os::unix::fs::{PermissionsExt, symlink};
  use std::os::unix::io::AsRawFd;

  use tempfile::TempDir;

  use super::*;

  fn policy() -> ArtifactTrustPolicy {
    let root = fstat(File::open("/").expect("root")).expect("root stat");
    ArtifactTrustPolicy {
      trusted_uid: root.st_uid,
      trusted_gid: root.st_gid,
      runtime_uid: root.st_uid.saturating_add(10_000),
      runtime_gid: root.st_gid.saturating_add(10_000),
    }
  }

  fn protected_temp() -> TempDir {
    let temp = TempDir::new_in("/code/helixbox").expect("tempdir");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o555)).expect("protect tempdir");
    temp
  }

  #[test]
  fn final_and_intermediate_symlinks_are_rejected() {
    let temp = protected_temp();
    let target = temp.path().join("target");
    fs::write(&target, "artifact").expect("write target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o444)).expect("protect target");
    let final_link = temp.path().join("final-link");
    symlink(&target, &final_link).expect("final symlink");
    assert!(open_verified(&final_link, ArtifactKind::ReadOnlyFile, policy()).is_err());

    let directory = temp.path().join("directory");
    fs::create_dir(&directory).expect("directory");
    let nested = directory.join("artifact");
    fs::write(&nested, "artifact").expect("nested artifact");
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o444)).expect("protect nested");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o555)).expect("protect directory");
    let directory_link = temp.path().join("directory-link");
    symlink(&directory, &directory_link).expect("directory symlink");
    assert!(
      open_verified(
        &directory_link.join("artifact"),
        ArtifactKind::ReadOnlyFile,
        policy(),
      )
      .is_err()
    );
  }

  #[test]
  fn owner_writable_program_and_runtime_writable_ancestor_are_rejected() {
    let temp = protected_temp();
    let program = temp.path().join("program");
    fs::write(&program, "program").expect("write program");
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("program mode");
    assert!(open_verified(&program, ArtifactKind::Executable, policy()).is_err());

    fs::set_permissions(&program, fs::Permissions::from_mode(0o555)).expect("protect program");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o557)).expect("writable tempdir");
    assert!(open_verified(&program, ArtifactKind::Executable, policy()).is_err());
  }

  #[test]
  fn verified_descriptor_remains_anchored_after_path_replacement() {
    let temp = protected_temp();
    let artifact = temp.path().join("artifact");
    fs::write(&artifact, "trusted").expect("trusted artifact");
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o444)).expect("protect artifact");
    let opened = open_verified(&artifact, ArtifactKind::ReadOnlyFile, policy()).expect("verify");
    let replacement = temp.path().join("replacement");
    fs::write(&replacement, "replacement").expect("replacement");
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o444))
      .expect("protect replacement");
    fs::rename(&replacement, &artifact).expect("replace path");
    assert_eq!(
      read_utf8(&opened, 64, "artifact").expect("read anchored descriptor"),
      "trusted"
    );
  }

  #[test]
  fn wrong_owner_identity_is_rejected() {
    let temp = protected_temp();
    let artifact = temp.path().join("artifact");
    fs::write(&artifact, "artifact").expect("artifact");
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o444)).expect("protect artifact");
    let mut wrong = policy();
    wrong.trusted_uid = wrong.trusted_uid.saturating_add(1);
    assert!(open_verified(&artifact, ArtifactKind::ReadOnlyFile, wrong).is_err());
  }

  #[test]
  fn configured_runtime_identity_must_match_the_observed_process() {
    let config = ScheduledCodexConfig {
      trusted_owner_uid: 0,
      trusted_owner_gid: 0,
      runtime_uid: 65_534,
      runtime_gid: 65_534,
      ..ScheduledCodexConfig::default()
    };
    let Err(error) = trust_policy_for_identity(&config, 0, 0, &[]) else {
      panic!("identity mismatch must fail");
    };
    assert_eq!(error, "scheduled_runtime_identity_mismatch");
    let Err(error) = trust_policy_for_identity(
      &config,
      config.runtime_uid,
      config.runtime_gid,
      &[config.trusted_owner_gid],
    ) else {
      panic!("trusted supplementary group must fail");
    };
    assert_eq!(error, "scheduled_runtime_must_not_own_trusted_artifacts");
  }

  #[test]
  fn digest_uses_verified_inode_after_path_replacement() {
    let temp = protected_temp();
    let artifact = temp.path().join("artifact");
    fs::write(&artifact, "trusted").expect("trusted artifact");
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o444)).expect("protect artifact");
    let opened = open_verified(&artifact, ArtifactKind::ReadOnlyFile, policy()).expect("verify");
    let expected = sha256_hex(b"trusted");
    let replacement = temp.path().join("replacement");
    fs::write(&replacement, "replacement").expect("replacement");
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o444))
      .expect("protect replacement");
    fs::rename(&replacement, &artifact).expect("replace path");
    verify_digest(&opened, &expected, "digest mismatch").expect("anchored digest");
  }

  #[test]
  fn open_file_descriptor_is_not_path_based() {
    let temp = protected_temp();
    let artifact = temp.path().join("artifact");
    fs::write(&artifact, "artifact").expect("artifact");
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o444)).expect("protect artifact");
    let opened = open_verified(&artifact, ArtifactKind::ReadOnlyFile, policy()).expect("verify");
    assert!(opened.as_raw_fd() >= 0);
  }
}
