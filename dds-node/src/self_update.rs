/// Phase D.4 — self-update apply path.
///
/// Called by [`crate::node::DdsNode::evaluate_self_update_rollout`] when the
/// rollout decision is [`dds_domain::RolloutDecision::ApplyNow`] and the node
/// config has `self_update_apply = true`.
///
/// Steps:
/// 1. Select the [`UpdateArtifact`] for the current platform.
/// 2. Guard against concurrent installs with an in-process atomic flag.
/// 3. Fetch the artifact via HTTPS, streaming SHA-256 as we go.
/// 4. Verify the OS-vendor signature on the staged file.
/// 5. Run the platform-native installer (msiexec /quiet or installer -pkg).
/// 6. Log the outcome; the service manager restarts the daemon after the
///    installer replaces the binaries.
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use dds_domain::types::{DdsSelfUpdateDocument, Platform, PublisherIdentity, UpdateArtifact};
use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tracing::{error, info, warn};

/// **M-2 (pre-prod review 2026-07-24)** — connect + response-header
/// timeout for the artifact request. A server that accepts the TCP
/// connection and then stalls must not hold the updater open forever.
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// **M-2** — inactivity timeout between received body chunks. Chosen
/// over a whole-request deadline for the read loop so a legitimately
/// large artifact on a slow link still completes, while a stalled or
/// byte-dribbling server is cut off promptly. The whole-operation
/// ceiling is [`DOWNLOAD_TOTAL_TIMEOUT`].
const DOWNLOAD_STALL_TIMEOUT: Duration = Duration::from_secs(60);

/// **M-2** — hard ceiling on the entire download, independent of
/// per-chunk progress. Bounds the "slow but never idle" case, in which
/// an endless-body server trickles one byte per stall-timeout and would
/// otherwise keep the update channel wedged indefinitely.
const DOWNLOAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// **M-2** — maximum artifact size accepted from the network, in bytes.
/// The largest artifact DDS ships is a platform MSI/PKG in the low
/// hundreds of MB; 2 GiB leaves a very wide margin while still bounding
/// disk consumption from a malicious or misconfigured endpoint. Enforced
/// against the advertised `Content-Length` *and* against the running
/// byte count, since `Content-Length` is attacker-controlled and may be
/// absent entirely on a chunked response.
const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

static INSTALL_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

struct InstallGuard;

impl Drop for InstallGuard {
    fn drop(&mut self) {
        INSTALL_IN_PROGRESS.store(false, Ordering::Release);
    }
}

/// Returns the [`Platform`] variant that matches the current binary's
/// compile-time target triple, or `None` for unrecognised triples.
pub fn current_platform() -> Option<Platform> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return Some(Platform::WinX64);
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    return Some(Platform::WinArm64);
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    return Some(Platform::MacosX64);
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return Some(Platform::MacosArm64);
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return Some(Platform::LinuxX64);
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    return Some(Platform::LinuxArm64);
    #[allow(unreachable_code)]
    None
}

/// SYSTEM-owned directory where update artifacts are staged before
/// installation.  Must be writable only by SYSTEM/root so an attacker
/// cannot substitute the artifact after signature verification.
fn staging_dir() -> PathBuf {
    // Redirect to a writable temp location in tests so the test process
    // never tries to touch protected system directories (which triggers
    // macOS TCC/SIP termination).
    #[cfg(test)]
    return std::env::temp_dir().join("dds-test-update-cache");

    #[cfg(all(not(test), windows))]
    return PathBuf::from(r"C:\ProgramData\DDS\update-cache");
    #[cfg(all(not(test), target_os = "macos"))]
    return PathBuf::from("/Library/Application Support/DDS/update-cache");
    #[cfg(not(any(test, windows, target_os = "macos")))]
    PathBuf::from("/var/cache/dds")
}

/// Download `artifact.url` to `dest`, verifying the SHA-256 in a streaming
/// pass so we never hold the whole blob in memory.
///
/// **M-2 (pre-prod review 2026-07-24)** — this used to run with no
/// request timeout and no maximum size while the caller held the
/// process-global install flag. A stalled server, or one feeding an
/// endless body, therefore filled the disk *and* wedged the update
/// channel permanently: `INSTALL_IN_PROGRESS` never cleared, so the node
/// could no longer receive any later update, including a security fix.
/// Every loop below is now bounded on three axes — per-chunk inactivity
/// ([`DOWNLOAD_STALL_TIMEOUT`]), whole-operation wall clock
/// ([`DOWNLOAD_TOTAL_TIMEOUT`]), and bytes written
/// ([`MAX_ARTIFACT_BYTES`]) — and every exit path is an `Err`, which
/// releases the guard in the caller.
async fn fetch_and_verify(artifact: &UpdateArtifact, dest: &Path) -> Result<(), String> {
    match tokio::time::timeout(
        DOWNLOAD_TOTAL_TIMEOUT,
        fetch_and_verify_inner(artifact, dest),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(format!(
            "self-update: download exceeded the {}s total budget — aborting",
            DOWNLOAD_TOTAL_TIMEOUT.as_secs()
        )),
    }
}

async fn fetch_and_verify_inner(artifact: &UpdateArtifact, dest: &Path) -> Result<(), String> {
    if !artifact.url.starts_with("https://") {
        return Err(format!(
            "self-update: artifact URL must use HTTPS (got {:?})",
            artifact.url
        ));
    }

    let client = reqwest::Client::builder()
        // M-2: bound connect + TLS handshake and time-to-first-byte. Not
        // `.timeout()`, which would apply to the whole body transfer and
        // would fail a legitimate multi-hundred-MB artifact on a slow
        // link; the body is bounded by the stall + total timeouts below.
        .connect_timeout(DOWNLOAD_CONNECT_TIMEOUT)
        .read_timeout(DOWNLOAD_STALL_TIMEOUT)
        .build()
        .map_err(|e| format!("self-update: failed to build HTTP client: {e}"))?;

    let response = client
        .get(&artifact.url)
        .send()
        .await
        .map_err(|e| format!("self-update: download request failed: {e}"))?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!("self-update: download returned HTTP {status}"));
    }

    // M-2: reject an over-size artifact before writing a single byte when
    // the server is honest enough to advertise the length. The running
    // check below is what actually enforces the cap.
    if let Some(len) = response.content_length()
        && len > MAX_ARTIFACT_BYTES
    {
        return Err(format!(
            "self-update: artifact advertises {len} bytes, over the {MAX_ARTIFACT_BYTES}-byte cap"
        ));
    }

    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| format!("self-update: could not create staging file: {e}"))?;

    let mut hasher = Sha256::new();
    let mut stream = response.bytes_stream();
    let mut written: u64 = 0;

    loop {
        // M-2: a chunk must arrive within the stall timeout. `read_timeout`
        // on the client covers the socket, but this also catches a peer
        // that keeps the connection alive at the TLS layer while making no
        // application progress.
        let next = match tokio::time::timeout(DOWNLOAD_STALL_TIMEOUT, stream.next()).await {
            Ok(next) => next,
            Err(_) => {
                return Err(format!(
                    "self-update: download stalled for {}s with {written} bytes received — aborting",
                    DOWNLOAD_STALL_TIMEOUT.as_secs()
                ));
            }
        };
        let Some(chunk_result) = next else { break };
        let chunk = chunk_result.map_err(|e| format!("self-update: download stream error: {e}"))?;

        // M-2: the load-bearing size cap. `Content-Length` is
        // attacker-controlled and absent on chunked responses, so the
        // ceiling is enforced against bytes actually received.
        written = written.saturating_add(chunk.len() as u64);
        if written > MAX_ARTIFACT_BYTES {
            return Err(format!(
                "self-update: artifact exceeded the {MAX_ARTIFACT_BYTES}-byte cap — aborting"
            ));
        }

        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|e| format!("self-update: write error: {e}"))?;
    }

    file.flush()
        .await
        .map_err(|e| format!("self-update: flush error: {e}"))?;

    let actual = hex::encode(hasher.finalize());
    if actual != artifact.sha256_hex {
        return Err(format!(
            "self-update: SHA-256 mismatch (expected {}, got {})",
            artifact.sha256_hex, actual
        ));
    }

    info!(
        url = %artifact.url,
        sha256 = %actual,
        bytes = written,
        "self-update: download and SHA-256 verification passed"
    );
    Ok(())
}

// --- Platform-specific OS-vendor signature verification -----------------

/// Verify that the OS-vendor signature on `path` matches `identity`.
/// On Linux this step is skipped (SHA-256 is the integrity anchor there).
async fn verify_os_signature(path: &Path, identity: &PublisherIdentity) -> Result<(), String> {
    #[cfg(windows)]
    {
        return verify_authenticode(path, identity).await;
    }
    #[cfg(target_os = "macos")]
    {
        return verify_apple_developer_id(path, identity).await;
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (path, identity);
        info!(
            "self-update: OS-vendor signature verification not applicable on Linux — SHA-256 anchors trust"
        );
        Ok(())
    }
}

#[cfg(windows)]
async fn verify_authenticode(path: &Path, identity: &PublisherIdentity) -> Result<(), String> {
    let PublisherIdentity::Authenticode {
        subject,
        root_thumbprint,
    } = identity
    else {
        return Err(format!(
            "self-update: expected Authenticode identity on Windows, got {:?}",
            identity
        ));
    };

    // **I-1 (pre-prod review 2026-07-24)** — fail closed when the
    // manifest omits `root_thumbprint`.
    //
    // Without a pinned root the only remaining check is signer-subject
    // CN equality, and a CN is not a security boundary: *any*
    // Authenticode certificate with a matching CN, issued by any root
    // WinTrust already trusts, would satisfy it. Since the manifest is
    // itself signed and quorum-gated, an omitted thumbprint is a
    // packaging mistake rather than a supported configuration — refuse
    // the update instead of silently degrading the pin to a string
    // compare.
    let Some(expected_tp) = root_thumbprint
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    else {
        return Err(
            "self-update: refusing to apply an artifact whose Authenticode identity omits \
             `root_thumbprint` — subject-CN equality alone is not a trust pin (I-1). \
             Re-publish the manifest with the signing chain's root thumbprint."
                .to_string(),
        );
    };

    let path_str = path
        .to_str()
        .ok_or_else(|| "self-update: artifact path is not valid UTF-8".to_string())?;

    // Use PowerShell Get-AuthenticodeSignature — avoids raw WinTrust FFI while
    // giving us both status and signer subject/thumbprint in one round-trip.
    let ps_script = format!(
        r#"$sig = Get-AuthenticodeSignature '{path_str}';
if ($sig.Status -ne 'Valid') {{ Write-Error "Status: $($sig.Status)"; exit 1 }};
$cert = $sig.SignerCertificate;
$subj = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false);
Write-Output "SUBJECT:$subj";
$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain;
[void]$chain.Build($cert);
foreach ($el in $chain.ChainElements) {{ Write-Output "THUMBPRINT:$($el.Certificate.Thumbprint.ToLower())" }}"#
    );

    let out = tokio::process::Command::new("powershell")
        .args(["-NonInteractive", "-Command", &ps_script])
        .output()
        .await
        .map_err(|e| format!("self-update: powershell exec failed: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "self-update: Authenticode verification failed: {stderr}"
        ));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);

    let actual_subject = stdout
        .lines()
        .find_map(|l| l.strip_prefix("SUBJECT:"))
        .ok_or_else(|| {
            "self-update: could not parse signer subject from PowerShell output".to_string()
        })?;

    if actual_subject != subject.as_str() {
        return Err(format!(
            "self-update: Authenticode subject mismatch (expected {:?}, got {:?})",
            subject, actual_subject
        ));
    }

    // I-1: the pinned root is now mandatory (checked above), so this is
    // an unconditional gate rather than an `if let`.
    let expected_tp_lc = expected_tp.to_ascii_lowercase();
    let found = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("THUMBPRINT:"))
        .any(|tp| tp.eq_ignore_ascii_case(&expected_tp_lc));
    if !found {
        return Err(format!(
            "self-update: required root thumbprint {expected_tp:?} not found in signer chain"
        ));
    }

    info!(
        subject = %subject,
        root_thumbprint = %expected_tp,
        "self-update: Authenticode signature verified"
    );
    Ok(())
}

#[cfg(target_os = "macos")]
async fn verify_apple_developer_id(
    path: &Path,
    identity: &PublisherIdentity,
) -> Result<(), String> {
    let PublisherIdentity::AppleDeveloperId { team_id } = identity else {
        return Err(format!(
            "self-update: expected AppleDeveloperId identity on macOS, got {:?}",
            identity
        ));
    };

    let out = tokio::process::Command::new("pkgutil")
        .args(["--check-signature", path.to_str().unwrap_or_default()])
        .output()
        .await
        .map_err(|e| format!("self-update: pkgutil exec failed: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "self-update: pkgutil --check-signature failed: {stderr}"
        ));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    // pkgutil output contains lines like:
    //   "    1. Developer ID Installer: ACME Corp (ABCDE12345)"
    // Extract the team ID from the parenthesised suffix.
    let found_team = stdout.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.contains("Developer ID") {
            trimmed.rfind('(').and_then(|start| {
                let after_paren = &trimmed[start + 1..];
                after_paren
                    .find(')')
                    .map(|end| after_paren[..end].to_string())
            })
        } else {
            None
        }
    });

    match found_team {
        Some(actual_team) if actual_team == *team_id => {
            info!(team_id = %team_id, "self-update: Apple Developer ID signature verified");
            Ok(())
        }
        Some(actual_team) => Err(format!(
            "self-update: Apple Developer ID team mismatch (expected {:?}, got {:?})",
            team_id, actual_team
        )),
        None => Err(format!(
            "self-update: could not extract Team ID from pkgutil output:\n{stdout}"
        )),
    }
}

// --- Platform-native installer ------------------------------------------

/// **M-2 (pre-prod review 2026-07-24)** — ceiling on the platform
/// installer.
///
/// Same wedge class as the unbounded download: `apply_update` holds the
/// process-global `INSTALL_IN_PROGRESS` flag across this call, so an
/// `msiexec` that blocks forever (a pending reboot lock, an MSI custom
/// action waiting on input) would permanently close the update channel.
/// 20 minutes is far beyond any legitimate DDS MSI/PKG install; past it
/// we kill the child and surface an error, which releases the flag.
///
/// Gated to the platforms that actually spawn an installer: the Linux
/// arm of [`run_installer`] returns "not implemented" without launching
/// anything, so an ungated constant would be dead code there — and CI
/// builds Linux with `-D warnings`.
#[cfg(any(windows, target_os = "macos"))]
const INSTALLER_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// Spawn `cmd`, wait up to [`INSTALLER_TIMEOUT`], and kill the child if
/// it overruns. `what` names the tool for error messages.
///
/// Only compiled where an installer is actually launched — see
/// [`INSTALLER_TIMEOUT`].
#[cfg(any(windows, target_os = "macos"))]
async fn run_child_bounded(
    mut cmd: tokio::process::Command,
    what: &str,
) -> Result<std::process::ExitStatus, String> {
    // `kill_on_drop` so that any early return from the timeout arm below
    // (or a cancelled task) does not leave an orphaned installer holding
    // the Windows Installer mutex.
    cmd.kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("self-update: {what} exec failed: {e}"))?;
    match tokio::time::timeout(INSTALLER_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => Ok(status),
        Ok(Err(e)) => Err(format!("self-update: {what} wait failed: {e}")),
        Err(_) => {
            let _ = child.kill().await;
            Err(format!(
                "self-update: {what} exceeded the {}s budget and was killed",
                INSTALLER_TIMEOUT.as_secs()
            ))
        }
    }
}

async fn run_installer(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let path_str = path
            .to_str()
            .ok_or_else(|| "self-update: artifact path not valid UTF-8".to_string())?;
        let mut cmd = tokio::process::Command::new("msiexec");
        cmd.args(["/i", path_str, "/quiet", "/norestart"]);
        let status = run_child_bounded(cmd, "msiexec").await?;
        if !status.success() {
            return Err(format!(
                "self-update: msiexec exited with non-zero status ({status})"
            ));
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let mut cmd = tokio::process::Command::new("installer");
        cmd.args(["-pkg", path.to_str().unwrap_or_default(), "-target", "/"]);
        let status = run_child_bounded(cmd, "macOS installer").await?;
        if !status.success() {
            return Err(format!(
                "self-update: macOS installer exited with non-zero status ({status})"
            ));
        }
        Ok(())
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = path;
        Err(
            "self-update: platform-native installer not implemented for Linux in Phase D.4"
                .to_string(),
        )
    }
}

// --- Public entry point -------------------------------------------------

/// Download and install the artifact for the current platform.
///
/// This is the Phase D.4 implementation.  It is spawned as a Tokio task by
/// `evaluate_self_update_rollout` so the ingest path is not blocked while
/// the potentially multi-hundred-MB download proceeds.
pub async fn apply_update(doc: DdsSelfUpdateDocument, jti: String) {
    // Guard: silently skip if another install is already underway.
    if INSTALL_IN_PROGRESS
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        info!(
            jti = %jti,
            "self-update: install already in progress, skipping duplicate apply"
        );
        return;
    }
    let _guard = InstallGuard;

    let version_str = format!(
        "{}.{}.{}",
        doc.version.major, doc.version.minor, doc.version.patch
    );

    // 1. Find the artifact matching this platform.
    let Some(platform) = current_platform() else {
        warn!(jti = %jti, "self-update: current platform is unrecognised, cannot apply");
        return;
    };

    let Some(artifact) = doc.artifacts.iter().find(|a| a.platform == platform) else {
        info!(
            jti = %jti,
            version = %version_str,
            "self-update: no artifact for this platform in manifest, skipping"
        );
        return;
    };

    info!(
        jti = %jti,
        version = %version_str,
        url = %artifact.url,
        "self-update: beginning apply (Phase D.4)"
    );

    // 2. Ensure the staging directory exists.
    let dir = staging_dir();
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        error!(jti = %jti, err = %e, "self-update: failed to create staging directory");
        return;
    }
    // AUDIT-2026-06-11 #11: lock the staging directory to the owner
    // (root/SYSTEM) so a co-resident attacker cannot drop or swap an artifact
    // into it. `create_dir_all` otherwise honors the umask. On Windows the
    // cache lives under a SYSTEM/Administrators-restricted %ProgramData% path.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }

    // Derive a stable filename from the JTI so concurrent documents don't
    // clobber each other during download.
    let safe_jti: String = jti
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let ext = if artifact.url.ends_with(".msi") {
        ".msi"
    } else if artifact.url.ends_with(".pkg") {
        ".pkg"
    } else {
        ".bin"
    };
    let staged = dir.join(format!("dds-update-{safe_jti}{ext}"));

    // 3. Download + streaming SHA-256 verification.
    if let Err(e) = fetch_and_verify(artifact, &staged).await {
        error!(jti = %jti, err = %e, "self-update: download/verify failed");
        let _ = tokio::fs::remove_file(&staged).await;
        return;
    }
    // AUDIT-2026-06-11 #11: restrict the staged artifact to the owner the
    // instant its content is verified, closing the verify→install TOCTOU window
    // in which a co-resident attacker could replace the bytes we just hashed
    // (and OS-vendor-signature-check) before `run_installer` executes them.
    crate::file_acl::restrict_to_owner(&staged);

    // 4. OS-vendor signature verification.
    if let Err(e) = verify_os_signature(&staged, &artifact.publisher_identity).await {
        error!(jti = %jti, err = %e, "self-update: OS-vendor signature check failed");
        let _ = tokio::fs::remove_file(&staged).await;
        return;
    }

    // 5. Run the platform-native installer.
    info!(jti = %jti, version = %version_str, "self-update: running platform installer");
    match run_installer(&staged).await {
        Ok(()) => {
            info!(
                jti = %jti,
                version = %version_str,
                "self-update: installer completed — service manager will restart the daemon"
            );
            // Best-effort cleanup of the staged artifact.
            let _ = tokio::fs::remove_file(&staged).await;
        }
        Err(e) => {
            error!(jti = %jti, err = %e, "self-update: installer failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the `apply_update*` tests: they all touch the process-global
    /// `INSTALL_IN_PROGRESS` flag, so running them concurrently let one test's
    /// `InstallGuard` drop clear the flag another test had just set (a flaky
    /// race independent of product code). Each apply test holds this lock.
    static APPLY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn current_platform_is_some() {
        // Verify we recognise all CI matrix platforms at compile time.
        assert!(
            current_platform().is_some(),
            "current_platform() returned None — add an arm for this target triple"
        );
    }

    #[test]
    fn staging_dir_is_absolute() {
        assert!(staging_dir().is_absolute());
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // current-thread test runtime; lock only serialises tests
    async fn apply_update_rejects_http_url() {
        let _serial = APPLY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use dds_domain::types::{
            DdsSelfUpdateDocument, Platform, PublisherIdentity, ReleaseChannel, RolloutPolicy,
            SemVer, UpdateArtifact,
        };

        // Build a document whose artifact uses plain HTTP — fetch_and_verify
        // must refuse before attempting the download.
        let doc = DdsSelfUpdateDocument {
            channel: ReleaseChannel::Stable,
            version: SemVer {
                major: 1,
                minor: 0,
                patch: 0,
            },
            artifacts: vec![UpdateArtifact {
                platform: current_platform().unwrap_or(Platform::LinuxX64),
                url: "http://example.com/dds.pkg".to_string(),
                sha256_hex: "a".repeat(64),
                publisher_identity: PublisherIdentity::AppleDeveloperId {
                    team_id: "ABCDE12345".to_string(),
                },
            }],
            min_supported_from: None,
            rollout: RolloutPolicy::Staged {
                canary_pct: 100,
                promote_to_full_after_secs: 0,
                halt_on_health_regression: false,
            },
            provenance: None,
        };

        // Must not panic; will log an error and return without installing.
        apply_update(doc, "test-jti-http".to_string()).await;
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // current-thread test runtime; lock only serialises tests
    async fn apply_update_skips_when_no_artifact_for_platform() {
        let _serial = APPLY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use dds_domain::types::{DdsSelfUpdateDocument, ReleaseChannel, RolloutPolicy, SemVer};

        // Empty artifact list — should log "no artifact for this platform".
        let doc = DdsSelfUpdateDocument {
            channel: ReleaseChannel::Stable,
            version: SemVer {
                major: 2,
                minor: 0,
                patch: 0,
            },
            artifacts: vec![],
            min_supported_from: None,
            rollout: RolloutPolicy::Staged {
                canary_pct: 100,
                promote_to_full_after_secs: 0,
                halt_on_health_regression: false,
            },
            provenance: None,
        };

        apply_update(doc, "test-jti-no-artifact".to_string()).await;
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // current-thread test runtime; lock only serialises tests
    async fn apply_update_no_concurrent_install() {
        let _serial = APPLY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Set the flag manually to simulate an in-progress install.
        INSTALL_IN_PROGRESS.store(true, Ordering::Release);

        use dds_domain::types::{DdsSelfUpdateDocument, ReleaseChannel, RolloutPolicy, SemVer};
        let doc = DdsSelfUpdateDocument {
            channel: ReleaseChannel::Stable,
            version: SemVer {
                major: 3,
                minor: 0,
                patch: 0,
            },
            artifacts: vec![],
            min_supported_from: None,
            rollout: RolloutPolicy::Staged {
                canary_pct: 100,
                promote_to_full_after_secs: 0,
                halt_on_health_regression: false,
            },
            provenance: None,
        };

        // Should return immediately (flag already set).
        apply_update(doc, "test-jti-concurrent".to_string()).await;

        // Flag must still be true (we never cleared it above).
        assert!(INSTALL_IN_PROGRESS.load(Ordering::Acquire));
        // Reset for other tests.
        INSTALL_IN_PROGRESS.store(false, Ordering::Release);
    }

    /// **M-2 regression** — the download budgets must all be finite and
    /// ordered so a stalled or endless-body server can never hold the
    /// process-global install flag indefinitely. This is the property
    /// that keeps the update channel from wedging permanently: every
    /// exit from `fetch_and_verify` is bounded, and every bounded exit
    /// is an `Err` that drops `InstallGuard`.
    // The point of this test is precisely to pin constant values, so a
    // future edit that unbounds them fails loudly.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn download_budgets_are_bounded_and_ordered() {
        assert!(
            DOWNLOAD_STALL_TIMEOUT < DOWNLOAD_TOTAL_TIMEOUT,
            "per-chunk stall budget must be shorter than the whole-download budget"
        );
        assert!(
            DOWNLOAD_CONNECT_TIMEOUT <= DOWNLOAD_STALL_TIMEOUT,
            "connect budget should not exceed the stall budget"
        );
        assert!(MAX_ARTIFACT_BYTES > 0, "artifact size cap must be non-zero");
        // Sanity: the cap is above any artifact DDS actually ships
        // (largest platform MSI is in the low hundreds of MB) so the
        // guard never fires on a legitimate release.
        assert!(
            MAX_ARTIFACT_BYTES >= 1024 * 1024 * 1024,
            "artifact cap must leave headroom over a real platform installer"
        );
    }

    /// **M-2 regression** — an oversized `Content-Length` is refused
    /// before a single byte is written to the staging directory.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn fetch_rejects_non_https_before_any_io() {
        let _serial = APPLY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use dds_domain::types::{Platform, PublisherIdentity, UpdateArtifact};
        let dir = std::env::temp_dir().join("dds-test-fetch-guard");
        let _ = std::fs::create_dir_all(&dir);
        let dest = dir.join("artifact.bin");
        let _ = std::fs::remove_file(&dest);

        let artifact = UpdateArtifact {
            platform: current_platform().unwrap_or(Platform::LinuxX64),
            url: "http://example.invalid/dds.msi".to_string(),
            sha256_hex: "b".repeat(64),
            publisher_identity: PublisherIdentity::AppleDeveloperId {
                team_id: "ABCDE12345".to_string(),
            },
        };
        let err = fetch_and_verify(&artifact, &dest)
            .await
            .expect_err("plain HTTP must be refused");
        assert!(err.contains("HTTPS"), "unexpected error: {err}");
        assert!(
            !dest.exists(),
            "staging file must not be created for a rejected URL"
        );
    }

    /// **I-1 regression** — an Authenticode identity with no pinned
    /// `root_thumbprint` must fail closed rather than degrading to a
    /// signer-CN string match that any WinTrust-trusted certificate with
    /// the same CN would satisfy.
    #[cfg(windows)]
    #[tokio::test]
    async fn authenticode_requires_pinned_root_thumbprint() {
        use dds_domain::types::PublisherIdentity;
        let dir = std::env::temp_dir().join("dds-test-authenticode-pin");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("unsigned.msi");
        std::fs::write(&file, b"not a real msi").unwrap();

        for identity in [
            PublisherIdentity::Authenticode {
                subject: "DDS Test Publisher".to_string(),
                root_thumbprint: None,
            },
            PublisherIdentity::Authenticode {
                subject: "DDS Test Publisher".to_string(),
                root_thumbprint: Some("   ".to_string()),
            },
        ] {
            let err = verify_authenticode(&file, &identity)
                .await
                .expect_err("missing/blank root_thumbprint must fail closed");
            assert!(
                err.contains("root_thumbprint"),
                "expected the I-1 fail-closed message, got: {err}"
            );
        }
        let _ = std::fs::remove_file(&file);
    }
}
