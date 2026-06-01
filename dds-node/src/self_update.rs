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
};

use dds_domain::types::{DdsSelfUpdateDocument, Platform, PublisherIdentity, UpdateArtifact};
use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tracing::{error, info, warn};

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
    #[cfg(windows)]
    return PathBuf::from(r"C:\ProgramData\DDS\update-cache");
    #[cfg(target_os = "macos")]
    return PathBuf::from("/Library/Application Support/DDS/update-cache");
    #[cfg(not(any(windows, target_os = "macos")))]
    PathBuf::from("/var/cache/dds")
}

/// Download `artifact.url` to `dest`, verifying the SHA-256 in a streaming
/// pass so we never hold the whole blob in memory.
async fn fetch_and_verify(artifact: &UpdateArtifact, dest: &Path) -> Result<(), String> {
    if !artifact.url.starts_with("https://") {
        return Err(format!(
            "self-update: artifact URL must use HTTPS (got {:?})",
            artifact.url
        ));
    }

    let client = reqwest::Client::builder()
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

    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| format!("self-update: could not create staging file: {e}"))?;

    let mut hasher = Sha256::new();
    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| format!("self-update: download stream error: {e}"))?;
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

    if let Some(expected_tp) = root_thumbprint {
        let found = stdout
            .lines()
            .filter_map(|l| l.strip_prefix("THUMBPRINT:"))
            .any(|tp| tp == expected_tp.as_str());
        if !found {
            return Err(format!(
                "self-update: required root thumbprint {expected_tp:?} not found in signer chain"
            ));
        }
    }

    info!(subject = %subject, "self-update: Authenticode signature verified");
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

async fn run_installer(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let path_str = path
            .to_str()
            .ok_or_else(|| "self-update: artifact path not valid UTF-8".to_string())?;
        let status = tokio::process::Command::new("msiexec")
            .args(["/i", path_str, "/quiet", "/norestart"])
            .status()
            .await
            .map_err(|e| format!("self-update: msiexec exec failed: {e}"))?;
        if !status.success() {
            return Err(format!(
                "self-update: msiexec exited with non-zero status ({status})"
            ));
        }
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let status = tokio::process::Command::new("installer")
            .args(["-pkg", path.to_str().unwrap_or_default(), "-target", "/"])
            .status()
            .await
            .map_err(|e| format!("self-update: macOS installer exec failed: {e}"))?;
        if !status.success() {
            return Err(format!(
                "self-update: macOS installer exited with non-zero status ({status})"
            ));
        }
        return Ok(());
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
    async fn apply_update_rejects_http_url() {
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
    async fn apply_update_skips_when_no_artifact_for_platform() {
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
    async fn apply_update_no_concurrent_install() {
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
}
