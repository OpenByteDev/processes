use std::{
    error::Error,
    path::PathBuf,
    process::{Command, Stdio},
    str::FromStr,
};

pub fn build_test_program_x86() -> Result<PathBuf, Box<dyn Error>> {
    build_helper_crate(
        "test-program",
        Some(&find_x86_variant_of_target()),
        false,
        "exe",
    )
}

pub fn build_test_program_x64() -> Result<PathBuf, Box<dyn Error>> {
    build_helper_crate(
        "test-program",
        Some(&find_x64_variant_of_target()),
        false,
        "exe",
    )
}

fn find_x64_variant_of_target() -> String {
    current_platform::CURRENT_PLATFORM.replace("i686", "x86_64")
}

fn find_x86_variant_of_target() -> String {
    current_platform::CURRENT_PLATFORM.replace("x86_64", "i686")
}

pub fn build_helper_crate(
    crate_name: &str,
    target: Option<&str>,
    release: bool,
    ext: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    let payload_crate_path = PathBuf::from_str(".\\tests\\helpers")?
        .join(crate_name)
        .canonicalize()?;

    let mut command = Command::new("cargo");
    command
        .arg("build")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(target) = target {
        command.arg("--target").arg(target);
    }
    let exit_code = command.current_dir(&payload_crate_path).spawn()?.wait()?;
    assert!(
        exit_code.success(),
        "Failed to build helper crate {} for target {}",
        crate_name,
        target.unwrap_or("default")
    );

    let mut payload_artifact_path = payload_crate_path;
    payload_artifact_path.push("target");

    if let Some(target) = target {
        payload_artifact_path.push(target);
    }

    payload_artifact_path.push(if release { "release" } else { "debug" });
    payload_artifact_path.push(format!("{crate_name}.{ext}"));
    assert!(&payload_artifact_path.exists());

    Ok(payload_artifact_path)
}

#[macro_export]
macro_rules! syringe_test {
    (fn $test_name:ident ($process:ident : OwnedProcess, $payload_path:ident : &Path $(,)?) $body:block) => {
        mod $test_name {
            use super::*;
            use dll_syringe::process::OwnedProcess;
            use std::{
                path::Path,
                process::{Command, Stdio},
            };

            #[test]
            #[cfg(any(
                target_arch = "x86",
                all(target_arch = "x86_64", feature = "into-x86-from-x64")
            ))]
            fn x86() {
                test_with_setup(
                    common::build_test_payload_x86().unwrap(),
                    common::build_test_target_x86().unwrap(),
                )
            }

            #[test]
            #[cfg(target_arch = "x86_64")]
            fn x86_64() {
                test_with_setup(
                    common::build_test_payload_x64().unwrap(),
                    common::build_test_target_x64().unwrap(),
                )
            }

            fn test_with_setup(
                payload_path: impl AsRef<Path>,
                target_path: impl AsRef<Path>,
            ) {
                let dummy_process: OwnedProcess = Command::new(target_path.as_ref())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn().unwrap()
                    .into();

                let _guard = dummy_process.try_clone().unwrap().kill_on_drop();

                test(dummy_process, payload_path.as_ref())
            }

            fn test(
                $process : OwnedProcess,
                $payload_path : &Path,
            ) $body
        }
    };
}

#[macro_export]
macro_rules! process_test {
    (fn $test_name:ident ($process:ident : OwnedProcess $(,)?) $body:block) => {
        mod $test_name {
            use super::*;
            use processes::OwnedProcess;
            use std::{
                path::Path,
                process::{Command, Stdio},
            };

            #[test]
            #[cfg(any(
                target_arch = "x86",
                all(target_arch = "x86_64", feature = "into-x86-from-x64")
            ))]
            fn x86() {
                test_with_setup(
                    common::build_test_program_x86().unwrap(),
                )
            }

            #[test]
            #[cfg(target_arch = "x86_64")]
            fn x86_64() {
                test_with_setup(
                    common::build_test_program_x64().unwrap(),
                )
            }

            fn test_with_setup(
                target_path: impl AsRef<Path>,
            ) {
                let dummy_process: OwnedProcess = Command::new(target_path.as_ref())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap()
                    .into();

                let _guard = dummy_process.try_clone().unwrap().kill_on_drop();

                test(dummy_process)
            }

            fn test(
                $process : OwnedProcess,
            ) $body
        }
    };
}
