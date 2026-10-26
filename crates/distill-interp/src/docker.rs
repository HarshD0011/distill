//! Container requests are effects on a daemon; container paths are not host paths.
use crate::{Analyzer, tooling::literal};
use distill_core::{EffectKind, Severity};
use distill_parse::Word;

impl Analyzer<'_> {
    pub(super) fn docker(&mut self, _name: &str, args: &[Word], depth: usize) {
        if args.len() == 1
            && !args[0].dynamic
            && matches!(args[0].text.as_str(), "--version" | "-v" | "--help")
        {
            self.raise(Severity::Safe);
            return;
        }
        let global = self.tool_options(
            args,
            &[
                "--host",
                "-H",
                "--context",
                "-c",
                "--config",
                "--tlscacert",
                "--tlscert",
                "--tlskey",
            ],
            &["--debug", "-D", "--tls", "--tlsverify"],
            true,
        );
        self.context_partial = true;
        self.unknown(
            "Container daemon identity, configuration, and existing resources are unresolved",
        );
        for value in global.all(&["--tlskey", "--tlscert", "--tlscacert"]) {
            self.read_destination(value);
        }
        if global.has(&["--host", "-H", "--context", "-c"]) {
            self.finding(
                Severity::Medium,
                EffectKind::NetworkSend,
                "docker.daemon",
                "Sends a request to a selected container daemon or remote context",
            );
        }
        let mut args = global.operands.as_slice();
        let Some(first) = args.first() else {
            self.unresolved_program("Container subcommand is missing");
            return;
        };
        if first.dynamic {
            self.unresolved_program("Container operation is dynamic");
            return;
        }
        let group = first.text.as_str();
        if matches!(
            group,
            "container"
                | "image"
                | "volume"
                | "network"
                | "system"
                | "builder"
                | "buildx"
                | "plugin"
                | "compose"
                | "context"
        ) {
            args = &args[1..];
        }
        let Some(sub) = args.first().filter(|arg| !arg.dynamic) else {
            self.unresolved_program("Container operation is unresolved");
            return;
        };
        let sub = sub.text.as_str();
        let rest = &args[1..];
        if group == "compose" {
            self.unresolved_program("Compose files, interpolation, service mounts, and lifecycle operations are unresolved");
            if rest.iter().chain(args.iter()).any(|a| {
                matches!(
                    a.text.as_str(),
                    "down" | "rm" | "kill" | "stop" | "--volumes" | "-v"
                )
            }) {
                self.finding(
                    Severity::High,
                    EffectKind::FileDelete,
                    "docker.compose-remove",
                    "Compose may stop applications or delete their persistent volumes",
                );
            }
            return;
        }
        if group == "plugin" && !matches!(sub, "ls" | "inspect") {
            self.finding(
                Severity::Critical,
                EffectKind::Privilege,
                "docker.plugin",
                "Changes container daemon plugins that can have host privileges",
            );
            self.unresolved_program("Container plugin code and permissions are unresolved");
            return;
        }
        match sub {
            "version" | "info" | "ps" | "ls" | "images" | "inspect" | "logs" | "top" | "stats"
            | "events" | "history" | "df" | "port" => {
                self.finding(
                    Severity::Low,
                    EffectKind::FileRead,
                    "docker.query",
                    "Queries container daemon state, metadata, or logs",
                );
            }
            "run" | "create" | "exec" => {
                let opts = self.tool_options(
                    rest,
                    &[
                        "--volume",
                        "-v",
                        "--mount",
                        "--volumes-from",
                        "--device",
                        "--cap-add",
                        "--cap-drop",
                        "--security-opt",
                        "--pid",
                        "--network",
                        "--net",
                        "--ipc",
                        "--userns",
                        "--entrypoint",
                        "--env",
                        "-e",
                        "--env-file",
                        "--publish",
                        "-p",
                        "--user",
                        "-u",
                        "--workdir",
                        "-w",
                        "--name",
                        "--restart",
                        "--hostname",
                        "-h",
                        "--memory",
                        "-m",
                        "--cpus",
                        "--label",
                        "-l",
                        "--pull",
                        "--runtime",
                    ],
                    &[
                        "--privileged",
                        "--rm",
                        "--read-only",
                        "--detach",
                        "-d",
                        "--interactive",
                        "-i",
                        "--tty",
                        "-t",
                        "--init",
                        "--publish-all",
                        "-P",
                    ],
                    true,
                );
                self.unresolved_program(
                    "Container image, entrypoint, and executed code are unresolved",
                );
                for (name, value) in &opts.values {
                    if (name == "--privileged"
                        && value
                            .as_ref()
                            .is_some_and(|v| !v.dynamic && v.text == "false"))
                        || (name == "--security-opt"
                            && value.as_ref().is_some_and(|v| {
                                !v.dynamic
                                    && matches!(
                                        v.text.as_str(),
                                        "no-new-privileges" | "no-new-privileges=true"
                                    )
                            }))
                    {
                        continue;
                    }
                    match name.as_str() {
                        "--privileged" | "--device" | "--cap-add" | "--security-opt" | "--runtime" => self.finding(Severity::Critical, EffectKind::Privilege, "docker.host-privilege", "Container can gain host devices, elevated capabilities, or weakened isolation"),
                        "--pid" | "--network" | "--net" | "--ipc" | "--userns" if value.as_ref().is_some_and(|v| v.text == "host" || v.dynamic) => self.finding(Severity::High, EffectKind::Privilege, "docker.host-namespace", "Container shares a host namespace"),
                        "--volume" | "-v" => if let Some(value) = value { self.docker_mount(value, false); },
                        "--mount" => if let Some(value) = value { self.docker_mount(value, true); },
                        "--env-file" => if let Some(value) = value { self.read_destination(value); },
                        "--publish" | "-p" | "--publish-all" | "-P" => self.finding(Severity::High, EffectKind::NetworkSend, "docker.publish", "Publishes a container service through the host network"),
                        "--restart" => self.finding(Severity::High, EffectKind::Persistence, "docker.restart", "Configures automatic container restart"),
                        _ => {}
                    }
                }
            }
            "build" => {
                let opts = self.tool_options(
                    rest,
                    &[
                        "-f",
                        "--file",
                        "-t",
                        "--tag",
                        "--build-arg",
                        "--secret",
                        "--ssh",
                        "--output",
                        "-o",
                        "--network",
                        "--target",
                        "--platform",
                        "--progress",
                        "--builder",
                        "--cache-from",
                        "--cache-to",
                    ],
                    &["--pull", "--no-cache", "--load", "--push", "--quiet", "-q"],
                    false,
                );
                self.unresolved_program("Container builds execute build instructions and may access secrets or external contexts");
                for value in opts.all(&["--output", "-o"]) {
                    self.write_destination(value, true);
                }
                if opts.has(&["--secret", "--ssh"]) {
                    self.finding(
                        Severity::High,
                        EffectKind::FileRead,
                        "docker.build-secret",
                        "Exposes build credentials or an SSH agent to build instructions",
                    );
                }
                let contexts = &opts.operands;
                let context = contexts
                    .last()
                    .filter(|v| !v.dynamic && !v.text.contains("://") && v.text != "-");
                let file = opts
                    .all(&["-f", "--file"])
                    .last()
                    .cloned()
                    .or_else(|| context.map(|v| literal(format!("{}/Dockerfile", v.text))));
                if let Some(file) = file {
                    self.artifact_file("dockerfile", &file, depth);
                }
            }
            "rm" | "rmi" | "prune" | "remove" => self.finding(
                Severity::High,
                EffectKind::FileDelete,
                "docker.remove",
                "Deletes containers, images, caches, networks, or persistent volumes",
            ),
            "stop" | "kill" | "restart" | "pause" | "unpause" | "start" | "update" => self.finding(
                Severity::High,
                EffectKind::Persistence,
                "docker.lifecycle",
                "Changes availability or configuration of containerized applications",
            ),
            "pull" | "load" | "import" => {
                self.finding(
                    Severity::High,
                    EffectKind::FileWrite,
                    "docker.image-install",
                    "Installs or replaces executable container images",
                );
                self.finding(
                    Severity::Medium,
                    EffectKind::NetworkReceive,
                    "docker.image-source",
                    "Container image contents come from an external source or input stream",
                );
            }
            "push" | "login" => self.finding(
                Severity::High,
                EffectKind::NetworkSend,
                "docker.credentials-or-push",
                "Sends image data or authentication information to a registry",
            ),
            "logout" => self.finding(
                Severity::Medium,
                EffectKind::FileWrite,
                "docker.logout",
                "Removes stored registry authentication",
            ),
            "cp" => {
                let opts = self.tool_options(
                    rest,
                    &[],
                    &["-a", "--archive", "-L", "--follow-link"],
                    false,
                );
                if let [from, to] = opts.operands.as_slice() {
                    if !from.text.contains(':') && from.text != "-" {
                        self.read_destination(from);
                    }
                    if !to.text.contains(':') && to.text != "-" {
                        self.write_destination(to, true);
                    }
                    self.finding(
                        Severity::Medium,
                        EffectKind::FileWrite,
                        "docker.copy",
                        "Copies data between the host and a container",
                    );
                } else {
                    self.unknown("Container copy operands are unresolved");
                }
            }
            _ => self.unresolved_program("Container subcommand or plugin behavior is not modeled"),
        }
    }

    fn docker_mount(&mut self, word: &Word, structured: bool) {
        let (source, readonly) = if structured {
            let parts: Vec<_> = word.text.split(',').collect();
            let source = parts
                .iter()
                .find_map(|s| s.strip_prefix("src=").or_else(|| s.strip_prefix("source=")));
            let bind = parts.contains(&"type=bind");
            if !bind {
                self.unknown("Container volume source is managed by the daemon");
                return;
            }
            (
                source,
                parts
                    .iter()
                    .any(|s| matches!(*s, "readonly" | "ro" | "readonly=true" | "ro=true")),
            )
        } else {
            let parts: Vec<_> = word.text.split(':').collect();
            (
                parts
                    .first()
                    .copied()
                    .filter(|s| s.starts_with('/') || s.starts_with('.')),
                parts
                    .get(2)
                    .is_some_and(|s| s.split(',').any(|s| s == "ro")),
            )
        };
        let Some(source) = source else {
            self.unknown("Container mount host source is unresolved");
            return;
        };
        let mut target = word.clone();
        target.text = source.into();
        self.read_destination(&target);
        if !readonly {
            self.write_destination(&target, true);
        }
        if source.ends_with(".sock") || source == "/" || source.starts_with("/dev/") {
            self.finding(
                Severity::Critical,
                EffectKind::Privilege,
                "docker.host-control",
                "Exposes a host control socket, device, or root filesystem to a container",
            );
        }
    }
}
