# Week 1 Threat Model

## Purpose

Sentinel protects AI-agent command execution by deciding whether a proposed command should be allowed, blocked, or paused for human confirmation before it runs.

The first version focuses on local sandbox execution. It is not intended to protect production systems yet.

## What Sentinel Protects

- A local developer machine or sandbox workspace from unexpected destructive commands.
- Agent workflows from prompt-injection-driven tool misuse.
- High-impact outbound actions, such as mass email or messaging, from going to the wrong recipients without confirmation.
- Auditability: every risky command decision should be logged.
- Human control over high-impact actions through confirmation.

## What Sentinel Does Not Protect Yet

- Real production servers.
- Commands run outside Sentinel.
- Malicious users who already control the host machine.
- Docker escape vulnerabilities.
- Perfect detection of every obfuscated attack.

## Core Distinction

Sentinel must distinguish between:

- **Malicious or agent-gone-haywire behavior:** the command conflicts with the user objective, exfiltrates data, steals credentials, destroys unrelated files, escalates privileges, or hides activity.
- **Destructive but authorized behavior:** the command has side effects, but the user clearly requested it, the scope is limited, and the environment is safe.

Example:

- `rm -rf ./dist` during "clean build artifacts" can be allowed in a sandbox.
- `rm -rf ./dist` during "summarize files" is suspicious and should be blocked or confirmed.

## Initial Environments

- `sandbox`: default for v1. Allows scoped destructive work, blocks critical actions.
- `dev`: stricter than sandbox. Destructive commands often require confirmation.
- `production`: simulated only in v1. High-risk actions require confirmation; critical actions block.

## Initial Verdicts

- `allow`: low-risk command that matches the context.
- `warn`: command is allowed but logged as suspicious or moderately risky.
- `confirm_required`: command may be legitimate, but needs explicit human approval.
- `block`: command is too risky or violates policy.

## Initial Risk Categories

- `safe_read_only`
- `safe_build_or_install`
- `authorized_destructive`
- `ambiguous_requires_confirmation`
- `data_exfiltration`
- `credential_theft`
- `privilege_escalation`
- `system_destruction`
- `network_abuse`
- `external_communication`
- `defense_evasion`
- `policy_violation`

## Week 1 Success Criteria

- Define the first supported environment as local sandbox execution.
- Create a small trusted seed dataset that covers the risk categories above.
- Use this seed dataset as a quality check for future benchmark and GPT-generated data.
- Avoid treating command text alone as the label; labels must depend on context.
