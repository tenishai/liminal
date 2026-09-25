# Security policy

## Reporting a vulnerability

Please don't open a public issue for a security problem.

Report it privately to **security@tenish.ai**.

If this repository's **Security** tab shows a **Report a vulnerability**
button, you can use that instead. GitHub offers it only on public
repositories where it has been turned on.

Include what you can of:

- what the problem is and what an attacker could do with it;
- the version, commit, or tag you tested;
- steps to reproduce, or a proof of concept;
- any configuration it depends on.

You don't need a complete write-up to report. A clear description of the
problem is enough to start.

## What happens next

- We acknowledge your report within **14 days**.
- We tell you whether we've confirmed the problem as soon as we know.
- We fix confirmed problems in the next release, or sooner for serious ones,
  and tell you before the fix is public.
- We credit you in the release notes unless you'd rather we didn't.

We ask that you give us a reasonable chance to fix a problem before disclosing
it publicly, and that you don't access or change data that isn't yours while
testing.

## Supported versions

liminal is pre-1.0. Security fixes go into the **latest release** only; older
releases are not patched. If you're running an older version, upgrade to get
fixes.

## Scope

liminal is an MCP gateway that brokers agents' access to tools. In scope:

- authentication at the gateway: token validation, audiences and scopes;
- per-agent credentials: anything that lets one agent use another's
  credentials or tools;
- policy: any way around a tool, file or scope restriction the operator set;
- federation: results from an upstream server being trusted when they
  shouldn't be.

**Out of scope:** vulnerabilities in third-party dependencies (please report
those upstream, and tell us if we ship an affected version), and problems that
require an attacker to already control the machine or the operator account
liminal runs under.
