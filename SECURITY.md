# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately rather than in a public issue:

- through GitHub's **Report a vulnerability** button in the Security tab of this repository, or
- by email to achraflakdim33@gmail.com.

Include the affected endpoint or file, the steps to reproduce and the impact you observed. I will acknowledge your report within 7 days and keep you informed until it is fixed.

## Supported versions

Only the latest commit on `main` receives security fixes.

## Scope

NAV is designed to run on a single machine, with its API bound to `127.0.0.1`. The following are known limitations rather than vulnerabilities:

- the API has no authentication, so anyone with local access to the machine can use it;
- the scan history is stored unencrypted in `backend/scan_history.json` and in the browser's local storage.

Exposing the API on a network interface is not supported.
