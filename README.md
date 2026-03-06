# OCISigner

![Build](https://img.shields.io/github/actions/workflow/status/NetSPI/OCISigner/unit-tests.yml?branch=main)
![Release](https://img.shields.io/github/v/release/NetSPI/OCISigner)
![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)
![Issues](https://img.shields.io/github/issues/NetSPI/OCISigner.svg)
![Forks](https://img.shields.io/github/forks/NetSPI/OCISigner.svg)
![Stars](https://img.shields.io/github/stars/NetSPI/OCISigner.svg)
![Java](https://img.shields.io/badge/java-25-informational)
![Burp](https://img.shields.io/badge/burp-montoya%202026.2-blue)

## Overview

> In the spirit of full transparency, development of this extension was assisted by LLM coding assistants. The assistant did most of the heavy lifting. As with any open-source tool, review the code to understand what it does before running it. That said, the code has been reviewed for potential issues.

OCISigner is a Burp Suite extension for signing OCI HTTP requests using API Key, Session Token, Config Profile (auto), Instance Principal (X.509), and Resource Principal (RPST) authentication methods. It supports SDK signing where possible and manual signing where the SDK is too restrictive for off-host use cases.

## Installation

Requirements:
- Burp Suite (Montoya API compatible)
- Java 21 for local builds

### Option 1: Install from GitHub Releases
1. Download the latest `OCISigner-*-all.jar` from:
   - https://github.com/NetSPI/OCISigner/releases
2. In Burp Suite, go to `Extensions` -> `Installed` -> `Add`.
3. Set `Extension type` to `Java` and select the downloaded jar.

### Option 2: Build and install locally
1. Build the extension:
   - `mvn clean package`
2. In Burp Suite, go to `Extensions` -> `Installed` -> `Add`.
3. Set `Extension type` to `Java` and select `target/OCISigner-*-all.jar`.

## Quick Start
1. In the OCISigner tab, pick an auth method, fill inputs, click **Save**.
2. Optionally click **Test Credentials** to validate.
3. Set **Always Sign With** to your profile and send requests in Repeater/Proxy.

## Important features

1. Toggle "Only sign in-scope requests" to only sign destinations set as in-scope in your Target tab
2. Toggle "Update timestamp" to automatically update the timestsamp for any date or x-date headers
3. Toggle "Only sign if Authorization exists" to only sign incoming HTTP requests that have an Authorization header. Helpful if you don't want ot sign requests going to other hosts that don't already have OCI auth.
4. "Test Credentials" will send a GetNamespace (/n/) API request to the region supplied to validate the creds supplied are valid. Per OCI documentation [here](https://docs.oracle.com/en-us/iaas/Content/Identity/policyreference/objectstoragepolicyreference.htm) (shown below) GetNamespace does **NOT REQUIRE AUTHORIZATION** making it a good endpoint to validate creds are working regardless of permissions.

## Notable Signing Notes
Reference:
- https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm

Behavior highlights:
- If both `date` and `x-date` are present, `x-date` takes precedence in the signing string.
- Standard `PUT`/`POST` signing includes body headers (`x-content-sha256`, `content-type`, `content-length`), including empty-body `PUT`/`POST`.
- The Object Storage exception is limited to these `PUT` APIs only:
  - `PutObject`: `/n/{namespace}/b/{bucket}/o/{object}`
  - `UploadPart`: `/n/{namespace}/b/{bucket}/u/{uploadId}/id/{partNumber}`
- For those two Object Storage `PUT` APIs, minimum signed headers are `(request-target)`, `host`, and `date`/`x-date`.
- For those two Object Storage `PUT` APIs:
  - If `x-content-sha256` is present, it is signed.
  - If `content-length` is present, it is signed.
  - If both are present, both are signed.
  - Missing optional body headers (ex. x-content-sha256) are not added only because of this exception rule.

## Operational Notes
- **Config Profile import (Auto):** Auto import checks `~/.oci/config` only.
- **Region save behavior:** Region changes take effect after clicking **Save**.
- **Config Profile region override:** If a region is set in the profile UI, it overrides the region in the selected config profile.
- **Proxy vs Repeater:** Both are supported. If proxy traffic is not being signed, check:
  - global `Signing Enabled`
  - `Always Sign With` profile selection
  - `Only sign in-scope requests`
  - `Only sign if Authorization exists`
- **Failure safety:** If signing fails, OCISigner sends the original request unchanged.

## Docs
Review the GitHub wiki for each profile auth method and how you would normally retrieve and use the credentials:
- https://github.com/NetSPI/OCISigner/wiki

## Dependency Inventory

| Dependency | Where Used | Purpose |
|---|---|---|
| `net.portswigger.burp.extensions:montoya-api:2026.2` | Burp extension entrypoint + UI panels + request hooks | Burp Suite extension API (UI, request handling, proxy integration). |
| `org.bouncycastle:bcprov-jdk18on:1.83` | Key parsing + crypto primitives | PEM and RSA key handling for signing. |
| `org.bouncycastle:bcpkix-jdk18on:1.83` | X.509 handling | Certificate parsing and chain handling for instance principal federation. |
| `com.oracle.oci.sdk:oci-java-sdk-shaded-full:3.81.0` | SDK signing mode + config profile provider | Uses OCI SDK signing where feasible and reads OCI config profiles. |
| `com.fasterxml.jackson.core:jackson-databind:2.21.1` | Token parsing + JWT helpers | JSON parsing for token responses and JWT claim extraction. |
| `org.junit.jupiter:junit-jupiter:6.0.3`* | Unit tests only | JUnit 5 test framework (unit tests and assertions). |
| `org.slf4j:slf4j-simple:1.7.33`* | Unit tests only | SLF4J binding to show logs during tests. |

*Test-scoped dependency.

### Bundled/transitive dependencies (via OCI SDK shaded full)
The shaded OCI SDK embeds a large set of transitive libraries, including Jackson, Jersey, Apache HTTP Client, HK2, Jakarta/Javax APIs, SLF4J, commons-logging, and commons-codec.

## Notes on Shading
The build relocates:
```
com.oracle.bmc -> com.webbinroot.ocisigner.shadow.com.oracle.bmc
```
This avoids classloader conflicts with other Burp extensions.

## Security Notes
- Tokens and private keys are sensitive. Avoid sharing logs that include them.
- Use the token masking features in the UI when demonstrating or screen-sharing.
