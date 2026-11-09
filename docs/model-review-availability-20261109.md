# Model review availability investigation

The retained workspace snapshot contained 14 commands: four completed model reviews, three unavailable reviews, and seven intentional skips where the only missing fact was host execution metadata. None of the inspected entries with additional analysis gaps lacked a routing attempt. This is a retained sample, not a whole-history completeness claim.

Two failures reported `Service write: Broken pipe (os error 32)` and one reported `Resource temporarily unavailable (os error 35)`. These are local IPC failures, not recorded model refusals or successful reviews. The running service came from the installed VS Code 0.5.8 content-addressed bundle and lacked the newer service status fields. It was still using the older transport implementation; the repository's fragmented-request fix had not been installed into the active editor.

The fixed service uses blocking accepted streams with one bounded read deadline. A new integration test sends a real judge request larger than 16 KiB in 1 KiB fragments and verifies that it queues and produces model advice. The original split-32-KiB test also remains. During the extension regressions, a separate recorder acknowledgement timed out under concurrent load at the old 100 ms limit. Recorder delivery now retains an independent, bounded 250 ms deadline, and timeout errors are named explicitly. A deterministic regression covers both a delayed 150 ms acknowledgement and a response beyond the deadline.

## Review input and diagnostics

Script source sharing was disabled on the active route. File commands could therefore be rated using their command/static analysis without the file's contents. Version 0.5.9 records source-sharing coverage with each file review: whether sharing was enabled, how many inspected code files were shared or omitted, and whether source was unavailable. Shared-source limits still apply. Oversized or unreadable files are not represented as fully reviewed; a lower model severity cannot clear their static review requirement. Source sharing remains controlled by **Include inspected script excerpts**; no plaintext-key or automatic privacy fallback was added.

Compact severity requests no longer send the large static graph, effect list and context evidence through the model queue. Full analysis provenance remains bound into the local cache key by a digest. The model receives the command, available inspected source and up to 16 gap descriptions, with an explicit count for omitted gaps. All original gaps remain in the report and approval policy. This reduces avoidable IPC/prompt size without dropping source from an enabled file review.

Local queue failures retain their actual error detail. Provider transport errors distinguish connection failures from deadlines. When a provider failure triggers the existing short cooldown, subsequent unavailable results retain the original cause. This avoids an unexplained generic status concealing why other reviews were held back.

## Display changes

The expanded command view no longer shows an open **Unresolved behavior** list. Its contents are kept under the collapsed **More details → Analysis limits** section. Hook summaries no longer repeat the same limitation in both the reason and analysis line or append “includes unresolved behavior” to approval risk. Known impact, UNKNOWN, recorded decisions and required review remain intact. The model-advice section shows connection failures and source-sharing gaps when expanded.

## Verification and activation

The Rust workspace passes 232 tests with one existing containment test ignored. The source-coverage regression checks shared, disabled, oversized and missing source. Five-request concurrency, response ordering, cache/source bindings and failure handling regressions remain enabled. The extension tests cover collapsed analysis limits and real connection-error/source-gap rendering.

Version 0.5.9 is built as a release VSIX so it can be distinguished from the old installed bundle. Installing a package does not prove its running extension host has activated it: reload the editor window to load the update and restart the managed service through SecretStorage. The active route's source-sharing setting remains visible in LLM settings.


The release VSIX was installed successfully as **distill.distill-trace@0.5.9**. At the post-install check, the running service still reported **0.5.8**; **Developer: Reload Window** is required to activate the update. All **89 extension tests** pass, as does the additional original-error cooldown check.
