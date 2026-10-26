# Verdict recheck — October 22, 2026

Some installed verdicts remain incorrect. CLI 0.4.1 / policy 7 passes the existing regression corpus, but a fresh 32-case challenge identifies nine severity gaps: seven concrete impacts are understated, and two credential-related Git invocations are UNKNOWN. All nine produce `ask` under the test's default analyzer policy. The installed user hook is advisory, so this is not a claim that host execution is blocked.

The [32 expectations](../corpus/verdict-challenge-20261022.json) were recorded before their first evaluation. They are targeted policy judgments about the stated effects, not a random sample or a general accuracy estimate. The [full results](verdict-challenge-20261022.json) preserve the installed executable hash, expected and actual impacts, approval risk, decision, coverage gaps, and five real-tool effect probes. This verification does not change or reinstall the analyzer.

## Confirmed remaining discrepancies

- `git diff --output=.env`: UNKNOWN / MEDIUM approval risk; expected HIGH because its output file can overwrite a credential path. A disposable fixture confirmed that Git truncated the fake `.env` file.
- `git diff --no-index .env input.txt`: UNKNOWN / MEDIUM approval risk; expected HIGH for reading credential contents. The real-tool fixture confirmed that its output included the fake credential line. Both Git cases expose missing option/operand handling. The [Git manual](https://git-scm.com/docs/git-diff) documents these options.
- `psql -c 'WITH gone AS (DELETE FROM accounts RETURNING *) SELECT * FROM gone'`: MEDIUM; expected CRITICAL for an unfiltered DELETE in the CTE. PostgreSQL documents that [data-modifying CTEs execute](https://www.postgresql.org/docs/current/queries-with.html#QUERIES-WITH-MODIFYING). No PostgreSQL server statement was executed by this audit.
- `psql -c 'DELETE FROM accounts WHERE true'` and the `WHERE 1=1` variant: HIGH; expected CRITICAL because these predicates still select every row. Each predicate removed all three synthetic rows in a private, in-memory SQLite fixture. This establishes the constant-predicate behavior, not full PostgreSQL grammar equivalence.
- `sqlite3 scratch.db '.shell rm -rf /'`: MEDIUM; expected CRITICAL for the nested shell deletion request. SQLite's [CLI documentation](https://www.sqlite.org/cli.html) defines `.shell` as shell execution. A separate harmless `.shell printf` probe confirmed helper execution; the deletion payload was never executed.
- `sqlite3 scratch.db "SELECT load_extension('./payload')"`: MEDIUM; expected HIGH for unresolved native extension code. SQLite documents [runtime extension loading](https://www.sqlite.org/loadext.html). No native extension was loaded by the test.
- `psql -c '\! rm -rf /'`: MEDIUM; expected CRITICAL for a shell deletion request. `psql -f .env`: MEDIUM; expected HIGH for opening a credential-classified script file. Both behaviors are documented in the [psql manual](https://www.postgresql.org/docs/current/app-psql.html). Neither command was executed.

These are analyzer effect-model gaps. The extension's missing-assessment presentation fix does not repair their severity ratings.

## Checks that passed in this run

- Existing semantic/policy audit: all 65 expectations matched, including four deliberately UNKNOWN runtime cases. Its nine benign oracle checks passed.
- Existing policy corpus: 40 cases, zero wrong impacts, unsafe allows, or unnecessary reviews.
- Language smoke: 155 analyses and 155 label checks.
- Extension 0.4.2: all 38 tests, including missing versus unresolved assessment presentation, real signed pre/post delivery, and forged-label isolation.
- Fresh challenge: 23 of 32 exact impact/review/risk expectations matched; all five separate effect probes passed. All nine discrepant cases requested review, with no `allow` decision in those cases. Counts across suites may overlap; no overall accuracy percentage is inferred.
- Live host-to-recorder probe: `printf 'distill-verdict-check-20261022\n'` produced one completed SAFE row, one policy-7 assessment, and no split attempt ID. This proves live correlation for that probe. The running recorder remains the compatible version 4; the installed extension package is 0.4.2. No live UI reload or visual verification is claimed.

## Reproduce

```sh
python3 scripts/verdict_challenge.py /Users/harshdhiman/.cargo/bin/distill --output /tmp/distill-verdict-challenge.json
```

The command intentionally exits 1 while the nine expectations fail. Candidate commands are only analyzed. The separate probes touch disposable fixture files, run harmless `printf`, and manipulate three private in-memory rows. No challenge deletion payload, external database, or user credential file is used.
