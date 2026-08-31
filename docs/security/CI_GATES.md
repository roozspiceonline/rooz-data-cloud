# CI feedback and merge gates

RDC uses one workflow for two deliberately different purposes:

- advisory jobs give fast, path-scoped feedback on pull requests;
- the full `Frontend checks`, `Backend checks`, and
  `Scaffold and Compose checks` jobs remain the required merge gates.

`scripts/classify-ci-paths.py` reads the NUL-delimited changed-path set from
Git. API changes select backend checks, console/package changes select frontend
checks, and documentation, deployment, verifier, and unknown paths select the
scaffold checks. Workflow and root workspace changes conservatively select all
three groups. Renames and deletions are included.

The advisory jobs are intentionally incomplete. Backend advisory feedback runs
Ruff and MyPy without a database. Frontend advisory feedback omits the
production build. Scaffold advisory feedback runs the verifier manifest and
Compose validation. A green advisory job therefore never grants merge
eligibility.

The three required full jobs have no path, dependency, draft, or job-level
condition. They run for every pull-request head targeting `main`, including
draft heads, and again for every push to merged `main`. Their names are stable
because the repository ruleset requires those exact contexts. The repository
verifier rejects conditions on these jobs, removed terminal commands, missing
merged-main triggers, or advisory classifier drift.

Promotion remains:

1. use advisory results for early diagnosis;
2. require all three full jobs on the exact PR head;
3. confirm mergeability and resolved review threads;
4. merge only through the pull request;
5. require the complete workflow again on the exact merged-main commit.
