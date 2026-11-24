#!/usr/bin/env python3
"""Tests for the Vorobey hackerpolice sync tool."""

from __future__ import annotations

import ast
import fnmatch
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from _support import (
    player,
    run_sync_and_read_outputs,
)

import policy
import sync_vorobey_hackerpolice as sync_module
from playerlist import (
    dumps,
    load,
    strict_json_loads,
    validate,
)
from policy import is_racist_proof
from sources import (
    load_snapshot,
)


class WorkflowContractTests(unittest.TestCase):
    """The workflow is code too, and part of the bot's behavior and security.

    A renamed CLI flag, a step output nobody writes any more, a report path that
    drifted from the pull-request body, an unpinned action or a check that no
    longer gates publishing could break the bot silently. Pin the contract in
    the suite instead.
    """

    root = Path(__file__).resolve().parent.parent
    workflow_path = root / ".github" / "workflows" / "sync-vorobey-hackerpolice.yml"
    dependabot_path = root / ".github" / "dependabot.yml"
    pyproject_path = root / "pyproject.toml"

    @classmethod
    def setUpClass(cls):
        cls.workflow = cls.workflow_path.read_text(encoding="utf-8")

    def jobs(self) -> dict[str, str]:
        """Split the jobs: mapping into one string per job."""
        _, _, body = self.workflow.partition("\njobs:\n")
        self.assertTrue(body, "the workflow must declare jobs")
        parts = re.split(r"^  ([a-z][a-z-]*):$", body, flags=re.M)
        return {parts[index]: parts[index + 1] for index in range(1, len(parts) - 1, 2)}

    def sync_invocation(self) -> str:
        start = self.workflow.index("python3 scripts/sync_vorobey_hackerpolice.py")
        lines = []
        for line in self.workflow[start:].splitlines():
            lines.append(line)
            if not line.rstrip().endswith("\\"):
                break
        return "\n".join(lines)

    def test_every_flag_it_passes_is_a_real_option(self):
        options = {option for action in sync_module.build_parser()._actions for option in action.option_strings}
        invocation = self.sync_invocation()
        passed = set(re.findall(r"--[a-z][a-z-]*", invocation))
        self.assertTrue(passed, "the sync step should pass flags")
        self.assertEqual(passed - options, set(), "the workflow passes a flag the parser dropped")
        # Check option flags embedded in the DRY_RUN and ALLOW_MASS_DEMOTION shell variables too.
        for hidden in re.findall(r"'(--[a-z][a-z-]*)'", self.workflow):
            self.assertIn(hidden, options)

    def test_it_always_demotes(self):
        """Without --demote the bot never applies a single demotion."""
        self.assertIn("--demote", set(re.findall(r"--[a-z][a-z-]*", self.sync_invocation())))

    def test_it_passes_the_files_from_the_environment(self):
        invocation = self.sync_invocation()
        self.assertIn('--database "$DATABASE"', invocation)
        self.assertIn('--snapshot "$SNAPSHOT"', invocation)

    def test_every_step_output_it_reads_is_one_the_run_writes(self):
        written = run_sync_and_read_outputs(
            database=dumps({"players": [player("[U:1:1]", ["cheater"])]}),
            snapshot=dumps({"players": []}),
            source=dumps({"players": [player("[U:1:1]", ["cheater"])]}),
        )
        read = set(re.findall(r"steps\.sync\.outputs\.([a-z_]+)", self.workflow))
        self.assertTrue(read, "the workflow reads no step output at all")
        self.assertEqual(read - set(written), set(), "the workflow reads an output nothing writes")

    def test_the_publish_steps_require_a_successful_sync(self):
        for block in re.findall(
            r"- name: (?:Open or update pull request|Push branch|Commit directly)([\s\S]*?)(?=\n\s+- name:|\Z)",
            self.workflow,
        ):
            self.assertIn("steps.sync.outcome == 'success'", block, "publishing must not run after a failed sync")
            self.assertIn("steps.sync.outputs.changed == 'true'", block)

    def test_the_pull_request_carries_both_files_and_uses_the_report_as_its_body(self):
        block = self.workflow[self.workflow.index("add-paths:") :]
        block = block[: block.index("branch:")]
        self.assertIn("${{ env.DATABASE }}", block)
        self.assertIn("${{ env.SNAPSHOT }}", block)
        reported = re.search(r'--report "\$RUNNER_TEMP/([^"]+)"', self.workflow)
        self.assertIsNotNone(reported, "the sync step must write a report")
        body = re.search(r"body-path:\s*\$\{\{\s*runner\.temp\s*\}\}/(\S+)", self.workflow)
        self.assertIsNotNone(body, "the pull request must use the report as its body")
        self.assertEqual(body.group(1), reported.group(1))

    def test_every_action_is_pinned_to_a_commit_and_says_which_release_it_is(self):
        uses = re.findall(r"uses:\s*(\S+)\s*(#[^\n]*)?", self.workflow)
        self.assertGreaterEqual(len(uses), 3)
        for reference, comment in uses:
            repository, _, sha = reference.partition("@")
            self.assertRegex(repository, r"^[\w.-]+/[\w.-]+$")
            self.assertRegex(sha, r"^[0-9a-f]{40}$", f"{reference} is not pinned to a commit SHA")
            self.assertRegex(comment or "", r"#\s*v\d", f"{reference} needs its release tag in a comment")

    def test_a_change_to_any_file_the_suite_reads_runs_the_checks(self):
        """Every file these tests read must be able to trigger them.

        The dependabot contract and the shipped JSON data are validated here.
        If any of those paths fall out of the workflow filter, a data-only
        pull request could bypass its assertion. README.md is deliberately
        absent: no test reads it, so its wording belongs to the maintainer.
        """
        block = self.workflow.split("  pull_request:\n", 1)[1].split("\npermissions:", 1)[0]
        patterns = re.findall(r'^\s+- "([^"]+)"', block, re.M)
        self.assertTrue(patterns, "the pull_request trigger has no paths at all")

        def covered(name: str) -> bool:
            return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)

        for name in (
            ".gitattributes",
            ".gitignore",
            "playerlist.garou3299.json",
            "rules.garou3299.json",
            "snapshot/playerlist.vorobey-hackerpolice.json",
            ".github/dependabot.yml",
            ".github/workflows/sync-vorobey-hackerpolice.yml",
            "pyproject.toml",
            "scripts/playerlist.py",
            "tests/test_sources.py",
            "tests/test_policy.py",
            "tests/test_playerlist.py",
            "tests/test_report.py",
            "tests/test_sync_cli.py",
            "tests/test_workflow.py",
            "tests/_support.py",
        ):
            self.assertTrue(covered(name), f"{name} can change without the checks running")

    def test_the_paths_it_names_exist(self):
        for key in ("DATABASE", "SNAPSHOT"):
            match = re.search(rf"^\s*{key}:\s*(\S+)$", self.workflow, re.M)
            self.assertIsNotNone(match, f"{key} is not defined")
            self.assertTrue((self.root / match.group(1)).is_file(), match.group(1))

    def test_read_only_checks_gate_the_write_capable_sync_job(self):
        """Third-party test tools must never run with credentials that can write."""
        jobs = self.jobs()
        self.assertEqual(set(jobs), {"checks", "sync"})
        checks, sync = jobs["checks"], jobs["sync"]
        self.assertIn("Lint and test the proposed change", checks)  # Preserve the existing pull-request check context.
        self.assertIn("Lint and test before publishing", checks)
        # The workflow grants nothing globally; each job opts in to exactly what it needs,
        # so a new job cannot inherit a write token by accident.
        self.assertRegex(self.workflow, r"(?m)^permissions: \{\}$")
        self.assertNotRegex(
            self.workflow.split("jobs:")[0],
            r"(?m)^\s+contents: write",
            "the default (workflow-level) permissions must never grant write access",
        )
        for command in (
            "python3 -m ruff check scripts tests",
            "python3 -m ruff format --check scripts tests",
            "python3 -m mypy scripts",
            "python3 -m bandit -q -r scripts",
            "python3 -X warn_default_encoding -W error::EncodingWarning -m coverage run -m unittest discover -s tests -v",
            "python3 -m coverage report",
            "python3 -m vulture scripts tests --min-confidence 60",
            "python3 -m unittest discover -s tests -q",
        ):
            self.assertIn(command, checks)
            self.assertNotIn(command, sync)
        self.assertIn("needs: checks", sync)
        self.assertIn("contents: read", checks)
        self.assertIn("persist-credentials: false", checks)
        self.assertNotIn("pull-requests: write", checks)
        self.assertIn("contents: write", sync)
        self.assertIn("pull-requests: write", sync)
        self.assertNotIn("pip install", sync)
        for name, block in jobs.items():
            self.assertIn("timeout-minutes:", block, f"the {name} job has no timeout")
            self.assertIn("concurrency:", block, f"the {name} job has no concurrency group")

    def test_the_second_test_pass_actually_ticks_the_clock(self):
        """Without the env var the clock step is just the suite run twice.

        The step re-runs the same discover command the coverage step already
        ran; TF2BD_TICKING_CLOCK is the only thing that makes it a different
        test. Dropping the variable would leave a green step that proves
        nothing, so assert the variable and the command travel together.
        """
        checks = self.jobs()["checks"]
        step = checks.split("No test may depend on the clock standing still", 1)[-1]
        self.assertIn('TF2BD_TICKING_CLOCK: "1"', step)
        self.assertIn("python3 -m unittest discover -s tests -q", step)
        self.assertIn(
            "TF2BD_TICKING_CLOCK",
            (Path(__file__).resolve().parent / "_support.py").read_text(encoding="utf-8"),
            "the workflow sets TF2BD_TICKING_CLOCK but nothing reads it",
        )

    def test_the_sync_job_always_acts_on_the_default_branch(self):
        """A non-default workflow ref must never reach the write-capable job.

        Pinning actions/checkout protects the data being updated, but does not
        pin the workflow YAML that GitHub loaded for a manual dispatch. Only a
        run whose workflow ref is the default branch may receive write
        permissions; checkout and PR base are also explicitly pinned there.
        """
        sync = self.jobs()["sync"]
        self.assertIn("github.ref == format('refs/heads/{0}', github.event.repository.default_branch)", sync)
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", sync)
        # Check pull requests on their merge refs; only sync pins the default branch.
        self.assertNotIn("ref: ${{ github.event.repository.default_branch }}", self.jobs()["checks"])

    def test_the_pull_request_targets_the_default_branch_explicitly(self):
        self.assertIn("base: ${{ env.BASE_BRANCH }}", self.workflow)

    def test_a_new_job_cannot_inherit_a_write_token(self):
        """Workflow-level permissions default to empty; jobs opt in individually.

        The previous workflow granted ``contents: read`` globally, which any
        future job would silently inherit (and which is the wrong reading of
        "read-only": it still exposes a token). ``permissions: {}`` makes every
        grant explicit, and the write-capable job is the only one that asks.
        """
        self.assertNotIn("permissions: write-all", self.workflow)
        jobs = self.jobs()
        self.assertNotIn("contents: write", jobs["checks"])
        self.assertIn("contents: write", jobs["sync"])
        self.assertIn("pull-requests: write", jobs["sync"])
        # Every job still declares its own permissions block.
        for name, block in jobs.items():
            self.assertIn("permissions:", block, f"the {name} job inherits the default token")

    def test_the_checks_job_does_not_download_history_it_never_reads(self):
        checks = self.jobs()["checks"]
        self.assertIn("fetch-depth: 1", checks)
        self.assertNotIn("fetch-depth: 0", checks)  # 0 means the entire history.

    def test_a_noop_or_direct_commit_closes_a_stale_bot_pull_request(self):
        """A no-op or direct commit makes any previously opened bot PR stale.

        Merging it later would undo a manual fix or newer upstream state. The
        cleanup must not fire on a dry run, and must not turn a clean sync red
        if the token cannot manage pull requests.
        """
        steps = self.workflow.split("\n      - ")
        block = next((step for step in steps if step.startswith("name: Close a stale bot pull request")), None)
        self.assertIsNotNone(block, "the workflow must close a stale bot pull request")
        assert block is not None  # Keep the narrowed value explicit for type checkers.
        self.assertIn("steps.sync.outcome == 'success'", block)
        self.assertIn("steps.sync.outputs.changed != 'true'", block)
        self.assertIn("env.MODE == 'commit'", block)
        self.assertIn("steps.direct_commit.outcome == 'success'", block)
        self.assertIn("||", block)
        self.assertIn("env.DRY_RUN_INPUT != 'true'", block)
        self.assertIn("continue-on-error: true", block)
        self.assertIn('gh pr list --repo "$REPOSITORY" --head "$BOT_BRANCH" --state open', block)

    def test_the_checks_job_tests_the_documented_python_floor(self):
        """Keep the 3.10 floor and production 3.12 in the checks matrix.

        Without the floor leg, a 3.11+ API (``datetime.UTC``, ``tomllib``) or a
        3.12-only f-string could pass CI while breaking the floor that
        pyproject.toml and the lint target both declare.
        The write-capable sync job stays on 3.12 as the production runtime.
        """
        checks = self.jobs()["checks"]
        self.assertIn("matrix:", checks)
        self.assertIn('"3.10"', checks)  # The documented minimum supported version.
        self.assertIn(
            '"3.12"',
            checks,
        )  # The production runtime version.
        self.assertIn("python-version: ${{ matrix.python-version }}", checks)
        # Keep matrix legs in separate cancellation groups.
        group = next(line for line in checks.splitlines() if line.strip().startswith("group: checks-"))
        self.assertIn("matrix.python-version", group)
        # The production sync job intentionally uses a single Python version.
        self.assertNotIn("matrix:", self.jobs()["sync"])

    def test_scripts_and_tests_parse_as_python_310(self):
        """The documented floor applies to shipped code and the test suite."""
        paths = sorted((self.root / "scripts").glob("*.py")) + sorted((self.root / "tests").glob("*.py"))
        for path in paths:
            with self.subTest(path=path.relative_to(self.root)):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 10))

        # Ensure the Python 3.10 parser rejects newer syntax.
        with self.assertRaises(SyntaxError):
            ast.parse("type Alias = int\n", feature_version=(3, 10))

    def test_python_310_floor_matches_the_lint_target_and_ci(self):
        pyproject = (self.root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("Python 3.10+", pyproject)
        self.assertIn('target-version = "py310"', pyproject)
        self.assertIn('"3.10"', self.jobs()["checks"])

    def test_the_suite_does_not_inherit_the_runners_output_file(self):
        """GITHUB_OUTPUT is exported by every CI step, including the test step.

        Inheriting it made the suite append ~300 lines to the runner's real
        output file: the tests then depended on their environment, and a step
        reading its own outputs would be reading values produced by the tests.

        Checked in a CHILD interpreter, because that is the only place the
        import-time behavior can be observed -- and because asserting on this
        file's own text would match this test's own source and never fail.
        """
        code = (
            "import os, sys;"
            "os.environ['GITHUB_OUTPUT']='must-not-survive-the-import';"
            f"sys.path.insert(0, {str(Path(__file__).resolve().parent)!r});"
            "import test_sources;"  # Import test_sources to load the shared environment guard without running tests.
            "print(os.environ.get('GITHUB_OUTPUT', '<popped>'))"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, encoding="utf-8", timeout=180
        )
        self.assertEqual(result.stdout.strip(), "<popped>", result.stderr[-500:])

    def test_the_coverage_gate_is_encoded_not_just_convention(self):
        """`coverage report` must fail on an untested statement OR branch.

        Without a [tool.coverage] section the gate only exists in a reviewer's
        head: a plain `coverage run` reports line coverage, and anything at all
        reports success. The thresholds belong in the file CI reads.
        """
        pyproject = (self.root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("branch = true", pyproject)
        self.assertIn('source = ["scripts"]', pyproject)
        # The floor must be high enough to catch real rot, and low enough that a
        # contributor is not pushed to invent a test for an unreachable branch.
        match = re.search(r"^fail_under = (\d+)$", pyproject, re.MULTILINE)
        self.assertIsNotNone(match, "coverage fail_under is missing from pyproject.toml")
        threshold = int(match.group(1))
        self.assertGreaterEqual(threshold, 90)
        self.assertLessEqual(threshold, 100)

    def test_the_check_job_is_read_only(self):
        jobs = self.jobs()
        self.assertIn("contents: read", jobs["checks"])
        self.assertNotIn("contents: write", jobs["checks"])
        self.assertNotIn("pull-requests: write", jobs["checks"])

    def ci_group(self) -> str:
        """The body of pyproject.toml's ``[dependency-groups] ci`` list.

        Parsed with a regex rather than tomllib: these tests also run on the
        3.10 matrix leg, where tomllib does not exist.
        """
        text = self.pyproject_path.read_text(encoding="utf-8")
        match = re.search(r"^\[dependency-groups\]\s*$(.*?)^\[", text, re.M | re.S)
        self.assertIsNotNone(match, "pyproject.toml has no [dependency-groups] table")
        body = re.search(r"^ci\s*=\s*\[(.*?)^\]", match.group(1), re.M | re.S)
        self.assertIsNotNone(body, "[dependency-groups] has no ci group")
        return body.group(1)

    def pinned_tools(self) -> dict[str, str]:
        """The ``name == version`` pins in the ci dependency group."""
        pins = {}
        for raw in self.ci_group().splitlines():
            line = raw.split("#", 1)[0].strip().rstrip(",").strip('"')
            if line:
                name, separator, version = line.partition("==")
                self.assertTrue(separator, f"{line} is not pinned with ==")
                pins[name] = version
        return pins

    def test_every_tool_the_workflow_runs_is_pinned_exactly_once(self):
        """An unpinned release could move a gate under us without a commit."""
        pins = self.pinned_tools()
        group = self.ci_group()
        for tool in ("ruff", "mypy", "bandit", "coverage", "vulture"):
            self.assertIn(tool, pins, f"{tool} runs in CI but is not pinned")
            self.assertRegex(pins[tool], r"^\d+(\.\d+)*$", f"{tool} needs an exact version")
            self.assertEqual(len(re.findall(rf'"{tool}==', group)), 1, f"{tool} is pinned twice")
            self.assertIn(f"python3 -m {tool} ", self.workflow, f"{tool} is pinned but never run")

    def test_the_workflow_installs_the_pinned_tools_and_pins_nothing_inline(self):
        """One source of truth: a second inline pin could silently disagree."""
        self.assertIn("--group ci", self.workflow)
        for tool in ("ruff", "mypy", "bandit", "coverage", "vulture"):
            self.assertNotRegex(self.workflow, rf'"{tool}==[^"]*"', f"{tool} is also pinned inline")

    def test_the_workflow_raises_pip_before_asking_for_a_dependency_group(self):
        """``--group`` arrives in pip 25.1; setup-python can ship an older pip.

        Without the upgrade the install dies with "no such option: --group" on
        whichever leg happens to have the older pip -- a failure that looks
        nothing like its cause.
        """
        install = self.workflow.split("--group ci", 1)[0]
        self.assertIn('--upgrade "pip>=25.1"', install)

    def test_checks_run_for_all_events_and_only_pull_requests_run_no_sync(self):
        jobs = self.jobs()
        self.assertNotIn("if: github.event_name == 'pull_request'", jobs["checks"])
        self.assertIn("if: github.event_name != 'pull_request'", jobs["sync"])
        self.assertIn("needs: checks", jobs["sync"])
        for watched in ("scripts/**", "tests/**", ".github/workflows/sync-vorobey-hackerpolice.yml"):
            self.assertIn(watched, self.workflow)

    def test_dependabot_owns_the_actions_and_the_check_tooling(self):
        text = self.dependabot_path.read_text(encoding="utf-8")
        self.assertIn('package-ecosystem: "github-actions"', text)
        self.assertIn('package-ecosystem: "pip"', text)
        self.assertNotIn("package-ecosystem: npm", text)
        self.assertIn('interval: "weekly"', text)

    def test_the_pip_entry_points_at_a_file_dependabot_can_actually_find(self):
        """A directory with no detectable manifest updates nothing, silently.

        Dependabot's pip fetcher reads pyproject.toml under the configured
        directory. Point the entry somewhere else, or drop the
        [dependency-groups] table, and the pins quietly stop being maintained
        with no error anywhere -- the exact rot this entry exists to prevent.
        """
        text = self.dependabot_path.read_text(encoding="utf-8")
        block = text.split('package-ecosystem: "pip"', 1)[1]
        directory = re.search(r'directory:\s*"([^"]+)"', block)
        self.assertIsNotNone(directory, "the pip entry needs a directory")
        target = self.root / directory.group(1).lstrip("/")
        self.assertTrue(target.is_dir(), f"{directory.group(1)} is not a directory")
        manifest = target / "pyproject.toml"
        self.assertTrue(manifest.is_file(), f"no pyproject.toml in {directory.group(1)}")
        self.assertEqual(manifest.resolve(), self.pyproject_path.resolve())
        self.assertIn("[dependency-groups]", manifest.read_text(encoding="utf-8"))

    def test_dependabot_does_not_propose_a_coverage_that_cannot_install(self):
        """The 3.10 leg cannot take coverage >=7.17.0; an ignore keeps CI green."""
        text = self.dependabot_path.read_text(encoding="utf-8")
        floors = re.findall(r'python-version:.*?"3\.(\d+)"', self.workflow)
        if floors and min(int(minor) for minor in floors) < 11:
            self.assertIn('dependency-name: "coverage"', text)
            self.assertIn('">=7.17.0"', text)


class RepositoryDataTests(unittest.TestCase):
    """The data files this repository ships must be exactly what the bot expects."""

    ROOT = Path(__file__).resolve().parents[1]

    def test_every_auto_proof_in_the_shipped_database_still_qualifies(self):
        """Tightening the prefix rule must never drop a real machine record.

        The shipped list carries hundreds of TF2BD auto lines; if any of them
        stopped qualifying, a demotion would silently delete evidence that
        justifies a racist tag.
        """
        database, _ = load(self.ROOT / "playerlist.garou3299.json")
        auto = [
            line
            for entry in database["players"]
            for line in (entry.get("proof") or [])
            if isinstance(line, str) and line.strip().casefold().startswith(policy.RACIST_PROOF_PREFIX.casefold())
        ]
        self.assertGreater(len(auto), 100, "the fixture this guards has disappeared")
        self.assertEqual([line for line in auto if not is_racist_proof(line)], [])

    def test_shipped_database_is_valid_and_canonically_formatted(self):
        database, original = load(self.ROOT / "playerlist.garou3299.json")
        self.assertEqual(validate(database).errors, [])
        # Canonical formatting prevents the bot from rewriting the full data file
        # after a manual formatting-only change.
        self.assertEqual(dumps(database), original)

    # The scammer list is deliberately not checked here. The bot never reads it,
    # never writes it, and never names it, so holding it to this tool's idea of
    # valid or canonical only means CI failing over an edit to a file that has
    # nothing to do with the sync.

    def test_the_shipped_racist_rule_still_justifies_automatic_racist_proofs(self):
        """The demotion policy relies on TF2BD's rule continuing to mark racist."""
        document = strict_json_loads((self.ROOT / "rules.garou3299.json").read_bytes())
        self.assertIsInstance(document, dict)
        rules = document.get("rules")
        self.assertIsInstance(rules, list)
        racist_rules = [
            rule
            for rule in rules
            if isinstance(rule, dict)
            and isinstance(rule.get("actions"), dict)
            and isinstance(rule["actions"].get("mark"), list)
            and "racist" in rule["actions"]["mark"]
        ]
        self.assertTrue(racist_rules, "the shipped rule no longer marks racist")
        self.assertTrue(
            any(
                isinstance(rule.get("triggers"), dict)
                and isinstance(rule["triggers"].get("chatmsg_text_match"), dict)
                and rule["triggers"]["chatmsg_text_match"].get("case_sensitive") is False
                and rule["triggers"]["chatmsg_text_match"].get("mode") == "word"
                and isinstance(rule["triggers"]["chatmsg_text_match"].get("patterns"), list)
                and bool(rule["triggers"]["chatmsg_text_match"]["patterns"])
                and all(
                    isinstance(pattern, str) and pattern
                    for pattern in rule["triggers"]["chatmsg_text_match"]["patterns"]
                )
                for rule in racist_rules
            ),
            "the racist rule must remain case-insensitive, word-matched, and non-empty",
        )

    def test_atomic_write_temporaries_are_ignored_by_git(self):
        """A SIGTERM/SIGKILL can leave a temp file that must not be staged."""
        command = ["git", "check-ignore", "-q", "--no-index", "--"]
        generated = subprocess.run(
            [*command, ".tf2bd-sync-review.tmp"],
            cwd=self.ROOT,
            timeout=30,
        )
        unrelated = subprocess.run(
            [*command, ".release-notes.tmp"],
            cwd=self.ROOT,
            timeout=30,
        )
        self.assertEqual(generated.returncode, 0, "atomic-write leftovers must stay out of commits")
        self.assertEqual(unrelated.returncode, 1, "the temporary-file rule must not hide unrelated dotfiles")

    def test_git_does_not_apply_line_ending_conversion_to_json_data(self):
        """The snapshot must remain the exact upstream byte sequence.

        `git check-attr` answers for any path, existing or not, so a name that
        leaves the repository would keep passing here forever. Each name is
        therefore required to be a file that is actually shipped.
        """
        for name in (
            "playerlist.garou3299.json",
            "snapshot/playerlist.vorobey-hackerpolice.json",
            "rules.garou3299.json",
        ):
            with self.subTest(path=name):
                self.assertTrue((self.ROOT / name).is_file(), f"{name} is named here but no longer shipped")
                result = subprocess.run(
                    ["git", "check-attr", "text", "--", name],
                    cwd=self.ROOT,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    check=True,
                    timeout=30,
                )
                self.assertIn(f"{name}: text: unset", result.stdout)

    @staticmethod
    def job_block(text, name):
        """The lines of one job, without needing a YAML parser in CI."""
        lines = text.splitlines()
        start = next(index for index, line in enumerate(lines) if line.rstrip() == f"  {name}:")
        end = len(lines)
        for index in range(start + 1, len(lines)):
            line = lines[index]
            if line.strip() and not line.startswith("    "):
                end = index
                break
        return "\n".join(lines[start:end])

    def test_a_running_sync_is_never_canceled_and_cannot_hang_forever(self):
        workflow = (self.ROOT / ".github/workflows/sync-vorobey-hackerpolice.yml").read_text(encoding="utf-8")
        sync_block = self.job_block(workflow, "sync")
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("timeout-minutes:", sync_block)  # Bound the job so a stalled fetch cannot run indefinitely.

    def test_publishing_steps_stage_only_the_two_data_files(self):
        """`git add -A` would publish whatever else happens to be in the workspace."""
        workflow = (self.ROOT / ".github/workflows/sync-vorobey-hackerpolice.yml").read_text(encoding="utf-8")
        self.assertNotIn("git add -A", workflow)
        self.assertNotIn("git add .", workflow)
        self.assertEqual(workflow.count('git add -- "$DATABASE" "$SNAPSHOT"'), 2)
        self.assertIn("compare/$BASE_BRANCH...$BOT_BRANCH?expand=1", workflow)

    def test_fallback_fetch_populates_the_remote_tracking_ref_before_a_leased_push(self):
        """A branch-only fetch otherwise updates FETCH_HEAD, not the lease ref.

        Reproduce actions/checkout's narrow default-branch refspec in a local
        repository, then execute the fetch-and-push block from the workflow.
        The existing remote branch is deliberately unknown to the initial
        checkout and the local fallback branch has no upstream configured, so
        only an explicit lease expectation can push it safely.
        """
        workflow = (self.ROOT / ".github/workflows/sync-vorobey-hackerpolice.yml").read_text(encoding="utf-8")
        sync_block = self.job_block(workflow, "sync")
        fallback = next(
            block for block in sync_block.split("\n      - ") if block.startswith("name: Push branch and link")
        )
        fallback_lines = fallback.splitlines()
        lease_start = next(index for index, line in enumerate(fallback_lines) if line.strip() == "expected=''")
        lease_end = next(
            index
            for index in range(lease_start, len(fallback_lines))
            if fallback_lines[index].strip().startswith("git push --force-with-lease")
        )
        lease_script = "\n".join(line.strip() for line in fallback_lines[lease_start : lease_end + 1])
        fetch = next(line for line in lease_script.splitlines() if line.startswith("if git fetch --quiet origin"))
        branch_match = re.search(r"^\s*BOT_BRANCH:\s*(\S+)", workflow, re.M)
        self.assertIsNotNone(branch_match)
        branch = branch_match.group(1)
        self.assertIn("+refs/heads/$BOT_BRANCH:refs/remotes/origin/$BOT_BRANCH", fetch)
        self.assertIn('git push --force-with-lease="refs/heads/$BOT_BRANCH:$expected"', lease_script)

        def git(directory: Path, *arguments: str) -> str:
            result = subprocess.run(
                ["git", *arguments],
                cwd=directory,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=True,
                timeout=30,
            )
            return result.stdout.strip()

        def run_lease_script(directory: Path, branch_name: str) -> None:
            """Execute the workflow's push block, quietly.

            Without capture, git writes its push and fetch progress straight to
            the test runner's console, so a passing suite prints remote URLs and
            branch names. Capturing it also puts the real output in the failure
            message, which ``check=True`` alone does not do.
            """
            result = subprocess.run(
                ["bash", "-c", lease_script],
                cwd=directory,
                env={**os.environ, "BOT_BRANCH": branch_name},
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            remote = root / "remote.git"
            source = root / "source"
            checkout = root / "checkout"
            git(root, "init", "--bare", str(remote))
            git(root, "init", str(source))
            git(source, "config", "user.name", "test")
            git(source, "config", "user.email", "test@example.invalid")
            (source / "file.txt").write_text("base\n", encoding="utf-8")
            git(source, "add", "file.txt")
            git(source, "commit", "-m", "base")
            git(source, "remote", "add", "origin", str(remote))
            git(source, "push", "origin", f"HEAD:refs/heads/{branch}")
            git(source, "push", "origin", "HEAD:refs/heads/main")

            git(root, "init", str(checkout))
            git(checkout, "remote", "add", "origin", str(remote))
            git(
                checkout,
                "config",
                "remote.origin.fetch",
                "+refs/heads/main:refs/remotes/origin/main",
            )
            git(checkout, "fetch", "origin", "main")
            git(checkout, "config", "user.name", "test")
            git(checkout, "config", "user.email", "test@example.invalid")
            git(checkout, "checkout", "-B", "main", "origin/main")
            git(checkout, "checkout", "-B", branch)  # The local fallback branch has no configured upstream.
            upstream = subprocess.run(
                ["git", "rev-parse", "--verify", "--abbrev-ref", "@{upstream}"],
                cwd=checkout,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
            self.assertNotEqual(upstream.returncode, 0)
            (checkout / "file.txt").write_text("bot update\n", encoding="utf-8")
            git(checkout, "add", "file.txt")
            git(checkout, "commit", "-m", "bot update")
            run_lease_script(checkout, branch)
            self.assertEqual(
                git(root, "--git-dir", str(remote), "rev-parse", f"refs/heads/{branch}"),
                git(checkout, "rev-parse", "HEAD"),
            )

            # On the first run, the remote bot branch is absent. A failed fetch must
            # leave an empty lease expectation that allows creation but never
            # authorizes overwriting an existing remote ref.
            git(source, "push", "origin", "--delete", branch)
            fresh = root / "fresh-checkout"
            git(root, "init", str(fresh))
            git(fresh, "remote", "add", "origin", str(remote))
            git(fresh, "config", "remote.origin.fetch", "+refs/heads/main:refs/remotes/origin/main")
            git(fresh, "fetch", "origin", "main")
            git(fresh, "config", "user.name", "test")
            git(fresh, "config", "user.email", "test@example.invalid")
            git(fresh, "checkout", "-B", "main", "origin/main")
            git(fresh, "checkout", "-B", branch)
            (fresh / "file.txt").write_text("first bot run\n", encoding="utf-8")
            git(fresh, "add", "file.txt")
            git(fresh, "commit", "-m", "first bot run")
            run_lease_script(fresh, branch)
            self.assertEqual(
                git(root, "--git-dir", str(remote), "rev-parse", f"refs/heads/{branch}"),
                git(fresh, "rev-parse", "HEAD"),
            )

    def test_stale_bot_pr_is_closed_after_noop_or_a_successful_direct_commit(self):
        workflow = (self.ROOT / ".github/workflows/sync-vorobey-hackerpolice.yml").read_text(encoding="utf-8")
        sync_block = self.job_block(workflow, "sync")
        stale_step = next(
            block
            for block in sync_block.split("\n      - ")
            if block.startswith("name: Close a stale bot pull request")
        )
        condition = next(line.strip() for line in stale_step.splitlines() if line.strip().startswith("if:"))
        self.assertIn("steps.sync.outcome == 'success'", condition)
        self.assertIn("env.DRY_RUN_INPUT != 'true'", condition)
        self.assertIn(
            "(steps.sync.outputs.changed != 'true' || "
            "(env.MODE == 'commit' && steps.direct_commit.outcome == 'success'))",
            condition,
        )
        commit_step = next(
            block for block in sync_block.split("\n      - ") if block.startswith("name: Commit directly")
        )
        self.assertIn("id: direct_commit", commit_step)
        close_command = "\n".join(
            line for line in stale_step.splitlines() if "gh pr close" in line or "--comment" in line
        )
        self.assertIn("--repo", close_command)
        self.assertIn("--comment", close_command)
        self.assertIn("superseded", close_command)

    def test_every_publishing_step_requires_a_successful_sync(self):
        """A red run must never publish, and must never claim "nothing to do".

        GitHub runs a step with an explicit `if:` even when an earlier step
        failed or was skipped, so each of these four steps has to test the
        sync step's own outcome -- otherwise a failing lint/test step turns
        the job red while a later publishing or cleanup step still runs.
        """
        workflow = (self.ROOT / ".github/workflows/sync-vorobey-hackerpolice.yml").read_text(encoding="utf-8")
        steps = workflow.split("\n      - ")
        for name in (
            "Open or update pull request",
            "Push branch and link a manual pull request",
            "Commit directly to the default branch",
            "Nothing to do",
            "Close a stale bot pull request",
        ):
            block = next((step for step in steps if step.startswith(f"name: {name}")), None)
            self.assertIsNotNone(block, f"workflow step not found: {name}")
            condition = [line for line in block.splitlines() if line.strip().startswith("if:")]
            self.assertEqual(len(condition), 1, f"{name} must have exactly one condition")
            self.assertIn("steps.sync.outcome == 'success'", condition[0], f"{name} can run after a failed sync")

    def test_shipped_snapshot_is_a_usable_hackerpolice_list(self):
        snapshot = load_snapshot(self.ROOT / "snapshot" / "playerlist.vorobey-hackerpolice.json")
        self.assertIsNotNone(snapshot)
        index = snapshot[0] if snapshot is not None else None
        self.assertGreater(len(index.by_steamid), 1000)  # type: ignore[union-attr]
        # The snapshot is a byte-exact copy of the upstream file, so it inherits
        # whatever upstream published -- including the occasional malformed row
        # (a negative account id, say). Those are skipped and reported, and one
        # of them must not fail the build. Still catch a wholesale format change
        # by requiring unusable rows to stay under 1% of the file.
        self.assertLess(index.skipped * 100, index.total)  # type: ignore[union-attr]


if __name__ == "__main__":
    unittest.main(verbosity=2)
