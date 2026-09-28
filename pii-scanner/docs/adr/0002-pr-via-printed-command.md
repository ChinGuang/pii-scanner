# PR flow: print `gh pr create` command, do not call GitHub API

The CLI creates a Fix Branch and commits all Fixes to it, but does not call the GitHub API to open the PR. Instead it prints the exact `gh pr create` command for the user to run. This avoids `GITHUB_TOKEN` setup and `gh` auth requirements during the demo, keeps the tool dependency-free, and still satisfies the requirement of "create a PR for review." Easy to upgrade later by replacing the print statement with a subprocess call.
