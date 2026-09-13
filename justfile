import "just.just"

[doc("Run a Python command via uv")]
[group("project")]
[positional-arguments]
python-run *args:
    @uv run "$@"

[doc("Bump the dev version")]
[group("project")]
bump-dev:
    uv version --bump dev

[doc("Build the package")]
[group("project")]
build:
    uv build

[doc("Publish the package to PyPI")]
[group("project")]
publish:
    just python-run dotenv --file pypi.env run uv publish dist/*

[doc("Run pre-commit with custom arguments")]
[group("lint")]
[positional-arguments]
pre-commit *args:
    just python-run pre-commit "$@"

[doc("Run all checks (pre-commit hooks, lint, typecheck)")]
[group("lint")]
lint:
    just pre-commit run --all-files

[doc("Run tests with pytest")]
[group("project")]
[positional-arguments]
test *args:
    just python-run pytest "$@"

[doc("Run lint and tests")]
[group("project")]
check: lint test
