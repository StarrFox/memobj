set windows-powershell

# show this list
default:
    just --list

# run tests
test:
    poetry run pytest

# publish a new version
publish:
    poetry publish --build

# does a version bump commit
bump-commit type: && create-tag
    poetry version {{type}}
    git commit -am "$(poetry version | awk '{print $2}' | xargs echo "bump to")"
    git push

# creates a new tag for the current version
create-tag:
    git fetch --tags
    poetry version | awk '{print $2}' | xargs git tag
    git push --tags

# update deps
update:
    nix flake update
    # the poetry devs dont allow this with normal update for some unknown reason
    poetry up --latest

# do a dep bump commit with tag and version
update-commit: update && create-tag
    poetry version patch
    git commit -am "bump deps"
    git push

# format
format:
    # TODO: treefmt?
    isort .
    black .
    alejandra .

# build test dll
build-test-dll:
    if (!(Test-Path "tests/manual/test_inject/target/release/test_inject.dll")) { cargo build --release --manifest-path tests/manual/test_inject/Cargo.toml }

# build test exe
build-test-exe:
    if (!(Test-Path "tests/manual/test_inject/target/release/inject_target.dll")) { cargo build --release --manifest-path tests/manual/test_inject/Cargo.toml --bin inject_target }

# run manual tests
manual-test: build-test-dll build-test-exe
    poetry run pytest -rs --run-manual tests/manual/

# run all tests
all-tests: test manual-test
