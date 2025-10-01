set windows-powershell

# show this list
default:
    just --list

# run tests
test:
    uv run pytest

# does a version bump commit
[linux]
bump-commit type=minor: && create-tag
    uv version --bump {{type}}
    git commit -am "$(uv version | awk '{print $2}' | xargs echo "bump to")"
    uv version | awk '{print $2}' | xargs git tag
    git push
    git push --tags

[windows]
bump-commit type=minor: && create-tag
    uv version --bump {{type}}
    git commit -am ("bump to " + (uv version | Select-String -Pattern '\d+\.\d+\.\d+' | ForEach-Object { $_.Matches.Value }))
    git fetch --tags
    git tag (uv version | Select-String -Pattern '\S+' | ForEach-Object { $_.Line.Split(' ')[1] })
    git push
    git push --tags

# creates a new tag for the current version
[linux]
create-tag:
    git fetch --tags
    uv version | awk '{print $2}' | xargs git tag
    git push --tags

[windows]
create-tag:
    git fetch --tags
    git tag (uv version | Select-String -Pattern '\S+' | ForEach-Object { $_.Line.Split(' ')[1] })
    git push --tags


# update deps
[linux]
update:
    nix flake update
    uv sync --all-groups --upgrade

[windows]
update:
    uv sync --all-groups --upgrade


# do a dep bump commit with tag and version
update-commit: update && create-tag
    uv version --bump patch
    git commit -am "bump deps"
    git push

# format
format:
    # TODO: treefmt?
    isort .
    black .
    alejandra .
