set windows-powershell

test:
    poetry run pytest

# publish a new version
publish TYPE:
    poetry version {{TYPE}}
    poetry publish --build
