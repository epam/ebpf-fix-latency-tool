Memo to myself:   For future releases:

  # 1. Update VERSION file
  echo "0.0.4" > VERSION

  # 2. Commit the version bump
  git add VERSION
  git commit -m "Bump version to 0.0.4"

  # 3. Tag and push
  git tag v0.0.4
  git push origin master --tags

