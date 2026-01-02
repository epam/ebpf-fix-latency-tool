# GitHub Actions Workflows

This directory contains automated CI/CD workflows for the eBPF FIX Latency Tool.

## Workflows

### 1. CI (`ci.yml`)

**Triggers:**
- Every push to `master` or `main` branch
- Every pull request to `master` or `main` branch

**What it does:**
- ✅ Builds the eBPF programs and userspace tool
- ✅ Runs unit tests (`make test`)
- ✅ Builds static binary for distribution
- ✅ Creates distribution package
- ✅ Uploads build artifacts (available for 30 days)

**Status:** Check the "Actions" tab on GitHub to see build status

---

### 2. Release (`release.yml`)

**Triggers:**
- When you push a version tag (e.g., `v0.0.3`, `v1.0.0`)

**What it does:**
- ✅ Verifies VERSION file matches the git tag
- ✅ Builds and tests the project
- ✅ Creates a GitHub Release
- ✅ Uploads distribution package and static binary
- ✅ Generates changelog from commits since last release

**How to create a release:**

```bash
# 1. Update VERSION file
echo "0.0.4" > VERSION

# 2. Commit the version bump
git add VERSION
git commit -m "Bump version to 0.0.4"

# 3. Create and push a tag
git tag v0.0.4
git push origin master --tags

# 4. GitHub Actions will automatically:
#    - Build the project
#    - Run tests
#    - Create a release at: https://github.com/YOUR_ORG/ebpf-latency-tool/releases/tag/v0.0.4
#    - Attach ebpf-fix-latency-tool-0.0.4.zip
```

**Important:**
- Tag format must be `vX.Y.Z` (e.g., `v0.0.4`, `v1.2.3`)
- VERSION file must match the tag (without the `v` prefix)
- If they don't match, the release workflow will fail

---

## Requirements

Both workflows require Ubuntu 22.04 (provided by GitHub runners) with:
- clang/LLVM for eBPF compilation
- libbpf development headers
- Linux kernel headers
- bpftool

These are automatically installed by the workflows.

## Limitations

⚠️ **Cannot run integration tests in CI:**
- eBPF programs require loading into a real kernel
- GitHub Actions runners don't allow loading eBPF programs (requires root + kernel features)
- Only unit tests can run in CI

For full integration testing, you'll need to run tests locally or on a dedicated test machine.

## Artifacts

CI builds upload artifacts that you can download from the Actions tab:
- `user/ebpf-fix-latency-tool-static` - Static binary
- `ebpf-fix-latency-tool-X.Y.Z.zip` - Distribution package

These are useful for testing builds from PRs before merging.
