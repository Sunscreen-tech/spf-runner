# Release Process

Internal documentation for releasing sunscreen-fhe to PyPI.

## Prerequisites

- GitHub Environments configured (`pypi-production`, `pypi-test`)
- PyPI API tokens stored as GitHub secrets
- Commit access to main branch

## Pre-release (TestPyPI)

Use pre-releases to test the PyPI publishing workflow before production releases.

1. Bump version (e.g., to `0.1.1`):
   ```bash
   # Update both files:
   # - sunscreen_fhe/pyproject.toml → version = "0.1.1"
   # - sunscreen_fhe/Cargo.toml → version = "0.1.1"
   ```

2. Commit and merge to main:
   ```bash
   git add sunscreen_fhe/pyproject.toml sunscreen_fhe/Cargo.toml
   git commit -m "chore: bump version to 0.1.1"
   # Create PR, get review, squash merge to main
   ```

3. Create pre-release tag:
   ```bash
   git checkout main
   git pull origin main
   git tag v0.1.1-rc1
   git push origin v0.1.1-rc1
   ```

4. Monitor GitHub Actions:
   - Navigate to Actions tab
   - Find "PyPI Release" workflow run
   - Wait for builds to complete
   - Workflow will pause at "Publish to pypi-test"

5. Approve deployment:
   - Click "Review deployments"
   - Select "pypi-test"
   - Click "Approve and deploy"

6. Verify on TestPyPI:
   ```bash
   pip install -i https://test.pypi.org/simple/ sunscreen-fhe==0.1.1rc1
   python -c "import sunscreen_fhe; print(sunscreen_fhe.__version__)"
   ```

## Production Release

1. Ensure version is updated (if not already done in pre-release):
   ```bash
   # Both files should have matching version:
   # - sunscreen_fhe/pyproject.toml → version = "0.1.1"
   # - sunscreen_fhe/Cargo.toml → version = "0.1.1"
   ```

2. Create production tag:
   ```bash
   git checkout main
   git pull origin main
   git tag v0.1.1
   git push origin v0.1.1
   ```

3. Monitor GitHub Actions:
   - Navigate to Actions tab
   - Find "PyPI Release" workflow run
   - Wait for builds to complete (4 platforms)
   - Workflow will pause at "Publish to pypi-production"

4. Approve deployment:
   - Click "Review deployments"
   - Select "pypi-production"
   - Click "Approve and deploy"

5. Verify on PyPI:
   ```bash
   pip install sunscreen-fhe==0.1.1
   python -c "import sunscreen_fhe; print(sunscreen_fhe.__version__)"
   ```

6. Verify package page:
   - https://pypi.org/project/sunscreen-fhe/

## Tag Naming Convention

- Production releases: `v0.1.0`, `v1.2.3` → publishes to PyPI
- Pre-releases: `v0.1.0-rc1`, `v0.1.0-beta.1`, `v0.1.0-alpha.1` → publishes to TestPyPI
- Detection: Any tag with `-` after the version number is treated as pre-release

## Platforms

Wheels are built for:
- Linux x86_64 (manylinux)
- Linux aarch64 (manylinux)
- macOS aarch64 (Apple Silicon)
- Windows x86_64

## Workflow Details

### Version Verification

The workflow automatically verifies that the git tag version matches `pyproject.toml`:
- Tag `v0.1.1` must match `version = "0.1.1"` in pyproject.toml
- Workflow fails if versions don't match
- Pre-release suffixes are stripped for comparison (e.g., `v0.1.1-rc1` → `0.1.1`)

### Manual Approval

Every deployment (TestPyPI or PyPI) requires manual approval via GitHub Environments:

### Troubleshooting

Version mismatch error:
- Ensure tag version matches pyproject.toml
- Check both base version (before `-`) and full version

Workflow not triggering:
- Ensure tag starts with `v` (e.g., `v0.1.0`)
- Check Actions tab for workflow run

Build failures:
- Review workflow logs in GitHub Actions
- Platform-specific build issues logged separately

Duplicate version error on PyPI:
- PyPI doesn't allow re-uploading same version
- Bump patch version (e.g., `0.1.0` → `0.1.1`)
- TestPyPI uses `--skip-existing` to allow retesting same version
