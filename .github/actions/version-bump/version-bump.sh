#!/usr/bin/env bash
# Compute next semver from latest published release / git tag and PR description directives.
set -euo pipefail

PR_BODY="${PR_BODY:-}"
DEFAULT_BUMP="${DEFAULT_BUMP:-minor}"

write_output() {
  local key="$1" value="$2"
  {
    echo "${key}=${value}"
  } >>"${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}"
}

fail_with_error() {
  local code="$1"
  write_output error "$code"
  write_output current_version ""
  write_output next_version ""
  write_output bump_level ""
  write_output bump_source ""
  exit 1
}

normalize_tag() {
  local tag="$1"
  tag="${tag#v}"
  tag="${tag#V}"
  echo "$tag"
}

is_valid_semver() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

bump_semver() {
  local version="$1" level="$2"
  local major minor patch
  IFS=. read -r major minor patch <<<"$version"
  case "$level" in
    major) echo "$((major + 1)).0.0" ;;
    minor) echo "${major}.$((minor + 1)).0" ;;
    patch) echo "${major}.${minor}.$((patch + 1))" ;;
    *) return 1 ;;
  esac
}

collect_version_candidates() {
  local repo="$1"
  local -a candidates=()
  local tag err

  if [[ -z "${GH_TOKEN:-}" ]]; then
    echo "::warning::GH_TOKEN is not set; cannot query GitHub for existing versions (defaulting to 0.0.0 if none found locally)."
    return 0
  fi

  err="$(mktemp)"
  if release_tags="$(
    gh api "repos/${repo}/releases?per_page=100" \
      --jq '[.[] | select(.draft == false) | .tag_name] | .[]' 2>"$err"
  )"; then
    while IFS= read -r tag || [[ -n "${tag:-}" ]]; do
      [[ -z "$tag" ]] && continue
      candidates+=("$(normalize_tag "$tag")")
    done <<<"$release_tags"
  else
    echo "::warning::Failed to list GitHub releases for ${repo}: $(tr '\n' ' ' <"$err")"
  fi

  if tag_names="$(
    gh api "repos/${repo}/tags?per_page=100" --jq '.[].name' 2>"$err"
  )"; then
    while IFS= read -r tag || [[ -n "${tag:-}" ]]; do
      [[ -z "$tag" ]] && continue
      candidates+=("$(normalize_tag "$tag")")
    done <<<"$tag_names"
  else
    echo "::warning::Failed to list git tags for ${repo}: $(tr '\n' ' ' <"$err")"
  fi
  rm -f "$err"

  local v
  for v in "${candidates[@]}"; do
    if is_valid_semver "$v"; then
      echo "$v"
    fi
  done
}

resolve_current_version() {
  local repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
  local max=""

  while IFS= read -r v; do
    [[ -z "$v" ]] && continue
    if [[ -z "$max" ]] || [[ "$(printf '%s\n%s\n' "$max" "$v" | sort -V | tail -1)" == "$v" ]]; then
      max="$v"
    fi
  done < <(collect_version_candidates "$repo")

  if [[ -n "$max" ]]; then
    echo "$max"
    return 0
  fi

  echo "0.0.0"
}

current_version="$(resolve_current_version)"
if ! is_valid_semver "$current_version"; then
  echo "::error::Resolved version is not valid semver: ${current_version}"
  fail_with_error invalid_current_version
fi

if [[ "$current_version" == "0.0.0" ]]; then
  echo "::notice::No published releases or semver git tags found; treating current version as 0.0.0 (first release)."
else
  echo "::notice::Current version resolved as ${current_version} (max semver from releases and tags)."
fi

declare -a directives=()
if [[ -n "$PR_BODY" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    shopt -s nocasematch
    case "$line" in
      '#major') directives+=('major') ;;
      '#minor') directives+=('minor') ;;
      '#patch') directives+=('patch') ;;
    esac
    shopt -u nocasematch
  done <<<"$PR_BODY"
fi

declare -A seen_levels=()
bump_level=""
for level in "${directives[@]}"; do
  seen_levels[$level]=1
done

distinct_count=${#seen_levels[@]}
if ((distinct_count > 1)); then
  echo "::error::Conflicting semver directives in PR description (#major, #minor, #patch)"
  fail_with_error conflicting_directives
fi

bump_source="implicit"
if ((distinct_count == 1)); then
  for level in "${!seen_levels[@]}"; do
    bump_level="$level"
  done
  bump_source="explicit"
else
  bump_level="$DEFAULT_BUMP"
fi

case "$bump_level" in
  major | minor | patch) ;;
  *)
    echo "::error::Invalid default bump: ${bump_level}"
    fail_with_error invalid_default_bump
    ;;
esac

next_version="$(bump_semver "$current_version" "$bump_level")"

write_output error ""
write_output current_version "$current_version"
write_output next_version "$next_version"
write_output bump_level "$bump_level"
write_output bump_source "$bump_source"

echo "Current: ${current_version} -> Next: ${next_version} (${bump_level}, ${bump_source})"
