#!/bin/bash

set -o nounset

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

source $SCRIPTPATH/metadata

wait_for_conflict() {
  echo -e "\n>>> $(tput setaf 3)Please resolve conflicts in $1$(tput sgr0)"
  echo -e ">>> $(tput setaf 3)Press enter when done$(tput sgr0)"
  read
}

error() {
  echo error: $1, please try again >&2
  echo "Usage: $0 aosp/calyx/independent/lineage"
  echo "       aosp includes kernels too"
  echo "       calyx == independent"
  exit 1
}

[[ $# -ne 1 ]] && error "incorrect number of arguments"

if [[ "aosp" == "$1" ]]; then

for repo in "${aosp_forks[@]}"; do
  echo -e "\n>>> $(tput setaf 3)Handling $repo$(tput sgr0)"

  cd $repo || exit 1
  git fetch gitlab-priv
  git checkout -b $branch gitlab-priv/$prev_branch || #exit 1

  git fetch aosp --tags || exit 1

  git pull --rebase=interactive aosp $aosp_tag || wait_for_conflict $repo
  git push -f gitlab-priv HEAD:refs/heads/$branch || exit 1
  git push -f gitlab-priv $aosp_tag:refs/tags/$aosp_tag || exit 1

  cd .. || exit 1
done

for kernel in "${!kernels[@]}"; do
  echo -e "\n>>> $(tput setaf 3)Handling kernel_$kernel$(tput sgr0)"

  cd kernel_$kernel || exit 1
  git fetch gitlab-priv
  git checkout -b $branch gitlab-priv/$prev_branch || exit 1

  git fetch aosp --tags || exit 1
  kernel_tag=${kernels[$kernel]}
  if [[ -z $kernel_tag ]]; then
    cd .. || exit 1
    continue
  fi
  git rebase --interactive $kernel_tag || wait_for_conflict $kernel
  git push -f gitlab-priv HEAD:refs/heads/$branch || exit 1
  git push -f gitlab-priv $kernel_tag:refs/tags/$kernel_tag || exit 1

  cd .. || exit 1
done

fi

if [[ "lineage" == "$1" ]]; then

for repo in ${lineage_forks[@]}; do
  echo -e "\n>>> $(tput setaf 3)Handling $repo$(tput sgr0)"

  cd $repo || exit 1
  git fetch gitlab-priv
  git checkout -b $branch gitlab-priv/$prev_branch || #exit 1

  git fetch lineage

  git pull --rebase=interactive lineage $lineage_branch || wait_for_conflict $repo
  git push -f gitlab-priv HEAD:refs/heads/$branch || exit 1

  cd .. || exit 1
done

for repo in "${!!lineage_caf_forks[@]}"; do
  echo -e "\n>>> $(tput setaf 3)Handling $repo$(tput sgr0)"

  cd $repo || exit 1
  git fetch gitlab-priv
  git checkout -b $branch gitlab-priv/$prev_branch || #exit 1

  git fetch lineage

  git pull --rebase=interactive lineage ${lineage_caf_forks[$repo]} || wait_for_conflict $repo
  git push -f gitlab-priv HEAD:refs/heads/$branch || exit 1

  cd .. || exit 1
done

fi

if [[ "calyx" == "$1" || "independent" == "$1" ]]; then

if [[ "$branch" == "$prev_branch" ]]; then
  echo "Not handling any independent repos."
else
  for repo in ${independent[@]}; do
    echo -e "\n>>> $(tput setaf 3)Handling $repo$(tput sgr0)"

    cd $repo || exit 1
    git fetch gitlab-priv
    git checkout -b $branch gitlab-priv/$prev_branch || exit 1

    git push -f gitlab-priv HEAD:refs/heads/$branch || exit 1

    cd .. || exit 1
  done
fi

fi