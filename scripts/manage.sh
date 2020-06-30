#!/bin/bash

set -o nounset

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

source $SCRIPTPATH/metadata

wait_for_conflict() {
  echo -e "\n>>> $(tput setaf 3)Please resolve conflicts in $1$(tput sgr0)"
  echo -e ">>> $(tput setaf 3)Press enter when done$(tput sgr0)"
  read
}

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

if [[ "$branch" -ne "$prev_branch" ]]; then
  for repo in ${independent[@]} ${lineage_forks[@]}; do
    echo -e "\n>>> $(tput setaf 3)Handling $repo$(tput sgr0)"

    cd $repo || exit 1
    git fetch gitlab-priv
    git checkout -b $branch gitlab-priv/$prev_branch || exit 1

    git push -f gitlab-priv HEAD:refs/heads/$branch || exit 1

    cd .. || exit 1
  done
else
  echo "Not handling any independent repos."
fi