#!/bin/bash

set -o nounset

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

source $SCRIPTPATH/metadata

DELETE_TAG=

build_number=
if [[ $# -eq 1 ]]; then
  build_number=$1
elif [[ $# -ne 0 ]]; then
  exit 1
fi

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

  if [[ -n $DELETE_TAG ]]; then
    git tag -d $DELETE_TAG
    git push gitlab-priv :refs/tags/$DELETE_TAG
    cd .. || exit 1
    continue
  fi

  if [[ -n $build_number ]]; then
    echo "Not pushing tags for now"
    #git tag -s $aosp_version.$build_number -m $aosp_version.$build_number || exit 1
    #git push gitlab-priv $aosp_version.$build_number || exit 1

    if [[ $repo == platform_manifest ]]; then
      git checkout $branch || exit 1
      git branch -D tmp || exit 1
    fi
  else
    git fetch aosp --tags || exit 1

    git pull --rebase aosp $aosp_tag || wait_for_conflict $repo
    git push -f gitlab-priv HEAD:refs/heads/$branch || exit 1
    git push -f gitlab-priv $aosp_tag:refs/tags/$aosp_tag || exit 1
  fi

  cd .. || exit 1
done

for kernel in "${!kernels[@]}"; do
  echo -e "\n>>> $(tput setaf 3)Handling kernel_$kernel$(tput sgr0)"

  cd kernel_$kernel || exit 1
  git fetch gitlab-priv
  git checkout -b $branch gitlab-priv/$prev_branch || exit 1

  if [[ -n $DELETE_TAG ]]; then
    git tag -d $DELETE_TAG
    git push gitlab-priv :refs/tags/$DELETE_TAG
    cd .. || exit 1
    continue
  fi

  if [[ -n $build_number ]]; then
    echo "Not pushing tags for now"
    #git tag -s $aosp_version.$build_number -m $aosp_version.$build_number || exit 1
    #git push gitlab-priv $aosp_version.$build_number || exit 1
  else
    git fetch aosp --tags || exit 1
    kernel_tag=${kernels[$kernel]}
    if [[ -z $kernel_tag ]]; then
      cd .. || exit 1
      continue
    fi
    git rebase $kernel_tag || wait_for_conflict $kernel
    git push -f gitlab-priv HEAD:refs/heads/$branch || exit 1
    git push -f gitlab-priv $kernel_tag:refs/tags/$kernel_tag || exit 1
  fi

  cd .. || exit 1
done

for repo in ${independent[@]}; do
  echo -e "\n>>> $(tput setaf 3)Handling $repo$(tput sgr0)"

  if [[ $repo == platform_manifest ]]; then
    echo "TODO"
  fi

  cd $repo || exit 1
  git fetch gitlab-priv
  git checkout -b $branch gitlab-priv/$prev_branch || exit 1

  if [[ -n $DELETE_TAG ]]; then
    git tag -d $DELETE_TAG
    git push gitlab-priv :refs/tags/$DELETE_TAG
    cd .. || exit 1
    continue
  fi

  if [[ -n $build_number ]]; then
    if [[ $repo == platform_manifest ]]; then
      git checkout -B tmp || exit 1
      sed -i s%refs/heads/$branch%refs/tags/$aosp_version.$build_number% default.xml || exit 1
      git commit default.xml -m $aosp_version.$build_number || exit 1
    fi

    echo "Not pushing tags for now"
    #git tag -s $aosp_version.$build_number -m $aosp_version.$build_number || exit 1
    #git push gitlab-priv $aosp_version.$build_number || exit 1

    if [[ $repo == platform_manifest ]]; then
      git checkout $branch || exit 1
      git branch -D tmp || exit 1
    fi
  else
    git push -f gitlab-priv HEAD:refs/heads/$branch || exit 1
  fi

  cd .. || exit 1
done
