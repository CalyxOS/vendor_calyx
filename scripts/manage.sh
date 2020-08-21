#!/bin/bash

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"

source $SCRIPTPATH/metadata

wait_for_conflict() {
  echo -e "\n>>> $(tput setaf 3)Please resolve conflicts in $1$(tput sgr0)"
  echo -e ">>> $(tput setaf 3)Press enter when done$(tput sgr0)"
  read
}

error() {
  echo error: $1, please try again >&2
  echo "Usage: `basename $0` aosp/calyx/independent/kernel/lineage/weblate"
  echo "       aosp includes kernels too"
  echo "       calyx == independent"
  exit 1
}

[[ $# -ne 1 ]] && error "incorrect number of arguments"

DATE=$(date --utc +%Y%m%d-%H%M%S)
GIT_ARGS=""

if [[ -n $DRY_RUN ]]; then
  GIT_ARGS="--dry-run"
fi

if [[ "aosp" == "$1" ]]; then

for repo in "${aosp_forks[@]}"; do
  echo -e "\n>>> $(tput setaf 3)Handling $repo$(tput sgr0)"

  cd $repo || exit 1
  git fetch gitlab-priv
  git branch -m $branch ${branch}-${DATE} 2>/dev/null
  git checkout -b $branch gitlab-priv/$prev_branch || exit 1

  git fetch aosp --tags || exit 1

  git push $GIT_ARGS gitlab-priv HEAD:refs/heads/backup/${prev_branch}-${DATE}
  git pull $GIT_ARGS --rebase=interactive aosp $aosp_tag || wait_for_conflict $repo
  git push $GIT_ARGS -f gitlab-priv HEAD:refs/heads/$branch || exit 1
  git push $GIT_ARGS -f gitlab-priv $aosp_tag:refs/tags/$aosp_tag || exit 1

  if [[ -n $DRY_RUN ]]; then
    git checkout gitlab-priv/$prev_branch
    git branch -D $branch
    git branch -m ${branch}-${DATE} $branch 2>/dev/null
  fi

  cd .. || exit 1
done

fi

if [[ "kernel" == "$1" || "aosp" == "$1" ]]; then

for kernel in "${!kernels[@]}"; do
  if [[ "google_msmdash4dot9" == "$kernel" ]]; then
    kernel="google_msm-4.9"
  fi
  echo -e "\n>>> $(tput setaf 3)Handling kernel_$kernel$(tput sgr0)"

  cd kernel_$kernel || exit 1
  git fetch gitlab-priv
  git branch -m $branch ${branch}-${DATE} 2>/dev/null
  git checkout -b $branch gitlab-priv/$prev_branch || exit 1

  git fetch aosp --tags || exit 1
  if [[ "google_msm-4.9" == "$kernel" ]]; then
    kernel="google_msmdash4dot9"
  fi
  kernel_tag=${kernels[$kernel]}
  if [[ -z $kernel_tag ]]; then
    cd .. || exit 1
    continue
  fi
  git push $GIT_ARGS gitlab-priv HEAD:refs/heads/backup/${prev_branch}-${DATE}
  git pull $GIT_ARGS --rebase=interactive aosp $kernel_tag || wait_for_conflict $kernel
  git push $GIT_ARGS -f gitlab-priv HEAD:refs/heads/$branch || exit 1
  git push $GIT_ARGS -f gitlab-priv $kernel_tag:refs/tags/$kernel_tag || exit 1

  if [[ -n $DRY_RUN ]]; then
    git checkout gitlab-priv/$prev_branch
    git branch -D $branch
    git branch -m ${branch}-${DATE} $branch 2>/dev/null
  fi

  cd .. || exit 1
done

for kernel in "${!kernels[@]}"; do
  if [[ -v ${kernel[@]} ]]; then
  kernel_modules="$kernel[@]"
  for kernel_module in "${!kernel_modules}"; do
    if [[ "google_msmdash4dot9" == "$kernel" ]]; then
      kernel="google_msm-4.9"
    fi
    echo -e "\n>>> $(tput setaf 3)Handling kernel_${kernel}_${kernel_module}$(tput sgr0)"

    cd kernel_${kernel}_${kernel_module} || exit 1
    git fetch gitlab-priv
    git branch -m $branch ${branch}-${DATE} 2>/dev/null
    git checkout -b $branch gitlab-priv/$prev_branch || exit 1

    git fetch aosp --tags || exit 1
    if [[ "google_msm-4.9" == "$kernel" ]]; then
      kernel="google_msmdash4dot9"
    fi
    kernel_tag=${kernels[$kernel]}
    if [[ -z $kernel_tag ]]; then
      cd .. || exit 1
      continue
    fi
    git push $GIT_ARGS gitlab-priv HEAD:refs/heads/backup/${prev_branch}-${DATE}
    git pull $GIT_ARGS --rebase=interactive aosp $kernel_tag || wait_for_conflict ${kernel}_${kernel_module}
    git push $GIT_ARGS -f gitlab-priv HEAD:refs/heads/$branch || exit 1
    git push $GIT_ARGS -f gitlab-priv $kernel_tag:refs/tags/$kernel_tag || exit 1

    if [[ -n $DRY_RUN ]]; then
      git checkout gitlab-priv/$prev_branch
      git branch -D $branch
      git branch -m ${branch}-${DATE} $branch 2>/dev/null
    fi

    cd .. || exit 1
  done
  fi
done

fi

if [[ "lineage" == "$1" ]]; then

for repo in ${lineage_forks[@]}; do
  echo -e "\n>>> $(tput setaf 3)Handling $repo$(tput sgr0)"

  cd $repo || exit 1
  git fetch gitlab-priv
  git branch -m $branch ${branch}-${DATE} 2>/dev/null
  git checkout -b $branch gitlab-priv/$prev_branch || exit 1

  git fetch lineage

  git push $GIT_ARGS gitlab-priv HEAD:refs/heads/backup/${prev_branch}-${DATE}
  git pull $GIT_ARGS --rebase=interactive lineage $lineage_branch || wait_for_conflict $repo
  git push $GIT_ARGS -f gitlab-priv HEAD:refs/heads/$branch || exit 1

  if [[ -n $DRY_RUN ]]; then
    git checkout gitlab-priv/$prev_branch
    git branch -D $branch
    git branch -m ${branch}-${DATE} $branch 2>/dev/null
  fi

  cd .. || exit 1
done

for repo in "${!!lineage_caf_forks[@]}"; do
  echo -e "\n>>> $(tput setaf 3)Handling $repo$(tput sgr0)"

  cd $repo || exit 1
  git fetch gitlab-priv
  git branch -m $branch ${branch}-${DATE} 2>/dev/null
  git checkout -b $branch gitlab-priv/$prev_branch || #exit 1

  git fetch lineage

  git push $GIT_ARGS gitlab-priv HEAD:refs/heads/backup/${prev_branch}-${DATE}
  git pull $GIT_ARGS --rebase=interactive lineage ${lineage_caf_forks[$repo]} || wait_for_conflict $repo
  git push $GIT_ARGS -f gitlab-priv HEAD:refs/heads/$branch || exit 1

  if [[ -n $DRY_RUN ]]; then
    git checkout gitlab-priv/$prev_branch
    git branch -D $branch
    git branch -m ${branch}-${DATE} $branch 2>/dev/null
  fi

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
    git branch -m $branch ${branch}-${DATE} 2>/dev/null
    git checkout -b $branch gitlab-priv/$prev_branch || exit 1

    git push $GIT_ARGS gitlab-priv HEAD:refs/heads/backup/${prev_branch}-${DATE}
    git push $GIT_ARGS -f gitlab-priv HEAD:refs/heads/$branch || exit 1

    if [[ -n $DRY_RUN ]]; then
      git checkout gitlab-priv/$prev_branch
      git branch -D $branch
      git branch -m ${branch}-${DATE} $branch 2>/dev/null
    fi

    cd .. || exit 1
  done
fi

fi

if [[ "weblate" == "$1" ]]; then

for component in "${!weblate_components[@]}"; do
  echo -e "\n>>> $(tput setaf 3)Locking $component$(tput sgr0)"
  wlc lock $component || exit 1

  if ! [[ -n $DRY_RUN ]]; then
    echo -e "\n>>> $(tput setaf 3)Commiting $component$(tput sgr0)"
    wlc commit $component || exit 1
  fi

  repo=${weblate_components[$component]}
  echo -e "\n>>> $(tput setaf 3)Handling $repo$(tput sgr0)"

  cd $repo || exit 1
  git fetch gitlab-priv
  git branch -m $branch weblate-${branch}-${DATE} 2>/dev/null
  git checkout -b $branch gitlab-priv/$branch || exit 1

  git fetch weblate || exit 1

  git push $GIT_ARGS gitlab-priv HEAD:refs/heads/backup/weblate-${branch}-${DATE}
  if ! [[ -n $DRY_RUN ]]; then
    git cherry-pick weblate/$branch || wait_for_conflict $repo
  fi
  git push $GIT_ARGS gitlab-priv HEAD:refs/heads/$branch || exit 1

  if [[ -n $DRY_RUN ]]; then
    git checkout gitlab-priv/$branch
    git branch -D $branch
    git branch -m weblate-${branch}-${DATE} $branch 2>/dev/null
  fi

  cd .. || exit 1

  if ! [[ -n $DRY_RUN ]]; then
    echo -e "\n>>> $(tput setaf 3)Resetting $component$(tput sgr0)"
    wlc reset $component || exit 1
  fi

  echo -e "\n>>> $(tput setaf 3)Unlocking $component$(tput sgr0)"
  wlc unlock $component || exit 1
done

fi
