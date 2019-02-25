#!/bin/sh
set -e
set -o pipefail

WORKING_DIRECTORY="$PWD"

[ "$GITHUB_PAGES_REPO" ] || {
  echo "ERROR: Environment variable GITHUB_PAGES_REPO is required"
  exit 1
}
[ -z "$CUSTOM_DOMAIN"] && CUSTOM_DOMAIN=charts.spvapi.no
[ -z "$GITHUB_PAGES_BRANCH" ] && GITHUB_PAGES_BRANCH=gh-pages
[ -z "$HELM_CHARTS_SOURCE" ] && HELM_CHARTS_SOURCE="$WORKING_DIRECTORY/stable"
[ -d "$HELM_CHARTS_SOURCE" ] || {
  echo "ERROR: Could not find Helm charts in $HELM_CHARTS_SOURCE"
  exit 1
}
[ -z "$HELM_VERSION" ] && HELM_VERSION=2.12.2
[ "$CIRCLE_BRANCH" ] || {
  echo "ERROR: Environment variable CIRCLE_BRANCH is required"
  exit 1
}

echo "GITHUB_PAGES_REPO=$GITHUB_PAGES_REPO"
echo "CUSTOM_DOMAIN=$CUSTOM_DOMAIN"
echo "GITHUB_PAGES_BRANCH=$GITHUB_PAGES_BRANCH"
echo "HELM_CHARTS_SOURCE=$HELM_CHARTS_SOURCE"
echo "HELM_VERSION=$HELM_VERSION"
echo "CIRCLE_BRANCH=$CIRCLE_BRANCH"

echo '>> Prepare...'
mkdir -p /tmp/helm/bin
mkdir -p /tmp/helm/publish
apk update
apk add ca-certificates git openssh

echo '>> Installing Helm...'
cd /tmp/helm/bin
wget "https://storage.googleapis.com/kubernetes-helm/helm-v${HELM_VERSION}-linux-amd64.tar.gz"
tar -zxf "helm-v${HELM_VERSION}-linux-amd64.tar.gz"
chmod +x linux-amd64/helm
alias helm=/tmp/helm/bin/linux-amd64/helm
helm version -c
helm init -c

echo ">> Checking out $GITHUB_PAGES_BRANCH branch from $GITHUB_PAGES_REPO"
cd /tmp/helm/publish
mkdir -p "$HOME/.ssh"
ssh-keyscan -H github.com >> "$HOME/.ssh/known_hosts"
git clone -b "$GITHUB_PAGES_BRANCH" "git@github.com:$GITHUB_PAGES_REPO.git" .

echo '>> Adding https://$CUSTOM_DOMAIN to repos to support dependencies...'
helm repo add spv-pub-charts https://$CUSTOM_DOMAIN

echo '>> Building charts...'
find "$HELM_CHARTS_SOURCE" -mindepth 1 -maxdepth 1 -type d | while read chart; do
  echo ">>> helm lint $chart"
  helm lint "$chart"
  chart_name="`basename "$chart"`"
  echo ">>> helm update dependencies $chart"
  helm dependency update "$chart"
  echo ">>> helm package -d $chart_name $chart"
  mkdir -p "$chart_name"
  helm package -d "$chart_name" "$chart"
done

find "." -mindepth 1 -maxdepth 1 -type d | while read existingFolder; do
  folder="$(basename $existingFolder)"
  if [ "$folder" != ".git" ] && [ ! -d ${HELM_CHARTS_SOURCE}/$folder ]; then
    echo ">>> Removing deleted folder $existingFolder"
    rm -rf "$existingFolder"
  fi
done


echo '>>> helm repo index'
helm repo index .

if [ "$CIRCLE_BRANCH" != "master" ]; then
  echo "Current branch is not master and do not publish"
  exit 0
fi

echo ">> Publishing to $GITHUB_PAGES_BRANCH branch of $GITHUB_PAGES_REPO"
git config user.email "$CIRCLE_USERNAME@users.noreply.github.com"
git config user.name CircleCI
git add .
git status
git commit -m "Published by CircleCI $CIRCLE_BUILD_URL"
git push origin "$GITHUB_PAGES_BRANCH"
