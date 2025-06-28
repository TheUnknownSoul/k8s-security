#!/usr/bin/env bash

declare -a binary_list=("unzip" "trivy" "kubectl" "openjdk-17-jdk" "python3" "cvemap")

declare -a deb_soft=("unzip" "openjdk-17-jdk" "python3")

function install_trivy() {
  directory=$(mktemp -d installerXXXX)
  cd "$directory" || echo "Can't change installation directory" && exit 1
  curl -LO https://github.com/aquasecurity/trivy/releases/download/v0.63.0/trivy_0.63.0_Linux-64bit.deb -o trivy.deb
  sudo dpkg --install trivy*.deb
  cd /tmp || exit 1
  find /tmp -delete -type d -name "installer*"
}

function install_kubectl() {
  directory=$(mktemp -d installerXXXX)
  cd "$directory" || echo "Can't change installation directory" && exit 1
  curl -LO https://dl.k8s.io/release/"$(curl -LS https://dl.k8s.io/release/stable.txt)"/bin/linux/amd64/kubectl
  chmod +x ./kubectl
  sudo mv ./kubectl /usr/local/bin/kubectl
  cd /tmp || exit 1
  find /tmp -delete -type d -name "installer*"
}

function install_cvemap() {
  directory=$(mktemp -d installerXXXX)
  cd "$directory" || exit 1
  curl -LO https://github.com/projectdiscovery/cvemap/releases/download/v0.0.7/cvemap_0.0.7_linux_amd64.zip
  unzip cvemap*.zip
  sudo mv ./cvemap /usr/local/bin/cvemap
  cd /tmp || exit 1
  find /tmp -delete -type d -name "installer*"
}

function check(){
  binary=$1
  if [[ -n $(which "$binary") ]]; then
    echo "$binary installed"
  else
    echo "$binary not installed. Installing..."
    if [[ $(echo "${deb_soft[@]}" | grep -ow "$binary" | wc -w) -eq "1" ]]; then
      echo "apt install $binary"
      sudo apt install "$binary" -y
    else
      install_"${binary}"
    fi
  fi
}

for binary in "${binary_list[@]}"; do
  check "$binary"
done




