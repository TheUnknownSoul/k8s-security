![Static Badge](https://img.shields.io/badge/Language%3A_-_Java_v.17-orange)
![Static Badge](https://img.shields.io/badge/Language%3A_-_Python_v.3-blue)
![Static Badge](https://img.shields.io/badge/Requires%3A_-_trivy_-purple)
![Static Badge](https://img.shields.io/badge/Requires%3A_-_CVEmap_-purple)

# Kubernetes security inspector  :lock: :heavy_check_mark: [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)
Project is under construction.
## Introduction

This tool will help you in assessment Kubernetes security.

#### Required tools 
* Java v.11 +
* Python 3.*
* [Trivy](https://github.com/aquasecurity/trivy)
* [CVEmap](https://github.com/projectdiscovery/cvemap)


## Installation 
* clone repository with ```git clone https://github.com/TheUnknownSoul/k8s-security```
* install all necessary dependencies with ```install_dependencies.sh``` (from /src/main/resources/scripts)
* build ```mvn package -DskipTests```
* run with ```java -jar k8security-0.0.1.jar```

### Version 0.0.1
- Check Role - base access control
- Count same type vulnerabilities 
- Give info about CVE's