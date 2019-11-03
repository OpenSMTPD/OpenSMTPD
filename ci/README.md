# Continuous Integration 

This directory contains CI/CD related scripts and resources

CI/CD process leverages GitHub Actions as a primary automation platform since
up to 20 parallel workflows are available for opensource projects.

On high level we have multiple dimensions to test: 

 - OS Distribution
 - TLS library implementation: libress, openssl
 - libc implementations: glibc, musl
 - compiler: gcc, clang (not yet tested)

Within this matrix build tests, static code analysis, functional and
integration tests are planned. Currently only build tests and static code
analysis exist. Help is much needed with developing functional and integration
tests.

## Directory strucuture

- [docker](#dockerfiles) dockerfiles for various distributions
- [scripts](#scripts) useful scripts for ci/cd automation


## Design Considerations

- Keep workflow yaml files and execution logic as separate as possible.
  Reference ci scripts from workflow files to allow running same tests
  locally, without depending on github.



# Dockerfiles

Dockerfiles in [docker](docker/) directory can be used for developing and
testing OpenSMTPD.  These dockerfiles are intended to be used for dev/test
cycle ONLY and ARE NOT intended to be a delivery mechanism for end users and
should not be published on external resouces like DockerHub. Dockerfiles in
this folder can be used as a reference for package maintainers of various
distributions.


## Usage

OpenSMTPD provides a set of dockerfiles for getting started with development
quickly locally or with GitHub's Actions.

For each distribution there is a separate dockerfile with a distro name
suffixed.  E.g. `Dockerfile.alpine` is a dockerfile that builds OpenSMTPD in
Alpine Linux environment.

To build:

    docker build -f docker/Dockerfile.alpine -t opensmtpd-alpine


All configuration files that are in `/etc/mail` are taken from `etc/`  directory.


To run the container that you've just built run:

    docker run --name smtpd_server -p 25:25 opensmtpd-alpine



# Scripts

Scripts to automate ci/cd actions:

- [coverity_scan](scripts/coverity_scan.sh) - runs coverity scan and submits 
  the rusult to Coverity. See script contents for usage instructions.

- [generate_certs](scripts/generate_certs.sh) - convenient script to quickly
  generate some TLS certificates. Useful for testing.

# Historical reference

[Initial design discusstion](https://github.com/OpenSMTPD/OpenSMTPD/issues/947)




