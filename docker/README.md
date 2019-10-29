# Dockerfiles

## Disclaimer

This folder contains dockerfiles that can be used for developing and OpenSMTPD.
These dockerfiles are intended to be used for dev/test cycle and ARE NOT
intended to be a delivery mechanism for end users and should not be published
on external resouces like DockerHub.  Dockerfiles in this folder can be used as
a reference for package maintainers of various distributions.


## Usage

OpenSMTPD provides a set of dockerfiles for getting started with development
quickly.

For each distribution there is a separate dockerfile with a distro name
suffixed.  E.g. `Dockerfile.alpine` is a dockerfile that builds OpenSMTPD in
Alpine Linux environment.

To build:

    docker build -f docker/Dockerfile.alpine -t opensmtpd-alpine


All configuration files that are in `/etc/mail` are taken from `etc/`  directory.


To run the container that you've just built run:

    docker run --name smtpd_server -p 25:25 opensmtpd-alpine




...to be continued..
