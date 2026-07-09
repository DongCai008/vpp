FROM fedora:40

# Bootstrap tools needed before VPP's own dependency installer runs
RUN dnf update -y && dnf install -y \
    git make sudo which findutils diffutils procps-ng \
    clang dnf-plugins-core openssl openssl-devel rpm-build \
    && dnf clean all

# install-dep's fedora branch calls `debuginfo-install`, which needs these repos enabled
RUN dnf config-manager --set-enabled fedora-debuginfo updates-debuginfo

# compat-openssl10-devel is no longer available in Fedora's repos (checked on
# both Fedora 40 and 44), but VPP's RPM_DEPENDS still lists it and its own
# $(BR)/.deps.ok check unconditionally `rpm -q`s every entry. Installing this
# empty placeholder first means install-dep's `dnf install` treats it as
# already satisfied instead of failing the whole transaction.
COPY docker/compat-openssl10-devel.spec /tmp/compat-openssl10-devel.spec
RUN rpmbuild -bb --define "_topdir /tmp/rpmbuild" /tmp/compat-openssl10-devel.spec \
    && rpm -i /tmp/rpmbuild/RPMS/noarch/compat-openssl10-devel-*.rpm \
    && rm -rf /tmp/rpmbuild /tmp/compat-openssl10-devel.spec

# Only the Makefile is needed to run install-dep
COPY Makefile /tmp/vpp/Makefile

WORKDIR /tmp/vpp
RUN git init && git config user.name "Docker Build" && git config user.email "docker-build@example.invalid"
RUN UNATTENDED=y make install-dep
RUN rm -rf /tmp/vpp

# The mounted workspace at runtime is owned by the host user, not the
# container's root; git's ownership check would otherwise refuse to run
# `git describe` etc, which breaks VPP's CMake version detection.
RUN git config --system --add safe.directory '*'

WORKDIR /workspace
CMD ["/bin/bash"]
