%define _buildid .59

%bcond_with systemd  # without
%bcond_without tests # with
%bcond_without seccomp  # with
# By default, we apply patches to disable tests that don't
# pass in a buildroot environment.
%bcond_with all_tests # without
# To generate the manpages at build-time,
# you must enable the epel repo and toggle
# the pandoc bcond.
%bcond_with pandoc  # without

%global gopath %{_datadir}/gocode

# Don't check gopath/src for Requires because it does not include any
# user-facing tools or other files that are installed in the docker package.
# Some example scripts are included that are intended for other operating
# systems, and rpm generates Requires for things we don't have.
%global __requires_exclude_from %{gopath}/src

%global provider        github
%global provider_tld    com
%global project         docker
%global repo            %{project}

%global import_path %{provider}.%{provider_tld}/%{project}/%{repo}
%global commit      7392c3b0ce0f9d3e918a321c66668c5d1ef4f689
%global shortcommit %(c=%{commit}; echo ${c:0:7})
%global __golang_provides_opts  %{buildroot}%{gopath} %{import_path} %{version}-%{release}

# The commit ids for containerd, tini, libnetwork, and runc here are taken from
# the corresponding variables in the upstream Dockerfile used to construct the
# build container image.
# https://github.com/moby/moby/blob/v17.03.2-ce/hack/dockerfile/binaries-commits
%global containerd_import_path  github.com/docker/containerd
%global containerd_commit       4ab9917febca54791c5f071a9d1f404867857fcc
%global containerd_shortcommit  %(c=%{containerd_commit}; echo ${c:0:7})
%global runc_import_path        github.com/opencontainers/runc
%global runc_commit             54296cf40ad8143b62dbcaa1d90e520a2136ddfe
%global runc_shortcommit        %(c=%{runc_commit}; echo ${c:0:7})
# libnetwork provides the docker-proxy binary.
%global libnetwork_import_path    github.com/docker/libnetwork
%global libnetwork_commit         0f534354b813003a754606689722fe253101bc4e
%global libnetwork_shortcommit    %(c=%{libnetwork_commit}; echo ${c:0:7})
# tini provides the "docker-init" binary
%global tini_import_path          github.com/krallin/tini
%global tini_commit               949e6facb77383876aeff8a6944dde66b3089574
%global tini_shortcommit          %(c=%{tini_commit}; echo ${c:0:7})

# Ensure that docker is built with version of golang used by upstream
%global golang_version          1.7.5

%global         build_tags %{?build_tags} selinux
%if %{with seccomp}
%global         build_tags %{?build_tags} seccomp
%endif
%global         docker_version 17.03.2-ce
%global         docker_rpm_version  17.03.2ce
%global         docker_version_suffix %{nil}
Name:           docker
Version:        %{docker_rpm_version}
Release: 1%{?_buildid}%{?dist}
Summary:        Automates deployment of containerized applications
License:        ASL 2.0 and MIT and BSD and MPLv2.0 and WTFPL
URL:            http://www.docker.com
# only x86_64 for now: https://github.com/docker/docker/issues/136
ExclusiveArch:  x86_64
Source0:        https://github.com/docker/docker/archive/docker-%{docker_version}%{docker_version_suffix}.tar.gz
Source1:        docker.service
Source2:        docker.sysconfig
Source3:        docker-storage.sysconfig
Source4:        https://%{containerd_import_path}/archive/%{containerd_commit}/containerd-%{containerd_shortcommit}.tar.gz
Source5:        https://%{runc_import_path}/archive/%{runc_commit}/runc-%{runc_shortcommit}.tar.gz
Source6:        https://%{libnetwork_import_path}/archive/%{libnetwork_commit}/libnetwork-%{libnetwork_shortcommit}.tar.gz
Source7:        https://%{tini_import_path}/archive/%{tini_commit}/tini-%{tini_shortcommit}.tar.gz
# Amazon-provided sources
Source2000:     docker-%{docker_version}%{docker_version_suffix}-man-pages.tar

# Amazon-provided patches
Patch2001:      docker-1.12.3-sysvinit-use-nohup.patch
Patch2002:      docker-1.12.3-sysvinit-add-storage-opts.patch
Patch2004:      docker-1.7.1-sysvinit-increase-daemon-maxfiles.patch
Patch2007:      docker-1.9.0-sysvinit-stop-before-network.patch
Patch2009:      docker-1.11.1-runc-libcontainer-apply_nosystemd.patch
# Patch out support for the P224 curve in Certificate Transparency, it's
# removed from our openssl library
Patch2010:      docker-1.12.3-CT-remove-P224-curve.patch
# Allow users to control the timeout when waiting for the daemon to start
Patch2011:      docker-1.12.3-sysvinit-configurable-start-timeout.patch
# These patches disable tests that don't work in the AL AMI buildroot environment
# Skip daemon tests that try to mount and unmount volumes
Patch2101:      docker-1.11.1-skip-daemon-tests-that-mount-volumes.patch
# The graphdriver/devmapper tests try to create and mount a loopback fs
Patch2103:      docker-1.9.0-skip-devmapper-tests.patch
# Skip graphdriver/vfs tests that require root privileges and mutate the filesystem
Patch2104:      docker-1.9.0-skip-mutating-vfs-tests.patch
# Skip pkg/archive and pkg/chrootarchive tests that require root privileges
Patch2106:      docker-1.11.1-skip-pkg-archive-tests-that-require-root.patch
# Skip pkg/mount tests that require root privileges
Patch2107:      docker-1.11.1-skip-pkg-mount-tests-that-require-root.patch
# Skip pkg/sysinfo test that tries to write to /proc
Patch2108:      docker-1.9.0-skip-pkg-sysinfo-tests-that-require-root.patch
# Skip volume/local tests that try to mutate the buildroot filesystem
Patch2109:      docker-1.12.3-skip-mutating-volume-local-tests.patch
# Skip tests in pkg/authorization that try to create sockets without being root
Patch2113:      docker-1.11.1-skip-pkg-authorization-tests-that-create-sockets.patch
# Skip tests in pkg/idtools that call mkdir outside the buildroot without privileges
Patch2114:      docker-1.11.1-skip-pkg-idtools-tests-that-require-root.patch
# Skip tests in distribution that generate network traffic
Patch2115:      docker-1.11.1-skip-distribution-tests-that-network.patch
# Skip tests in registry that try to write to /etc/docker/certs.d
Patch2116:      docker-1.11.2-skip-registry-tests-that-require-root.patch
# Skip tests in builder that try to change namespaces
Patch2117:      docker-1.12.3-skip-builder-tests-that-require-root.patch
# Skip Overlay Tar/Untar test which fails in buildroot when setting ext. attributes on overlay fs
Patch2118:      docker-1.12.6-skip-overlay-tar-untar-test.patch
Patch2119:      docker-17.03-skip-daemon-tests-that-require-root.patch
Patch2120:      no-private-mnt-namespace.patch
Patch2123:      runc-allow-git-sha-override.patch
Patch2124:      containerd-allow-git-sha-override.patch
Patch2125:      tini-allow-git-sha-override.patch

# The following patches are imported from a third-party or upstream in order
# to backport a change before we're ready to update to a newer release.
# <nothing here>

BuildRequires:  gcc
BuildRequires:  glibc-static
BuildRequires:  golang >= %{golang_version}
BuildRequires:  device-mapper-devel
BuildRequires:  btrfs-progs-devel >= 3.14.2
BuildRequires:  cmake
%if %{with systemd}
BuildRequires:  pkgconfig(systemd)
# Use appropriate NVR for systemd-units to ensure SocketUser and SocketGroup are available
%if 0%{?fedora} >= 21
Requires:       systemd-units >= 214
%else
%if 0%{?fedora} == 20
Requires:       systemd-units >= 208-20
%else
Requires:       systemd-units >= 204-20
%endif
%endif
%else
%if %{with seccomp}
BuildRequires:  libseccomp-static
%endif
Requires(post):     chkconfig
Requires(preun):    chkconfig
Requires(postun):   initscripts
%endif
%if %{with pandoc}
BuildRequires:  pandoc
%endif
Provides:       docker-io = %{version}
Provides:       lxc-docker = %{version}
Provides:       containerd = 0-1.git%{containerd_shortcommit}
Provides:       runc = 0-1.git%{runc_shortcommit}
Obsoletes:      docker-devel < 17
Obsoletes:      docker-pkg-devel < 17
# need xz to work with ubuntu images
# https://bugzilla.redhat.com/show_bug.cgi?id=1045220
Requires:       xz
# https://bugzilla.redhat.com/show_bug.cgi?id=1034919
Requires:       libcgroup

Requires: device-mapper-libs >= 1.02.90-2.24
# Used by the sysvinit script for mountpoint namespacing
Requires: /usr/bin/unshare
# Docker upstream strongly recommends using a 3.8+ kernel
Requires: kernel >= 3.8
# In Docker 1.9.1, the default filesystem for devmapper
# changed from ext4 to xfs
Requires: xfsprogs
# Older versions of ec2-net-utils call ec2net.hotplug
# for veth interfaces, which causes performance issues
# when quickly creating or deleting lots of containers
Conflicts: ec2-net-utils < 0.4-1.24

# Add provides for all the vendored modules in docker, runc, and containerd
Provides:   bundled(golang(bitbucket.org/ww/goautoneg))
Provides:   bundled(golang(github.com/Azure/go-ansiterm))
Provides:   bundled(golang(github.com/BurntSushi/toml))
Provides:   bundled(golang(github.com/Graylog2/go-gelf))
Provides:   bundled(golang(github.com/Microsoft/go-winio))
Provides:   bundled(golang(github.com/Microsoft/hcsshim))
Provides:   bundled(golang(github.com/RackSec/srslog))
Provides:   bundled(golang(github.com/Sirupsen/logrus))
Provides:   bundled(golang(github.com/agl/ed25519))
Provides:   bundled(golang(github.com/armon/go-metrics))
Provides:   bundled(golang(github.com/armon/go-radix))
Provides:   bundled(golang(github.com/aws/aws-sdk-go))
Provides:   bundled(golang(github.com/beorn7/perks))
Provides:   bundled(golang(github.com/boltdb/bolt))
Provides:   bundled(golang(github.com/cloudflare/cfssl))
Provides:   bundled(golang(github.com/cloudfoundry/gosigar))
Provides:   bundled(golang(github.com/codegangsta/cli))
Provides:   bundled(golang(github.com/coreos/etcd))
Provides:   bundled(golang(github.com/coreos/go-systemd))
Provides:   bundled(golang(github.com/coreos/pkg))
Provides:   bundled(golang(github.com/cyberdelia/go-metrics-graphite))
Provides:   bundled(golang(github.com/deckarep/golang-set))
Provides:   bundled(golang(github.com/docker/containerd))
Provides:   bundled(golang(github.com/docker/distribution))
Provides:   bundled(golang(github.com/docker/docker-credential-helpers))
Provides:   bundled(golang(github.com/docker/engine-api))
Provides:   bundled(golang(github.com/docker/go))
Provides:   bundled(golang(github.com/docker/go-connections))
Provides:   bundled(golang(github.com/docker/go-events))
Provides:   bundled(golang(github.com/docker/go-units))
Provides:   bundled(golang(github.com/docker/libkv))
Provides:   bundled(golang(github.com/docker/libnetwork))
Provides:   bundled(golang(github.com/docker/libtrust))
Provides:   bundled(golang(github.com/docker/notary))
Provides:   bundled(golang(github.com/docker/swarmkit))
Provides:   bundled(golang(github.com/fluent/fluent-logger-golang))
Provides:   bundled(golang(github.com/flynn-archive/go-shlex))
Provides:   bundled(golang(github.com/go-check/check))
Provides:   bundled(golang(github.com/go-ini/ini))
Provides:   bundled(golang(github.com/godbus/dbus))
Provides:   bundled(golang(github.com/gogo/protobuf))
Provides:   bundled(golang(github.com/golang/glog))
Provides:   bundled(golang(github.com/golang/mock))
Provides:   bundled(golang(github.com/golang/protobuf))
Provides:   bundled(golang(github.com/google/certificate-transparency))
Provides:   bundled(golang(github.com/gorilla/context))
Provides:   bundled(golang(github.com/gorilla/mux))
Provides:   bundled(golang(github.com/hashicorp/consul))
Provides:   bundled(golang(github.com/hashicorp/go-immutable-radix))
Provides:   bundled(golang(github.com/hashicorp/go-memdb))
Provides:   bundled(golang(github.com/hashicorp/go-msgpack))
Provides:   bundled(golang(github.com/hashicorp/go-multierror))
Provides:   bundled(golang(github.com/hashicorp/golang-lru))
Provides:   bundled(golang(github.com/hashicorp/memberlist))
Provides:   bundled(golang(github.com/hashicorp/serf))
Provides:   bundled(golang(github.com/imdario/mergo))
Provides:   bundled(golang(github.com/inconshreveable/mousetrap))
Provides:   bundled(golang(github.com/jmespath/go-jmespath))
Provides:   bundled(golang(github.com/kr/pty))
Provides:   bundled(golang(github.com/mattn/go-shellwords))
Provides:   bundled(golang(github.com/mattn/go-sqlite3))
Provides:   bundled(golang(github.com/matttproud/golang_protobuf_extensions))
Provides:   bundled(golang(github.com/miekg/dns))
Provides:   bundled(golang(github.com/miekg/pkcs11))
Provides:   bundled(golang(github.com/mistifyio/go-zfs))
Provides:   bundled(golang(github.com/mreiferson/go-httpclient))
Provides:   bundled(golang(github.com/opencontainers/runc))
Provides:   bundled(golang(github.com/opencontainers/runtime-spec))
Provides:   bundled(golang(github.com/opencontainers/runtime-spec/specs-go))
Provides:   bundled(golang(github.com/opencontainers/specs))
Provides:   bundled(golang(github.com/pborman/uuid))
Provides:   bundled(golang(github.com/philhofer/fwd))
Provides:   bundled(golang(github.com/pivotal-golang/clock))
Provides:   bundled(golang(github.com/pkg/errors))
Provides:   bundled(golang(github.com/prometheus/client_golang))
Provides:   bundled(golang(github.com/prometheus/client_model))
Provides:   bundled(golang(github.com/prometheus/common))
Provides:   bundled(golang(github.com/prometheus/procfs))
Provides:   bundled(golang(github.com/rcrowley/go-metrics))
Provides:   bundled(golang(github.com/samuel/go-zookeeper))
Provides:   bundled(golang(github.com/satori/go.uuid))
Provides:   bundled(golang(github.com/seccomp/libseccomp-golang))
Provides:   bundled(golang(github.com/spf13/cobra))
Provides:   bundled(golang(github.com/spf13/pflag))
Provides:   bundled(golang(github.com/syndtr/gocapability))
Provides:   bundled(golang(github.com/tchap/go-patricia))
Provides:   bundled(golang(github.com/tinylib/msgp))
Provides:   bundled(golang(github.com/ugorji/go))
Provides:   bundled(golang(github.com/urfave/cli))
Provides:   bundled(golang(github.com/vaughan0/go-ini))
Provides:   bundled(golang(github.com/vbatts/tar-split))
Provides:   bundled(golang(github.com/vdemeester/shakers))
Provides:   bundled(golang(github.com/vishvananda/netlink))
Provides:   bundled(golang(github.com/vishvananda/netns))
Provides:   bundled(golang(golang.org/x/crypto))
Provides:   bundled(golang(golang.org/x/net))
Provides:   bundled(golang(golang.org/x/oauth2))
Provides:   bundled(golang(golang.org/x/sys))
Provides:   bundled(golang(google.golang.org/api))
Provides:   bundled(golang(google.golang.org/cloud))
Provides:   bundled(golang(google.golang.org/grpc))
Provides:   bundled(golang(gopkg.in/fsnotify.v1))


%description
Docker is an open-source engine that automates the deployment of any
application as a lightweight, portable, self-sufficient container that will
run virtually anywhere.

Docker containers can encapsulate any payload, and will run consistently on
and between virtually any server. The same container that a developer builds
and tests on a laptop will run at scale, in production*, on VMs, bare-metal
servers, OpenStack clusters, public instances, or combinations of the above.

%prep
%setup -q -n %{project}-%{docker_version}%{docker_version_suffix}
# Unpack runc and containerd
tar xvf %SOURCE4
tar xvf %SOURCE5
tar xvf %SOURCE6
tar xvf %SOURCE7
%if %{without systemd}
%patch2001 -p1
%patch2002 -p1
%patch2004 -p1
%patch2007 -p1
%patch2009 -p1
%endif
%patch2010 -p1
%patch2011 -p1
%if %{without all_tests}
%patch2101 -p1
%patch2103 -p1
%patch2104 -p1
%patch2106 -p1
%patch2107 -p1
%patch2108 -p1
%patch2109 -p1
%patch2113 -p1
%patch2114 -p1
%patch2115 -p1
%patch2116 -p1
%patch2117 -p1
%patch2118 -p1
%patch2119 -p1
%patch2120 -p1
%patch2123 -p1
%patch2124 -p1
%patch2125 -p1
%endif

%if %{with pandoc}
sed -i 's/go-md2man -in "$FILE" -out/pandoc -s -t man "$FILE" -o/g' man/md2man-all.sh
%endif
sed -i 's/\!bash//g' contrib/completion/bash/docker

%build
# Build containerd
pushd containerd-%{containerd_commit}
mkdir -p ./_build/src/github.com/docker
ln -s $(pwd) ./_build/src/%{containerd_import_path}
export GOPATH=$(pwd)/_build
make GIT_COMMIT_OVERRIDE=%{containerd_commit} static
popd

# Build runc
pushd runc-%{runc_commit}
mkdir -p ./_build/src/github.com/opencontainers
ln -s $(pwd) ./_build/src/%{runc_import_path}
export GOPATH=$(pwd)/_build
make GIT_COMMIT_OVERRIDE=%{runc_commit} BUILDTAGS="%{?build_tags} static"
popd

# Build docker-proxy
pushd libnetwork-%{libnetwork_commit}
mkdir -p _build/src/github.com/docker/
ln -s $(pwd) ./_build/src/%{libnetwork_import_path}
export GOPATH=$(pwd)/_build
go build -o "bin/docker-proxy" ./cmd/proxy
popd

# Build docker-init
pushd tini-%{tini_commit}
GIT_COMMIT_OVERRIDE=%{tini_shortcommit} cmake .
make
popd

# set up temporary build gopath, and put our directory there
mkdir -p ./_build/src/github.com/docker
ln -s $(pwd) ./_build/src/%{import_path}

export DOCKER_GITCOMMIT="%{shortcommit}/%{docker_version}%{docker_version_suffix}"
export DOCKER_BUILDTAGS="%{?build_tags}"
export GOPATH=$(pwd)/_build:$(pwd)/vendor:%{gopath}

hack/make.sh dynbinary
%if %{with pandoc}
docs/man/md2man-all.sh
%else
# Provide pre-rendered man pages to avoid needing
# pandoc in the buildroot
tar xvf %{SOURCE2000} -C man
%endif
cp contrib/syntax/vim/LICENSE LICENSE-vim-syntax
cp contrib/syntax/vim/README.md README-vim-syntax.md

%install
rm -rf %{buildroot}
# install binary
install -d %{buildroot}%{_bindir}
install -p -m 755 bundles/%{docker_version}%{docker_version_suffix}/dynbinary-client/docker-%{docker_version}%{docker_version_suffix} %{buildroot}%{_bindir}/docker
install -p -m 755 bundles/%{docker_version}%{docker_version_suffix}/dynbinary-daemon/dockerd-%{docker_version}%{docker_version_suffix} %{buildroot}%{_bindir}/dockerd
install -p -m 755 containerd-%{containerd_commit}/bin/containerd  %{buildroot}%{_bindir}/docker-containerd
install -p -m 755 containerd-%{containerd_commit}/bin/containerd-shim  %{buildroot}%{_bindir}/docker-containerd-shim
install -p -m 755 containerd-%{containerd_commit}/bin/ctr  %{buildroot}%{_bindir}/docker-ctr
install -p -m 755 runc-%{runc_commit}/runc %{buildroot}%{_bindir}/docker-runc
install -p -m 755 libnetwork-%{libnetwork_commit}/bin/docker-proxy %{buildroot}%{_bindir}/docker-proxy
install -p -m 755 tini-%{tini_commit}/tini-static %{buildroot}%{_bindir}/docker-init

# install manpages
install -d %{buildroot}%{_mandir}/man1
install -p -m 644 man/man1/docker*.1 %{buildroot}%{_mandir}/man1
install -d %{buildroot}%{_mandir}/man5
install -p -m 644 man/man5/Dockerfile.5 %{buildroot}%{_mandir}/man5
install -d %{buildroot}%{_mandir}/man8
install -p -m 644 man/man8/docker*.8 %{buildroot}%{_mandir}/man8

# install bash completion
install -dp %{buildroot}%{_datadir}/bash-completion
install -p -m 644 contrib/completion/bash/docker %{buildroot}%{_datadir}/bash-completion

# install vim syntax highlighting
# (in process of being included in default vim)
install -d %{buildroot}%{_datadir}/vim/vimfiles/{doc,ftdetect,syntax}
install -p -m 644 contrib/syntax/vim/doc/dockerfile.txt %{buildroot}%{_datadir}/vim/vimfiles/doc
install -p -m 644 contrib/syntax/vim/ftdetect/dockerfile.vim %{buildroot}%{_datadir}/vim/vimfiles/ftdetect
install -p -m 644 contrib/syntax/vim/syntax/dockerfile.vim %{buildroot}%{_datadir}/vim/vimfiles/syntax

# install udev rules
install -d %{buildroot}%{_sysconfdir}/udev/rules.d
install -p contrib/udev/80-docker.rules %{buildroot}%{_sysconfdir}/udev/rules.d

# install storage dir
install -d %{buildroot}%{_sharedstatedir}/%{repo}

%if %{with systemd}
# install systemd unitfile
install -d %{buildroot}%{_unitdir}
install -p -m 644 %{SOURCE1} %{buildroot}%{_unitdir}
install -p -m 644 contrib/init/systemd/docker.socket %{buildroot}%{_unitdir}
%else
# install systemd/init scripts
install -d %{buildroot}%{_initddir}
install -p -m 755 contrib/init/sysvinit-redhat/docker %{buildroot}%{_initddir}
%endif

# for additional args
install -d %{buildroot}%{_sysconfdir}/sysconfig/
install -p -m 644 %{SOURCE2} %{buildroot}%{_sysconfdir}/sysconfig/docker
install -p -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/sysconfig/docker-storage

# sources
install -d -p %{buildroot}%{gopath}/src/%{import_path}
rm -rf pkg/symlink/testdata

%clean
rm -rf %{buildroot}

%check
%if %{with tests}
# We can't run the tests for runc or containerd in the buildroot,
# because they expect docker to be running.

export DOCKER_BUILDTAGS="%{?build_tags}"

mkdir -p _gopath/src/%{import_path}
sourcedirs="api
builder
cli
cliconfig
client
cmd
container
contrib
daemon
distribution
dockerversion
docs
experimental
hack
image
integration-cli
layer
libcontainerd
migrate
oci
opts
pkg
plugin
profiles
project
reference
registry
restartmanager
runconfig
utils
vendor
volume"
for dir in ${sourcedirs}
do
    ln -s $(pwd)/$dir _gopath/src/%{import_path}/
done

pushd _gopath/src >/dev/null
go_dirs=$(find -L * -name '*_test.go' -printf '%h\n' | sort -u)
popd >/dev/null
if [ -z "${go_dirs}" ]; then
    echo "Testing was requested, but no tests were found"
    exit 1
fi

for go_dir in ${go_dirs}; do
    # There are hundreds of tests in integration-cli, and they all try to launch
    # a docker daemon in the buildroot, so skip that entire module
    if [ "${go_dir}" = "github.com/docker/docker/integration-cli" ] ||
       [ "${go_dir}" = "github.com/docker/docker/libcontainerd" ] ||
       [ "${go_dir}" = "github.com/docker/docker/pkg/term/windows" ]; then
        echo "Skipping ${go_dir}"
        continue
    fi
    %if %{without seccomp}
    if [ "${go_dir}" = "github.com/docker/docker/profiles/seccomp" ]; then
      echo "Skipping seccomp tests"
      continue
    fi
    %endif
    testoutput=$(mktemp)
    GOPATH=%{buildroot}%{gopath}:$(pwd)/_gopath:%{gopath} \
    go test -v -tags "daemon $DOCKER_BUILDTAGS" "${go_dir}" 2>&1 \
    | tee "${testoutput}"
    if [ "${PIPESTATUS[0]}" -ne "0" ]; then
        echo "one or more tests failed in ${go_dir}"
        exit 1
    fi
    if grep -F -q -e 'warning: no tests to run' -e '[no test files]' ${testoutput} ; then
        echo "${go_dir} should contain tests, but none were found"
        exit 1
    fi
    rm -f "${testoutput}"
done
%endif

%pre
getent group docker > /dev/null || %{_sbindir}/groupadd -r docker
exit 0

%post
%if %{with systemd}
%systemd_post docker
%else
if [ "$1" -eq "1" ]; then
# install but don't activate
/sbin/chkconfig --add docker
elif [ "$1" -eq "2" ]; then
# If upgrading, reset the init priorities, to ensure that
# the daemon always stops before networking goes down
# during shutdown and reboot.
/sbin/chkconfig docker resetpriorities || :
fi
%endif

%preun
%if %{with systemd}
%systemd_preun docker
%else
if [ "$1" -eq "0" ]; then
/sbin/service docker stop >/dev/null 2>&1 || :
/sbin/chkconfig --del docker
fi
%endif

%postun
%if %{with systemd}
%systemd_postun_with_restart docker
%else
if [ "$1" -ge "1" ] ; then
        /sbin/service docker condrestart >/dev/null 2>&1 ||:
fi
%endif

%triggerun -- docker < 1.6.0-1.5
# Previous versions of docker 1.5 and 1.6 generated an invalid key.json,
# due to a bug in libtrust.  Now that the bug has been fixed, the daemon
# itself detects the invalid key, and will refuse to start unless it is
# renamed or removed.
# A new key will be generated when the daemon is next started.
# Docker 1.4 and older don't generate this key at all.
keyfile="/etc/docker/key.json"
[ -e "${keyfile}" ] && mv -f "${keyfile}"{,.rpmsave} >/dev/null 2>&1 || :

%files
%doc AUTHORS CHANGELOG.md CONTRIBUTING.md LICENSE MAINTAINERS NOTICE README.md 
%doc LICENSE-vim-syntax README-vim-syntax.md
%{_mandir}/man1/docker-attach.1.*
%{_mandir}/man1/docker-build.1.*
%{_mandir}/man1/docker-commit.1.*
%{_mandir}/man1/docker-cp.1.*
%{_mandir}/man1/docker-create.1.*
%{_mandir}/man1/docker-diff.1.*
%{_mandir}/man1/docker-events.1.*
%{_mandir}/man1/docker-exec.1.*
%{_mandir}/man1/docker-export.1.*
%{_mandir}/man1/docker-history.1.*
%{_mandir}/man1/docker-images.1.*
%{_mandir}/man1/docker-import.1.*
%{_mandir}/man1/docker-info.1.*
%{_mandir}/man1/docker-inspect.1.*
%{_mandir}/man1/docker-kill.1.*
%{_mandir}/man1/docker-load.1.*
%{_mandir}/man1/docker-login.1.*
%{_mandir}/man1/docker-logout.1.*
%{_mandir}/man1/docker-logs.1.*
%{_mandir}/man1/docker-network-connect.1.*
%{_mandir}/man1/docker-network-create.1.*
%{_mandir}/man1/docker-network-disconnect.1.*
%{_mandir}/man1/docker-network-inspect.1.*
%{_mandir}/man1/docker-network-ls.1.*
%{_mandir}/man1/docker-network-rm.1.*
%{_mandir}/man1/docker-pause.1.*
%{_mandir}/man1/docker-port.1.*
%{_mandir}/man1/docker-ps.1.*
%{_mandir}/man1/docker-pull.1.*
%{_mandir}/man1/docker-push.1.*
%{_mandir}/man1/docker-rename.1.*
%{_mandir}/man1/docker-restart.1.*
%{_mandir}/man1/docker-rm.1.*
%{_mandir}/man1/docker-rmi.1.*
%{_mandir}/man1/docker-run.1.*
%{_mandir}/man1/docker-save.1.*
%{_mandir}/man1/docker-search.1.*
%{_mandir}/man1/docker-start.1.*
%{_mandir}/man1/docker-stats.1.*
%{_mandir}/man1/docker-stop.1.*
%{_mandir}/man1/docker-tag.1.*
%{_mandir}/man1/docker-top.1.*
%{_mandir}/man1/docker-unpause.1.*
%{_mandir}/man1/docker-update.1.*
%{_mandir}/man1/docker-version.1.*
%{_mandir}/man1/docker-wait.1.*
%{_mandir}/man1/docker.1.*
%{_mandir}/man1/docker-checkpoint-create.1.*
%{_mandir}/man1/docker-checkpoint-ls.1.*
%{_mandir}/man1/docker-checkpoint-rm.1.*
%{_mandir}/man1/docker-checkpoint.1.*
%{_mandir}/man1/docker-container-attach.1.*
%{_mandir}/man1/docker-container-commit.1.*
%{_mandir}/man1/docker-container-cp.1.*
%{_mandir}/man1/docker-container-create.1.*
%{_mandir}/man1/docker-container-diff.1.*
%{_mandir}/man1/docker-container-exec.1.*
%{_mandir}/man1/docker-container-export.1.*
%{_mandir}/man1/docker-container-inspect.1.*
%{_mandir}/man1/docker-container-kill.1.*
%{_mandir}/man1/docker-container-logs.1.*
%{_mandir}/man1/docker-container-ls.1.*
%{_mandir}/man1/docker-container-pause.1.*
%{_mandir}/man1/docker-container-port.1.*
%{_mandir}/man1/docker-container-prune.1.*
%{_mandir}/man1/docker-container-rename.1.*
%{_mandir}/man1/docker-container-restart.1.*
%{_mandir}/man1/docker-container-rm.1.*
%{_mandir}/man1/docker-container-run.1.*
%{_mandir}/man1/docker-container-start.1.*
%{_mandir}/man1/docker-container-stats.1.*
%{_mandir}/man1/docker-container-stop.1.*
%{_mandir}/man1/docker-container-top.1.*
%{_mandir}/man1/docker-container-unpause.1.*
%{_mandir}/man1/docker-container-update.1.*
%{_mandir}/man1/docker-container-wait.1.*
%{_mandir}/man1/docker-container.1.*
%{_mandir}/man1/docker-deploy.1.*
%{_mandir}/man1/docker-image-build.1.*
%{_mandir}/man1/docker-image-history.1.*
%{_mandir}/man1/docker-image-import.1.*
%{_mandir}/man1/docker-image-inspect.1.*
%{_mandir}/man1/docker-image-load.1.*
%{_mandir}/man1/docker-image-ls.1.*
%{_mandir}/man1/docker-image-prune.1.*
%{_mandir}/man1/docker-image-pull.1.*
%{_mandir}/man1/docker-image-push.1.*
%{_mandir}/man1/docker-image-rm.1.*
%{_mandir}/man1/docker-image-save.1.*
%{_mandir}/man1/docker-image-tag.1.*
%{_mandir}/man1/docker-image.1.*
%{_mandir}/man1/docker-network-prune.1.*
%{_mandir}/man1/docker-network.1.*
%{_mandir}/man1/docker-node-demote.1.*
%{_mandir}/man1/docker-node-inspect.1.*
%{_mandir}/man1/docker-node-ls.1.*
%{_mandir}/man1/docker-node-promote.1.*
%{_mandir}/man1/docker-node-ps.1.*
%{_mandir}/man1/docker-node-rm.1.*
%{_mandir}/man1/docker-node-update.1.*
%{_mandir}/man1/docker-node.1.*
%{_mandir}/man1/docker-plugin-create.1.*
%{_mandir}/man1/docker-plugin-disable.1.*
%{_mandir}/man1/docker-plugin-enable.1.*
%{_mandir}/man1/docker-plugin-inspect.1.*
%{_mandir}/man1/docker-plugin-install.1.*
%{_mandir}/man1/docker-plugin-ls.1.*
%{_mandir}/man1/docker-plugin-push.1.*
%{_mandir}/man1/docker-plugin-rm.1.*
%{_mandir}/man1/docker-plugin-set.1.*
%{_mandir}/man1/docker-plugin-upgrade.1.*
%{_mandir}/man1/docker-plugin.1.*
%{_mandir}/man1/docker-secret-create.1.*
%{_mandir}/man1/docker-secret-inspect.1.*
%{_mandir}/man1/docker-secret-ls.1.*
%{_mandir}/man1/docker-secret-rm.1.*
%{_mandir}/man1/docker-secret.1.*
%{_mandir}/man1/docker-service-create.1.*
%{_mandir}/man1/docker-service-inspect.1.*
%{_mandir}/man1/docker-service-logs.1.*
%{_mandir}/man1/docker-service-ls.1.*
%{_mandir}/man1/docker-service-ps.1.*
%{_mandir}/man1/docker-service-rm.1.*
%{_mandir}/man1/docker-service-scale.1.*
%{_mandir}/man1/docker-service-update.1.*
%{_mandir}/man1/docker-service.1.*
%{_mandir}/man1/docker-stack-deploy.1.*
%{_mandir}/man1/docker-stack-ls.1.*
%{_mandir}/man1/docker-stack-ps.1.*
%{_mandir}/man1/docker-stack-rm.1.*
%{_mandir}/man1/docker-stack-services.1.*
%{_mandir}/man1/docker-stack.1.*
%{_mandir}/man1/docker-swarm-init.1.*
%{_mandir}/man1/docker-swarm-join-token.1.*
%{_mandir}/man1/docker-swarm-join.1.*
%{_mandir}/man1/docker-swarm-leave.1.*
%{_mandir}/man1/docker-swarm-unlock-key.1.*
%{_mandir}/man1/docker-swarm-unlock.1.*
%{_mandir}/man1/docker-swarm-update.1.*
%{_mandir}/man1/docker-swarm.1.*
%{_mandir}/man1/docker-system-df.1.*
%{_mandir}/man1/docker-system-events.1.*
%{_mandir}/man1/docker-system-info.1.*
%{_mandir}/man1/docker-system-prune.1.*
%{_mandir}/man1/docker-system.1.*
%{_mandir}/man1/docker-volume-create.1.*
%{_mandir}/man1/docker-volume-inspect.1.*
%{_mandir}/man1/docker-volume-ls.1.*
%{_mandir}/man1/docker-volume-prune.1.*
%{_mandir}/man1/docker-volume-rm.1.*
%{_mandir}/man1/docker-volume.1.*
%{_mandir}/man5/Dockerfile.5.*
%{_mandir}/man8/dockerd.8.*
%config(noreplace) %{_sysconfdir}/sysconfig/docker
%config(noreplace) %{_sysconfdir}/sysconfig/docker-storage
%{_bindir}/docker
%{_bindir}/dockerd
%{_bindir}/docker-containerd
%{_bindir}/docker-containerd-shim
%{_bindir}/docker-ctr
%{_bindir}/docker-proxy
%{_bindir}/docker-runc
%{_bindir}/docker-init
%if %{with systemd}
%{_unitdir}/docker.service
%{_unitdir}/docker.socket
%else
%{_initddir}/docker
%endif
%{_datadir}/bash-completion/docker
%dir %{_sharedstatedir}/docker
%{_sysconfdir}/udev/rules.d/80-docker.rules
%{_datadir}/vim/vimfiles/doc/dockerfile.txt
%{_datadir}/vim/vimfiles/ftdetect/dockerfile.vim
%{_datadir}/vim/vimfiles/syntax/dockerfile.vim

%changelog
* Mon Jul 31 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Update comments in the spec file to more accurately reflect the provenance of some patches

* Mon Jul 24 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Build tini as docker-init.
- Update spec file for 17.03.2-ce

* Wed Jun 7 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Embed the correct git sha in the tini build

* Fri Jun 2 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Override the git sha information that's compiled into runc and containerd binaries

* Thu May 18 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Revert the removal of the runc nosystemd patch per CR feedback.
- cr cleanup:  * Remove an unused patch  * Don't override BuildRoot

* Wed May 17 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Additional purging of devel packages

* Tue May 9 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Use libseccomp from KaOS

* Fri Apr 28 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Don't run docker daemon in a private mount namespace.

* Thu Apr 13 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Stop generating -devel and -pkg-devel packages

* Wed Apr 12 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Remove special casing for directories containing experimental or windows code.
- clean up some specfile comments

* Tue Apr 11 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Rename a patch

* Mon Apr 10 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Re-add 'utils' to installed source dirs
- Add 'cliconfig' to installed source dirs
- Refresh patches for 17.03.1-ce
- Package 17.03.1-ce
- Encode 'ce' in the docker version string
- Undo the package rename

* Thu Apr 6 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Handle management of the docker daemon process across the package name change
- Update to the full 17.04.0-ce release.
- Patch cleanup for 17.04
- Disable seccomp by default, for now. Install a bunch of new manpages. Obsolete docker < 17.03 so we provide a proper upgrade path for old releases.

* Wed Apr 5 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Skip seccomp tests if not building with seccomp.
- Build with libseccomp

* Wed Mar 29 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Refresh patches for 17.04-ce

* Tue Mar 28 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Update hashes for vendored projects

* Mon Mar 27 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Make docker version RPM friendly
- Update to v17.04.0-ce-rc1

* Mon Feb 27 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Bump release version to 2.

* Thu Feb 23 2017 Noah Meyerhans <nmeyerha@amazon.com>
- Add docker-1.12.6-devmapper-race-fix.patch, backporting the fix for docker issue 27002

* Thu Jan 5 2017 Frederick Lefebvre <fredlef@amazon.com>
- Update to 1.12.6

* Wed Jan 4 2017 Jamie Anderson <jamieand@amazon.com>
- Add sysconfig variable to control timeout waiting for daemon pidfile to appear

* Thu Nov 3 2016 Jamie Anderson <jamieand@amazon.com>
- Fix Provides: for bundled containerd
- Rework patches to skip tests that don't work in a buildroot
- Disable P224 curve in Certificate Transparency
- Rework patches to sysvinit script
- Rework %check to skip experimental and windows code
- Update list of bundled Provides

* Wed Nov 2 2016 Jamie Anderson <jamieand@amazon.com>
- Require golang >= 1.6.3 to match upstream
- Sync to upstream release 1.12.3

* Tue Jun 28 2016 Jamie Anderson <jamieand@amazon.com>
- Add bcond to re-enable tests that don't work in a buildroot
- Skip registry tests that require root access
- Resync to containerd commit required by version 1.11.2
- Resync to upstream release 1.11.2

* Thu May 19 2016 Jamie Anderson <jamieand@amazon.com>
- Add in-tree build of runC
- Add in-tree build of containerd
- Sync to upstream release 1.11.1

* Tue Feb 16 2016 Samuel Karp <skarp@amazon.com>
- Skip test that only runs in 2015, fix test that fails with older coreutils

* Tue Nov 24 2015 Jamie Anderson <jamieand@amazon.com>
- Add Requires: for xfsprogs to support devicemapper default filesystem change
- Update patch that disables docker/daemon tests that don't work in a buildroot
- Sync to upstream version 1.9.1

* Thu Nov 12 2015 Jamie Anderson <jamieand@amazon.com>
- conflict with older ec2-net-utils that calls ec2net.hotplug on veth interfaces
- remove dependency on system sqlite

* Wed Nov 11 2015 Jamie Anderson <jamieand@amazon.com>
- remove empty test file from pkg/term/windows that causes %%check failures
- add patches to disable specific tests that fail in a buildroot environment
- rework check section to discover all modules with tests
- ensure that docker stops before the network on shutdown and reboot
- update list of modules in devel package for version 1.9.0
- update patches to sysvinit script for version 1.9
- add patches to conditionally disable systemd support in libcontainer
- Update list of man pages for version 1.9
- Switch to vendored dependency model
- Sync to upstream version 1.9.0

* Wed Sep 2 2015 Ian Weller <iweller@amazon.com>
- Exclude automatic provides from devel package contents

* Tue Aug 25 2015 Jamie Anderson <jamieand@amazon.com>
- Increase maxfiles for the daemon, but not per-container

* Mon Jul 27 2015 Jamie Anderson <jamieand@amazon.com>
- update testing for version 1.7.1
- docker-devel and docker-pkg-devel should be noarch
- update requires and buildrequires for version 1.7.1
- update location of manpage sources
- use auto-generated go modules provides
- use system libcontainer

* Wed Jul 15 2015 Jamie Anderson <jamieand@amazon.com>
- sync to upstream release 1.7.1

* Tue Jun 2 2015 Jamie Anderson <jamieand@amazon.com>
- Require a 3.8+ kernel, as recommended by upstream.

* Wed May 27 2015 Jamie Anderson <jamieand@amazon.com>
- Remove security patches that have been incorporated upstream
- Update to upstream version 1.6.2

* Thu May 14 2015 Jamie Anderson <jamieand@amazon.com>
- Remove invalid key.json that was created by older libtrust, if one is found
- Require a version of libtrust that supports v2 registries

* Tue May 5 2015 Jamie Anderson <jamieand@amazon.com>
- Backport security fixes from upstream 1.6 branch
- Conditionalize use of vendored distribution/digest from registry-2.0 tools
- Skip a new libcontainer test which doesn't work in a chroot build environment
- Update to upstream release 1.6.0

* Wed Feb 18 2015 Jamie Anderson <jamieand@amazon.com>
- Add conditionalized support for building with in-tree libcontainer
- Require a version of btrfs-progs-devel that includes version.h
- Disable tests for iptables package, they don't work in a build environment
- Include source for devicemapper, pubsub, and urlutil packages
- Remove pkg/log, which was replaced by logrus
- Add new man pages
- Add Requires: for unshare, which is now used by the sysvinit script
- Add new BuildRequires: for logrus and go-fsnotify
- Update to upstream release 1.5.0

* Thu Dec 11 2014 Jamie Anderson <jamieand@amazon.com>
- Update to upstream version 1.3.3 to address CVE-2014-9356, CVE-2014-9357, and CVE-2014-9358

* Wed Nov 26 2014 Tom Kirchner <tjk@amazon.com>
- Require newer device-mapper-libs

* Tue Nov 25 2014 Jamie Anderson <jamieand@amazon.com>
- Update to version 1.3.2 for CVE-2014-6407 and CVE-2014-6408

* Sat Nov 22 2014 Jamie Anderson <jamieand@amazon.com>
- Enable support for backing store configuration options

* Tue Nov 4 2014 Jamie Anderson <jamieand@amazon.com>
- Update to upstream version 1.3.1 Enable tests Fix Provides: for modules that moved from -devel to -pkg-devel or libcontainer
- import source package F21/docker-io-1.3.0-1.fc21
- import source package F21/docker-io-1.2.0-5.fc21
- import source package F21/docker-io-1.2.0-4.fc21
- import source package F21/docker-io-1.2.0-3.fc21

* Mon Oct 20 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.3.0-1
- Resolves: rhbz#1153936 - update to v1.3.0
- don't install zsh files
- iptables=false => ip-masq=false

* Wed Oct 08 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.2.0-5
- Resolves: rhbz#1149882 - systemd unit and socket file updates

* Tue Sep 30 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.2.0-4
- Resolves: rhbz#1139415 - correct path for bash completion
    /usr/share/bash-completion/completions
- versioned provides for docker
- golang versioned requirements for devel and pkg-devel
- remove macros from changelog
- don't own dirs owned by vim, systemd, bash

* Thu Sep 25 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.2.0-3
- Resolves: rhbz#1145660 - support /etc/sysconfig/docker-storage 
  From: Colin Walters <walters@redhat.com>
- patch to ignore selinux if it's disabled
  https://github.com/docker/docker/commit/9e2eb0f1cc3c4ef000e139f1d85a20f0e00971e6
  From: Dan Walsh <dwalsh@redhat.com>

* Mon Sep 8 2014 Jamie Anderson <jamieand@amazon.com>
- Update description of devel package.

* Fri Sep 5 2014 Jamie Anderson <jamieand@amazon.com>
- Update to version 1.2 Move apply_nosystemd patch to golang-libcontainer No longer require bridge-utils

* Thu Sep 4 2014 Jamie Anderson <jamieand@amazon.com>
- import source package F21/docker-io-1.2.0-2.fc21
- import source package F21/docker-io-1.2.0-1.fc21
- import source package F21/docker-io-1.1.2-2.fc21
- import source package F21/docker-io-1.1.2-1.fc21
- import source package F21/docker-io-1.0.0-10.fc21
- import source package F21/docker-io-1.0.0-9.fc21
- import source package F21/docker-io-1.0.0-8.fc21
- import source package F21/docker-io-1.0.0-7.fc21
- import source package F21/docker-io-1.0.0-6.fc21
- import source package F21/docker-io-1.0.0-5.fc21
- import source package F21/docker-io-1.0.0-4.fc21
- import source package F21/docker-io-1.0.0-3.fc21
- import source package F21/docker-io-1.0.0-2.fc21

* Sun Aug 24 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.2.0-2
- Provides docker only for f21 and above

* Sat Aug 23 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.2.0-1
- Resolves: rhbz#1132824 - update to v1.2.0

* Sat Aug 16 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.1.2-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Fri Aug 01 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.1.2-2
- change conditionals

* Thu Jul 31 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.1.2-1
- Resolves: rhbz#1124036 - update to upstream v1.1.2

* Mon Jul 28 2014 Vincent Batts <vbatts@fedoraproject.org> - 1.0.0-10
- split out the import_path/pkg/... libraries, to avoid cyclic deps with libcontainer

* Thu Jul 24 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.0.0-9
- /etc/sysconfig/docker should be config(noreplace)

* Wed Jul 23 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.0.0-8
- Resolves: rhbz#1119849
- Resolves: rhbz#1119413 - min delta between upstream and packaged unitfiles
- devel package owns directories it creates
- ensure min NVRs used for systemd contain fixes RE: CVE-2014-3499

* Wed Jul 16 2014 Vincent Batts <vbatts@fedoraproject.org> - 1.0.0-7
- clean up gopath
- add Provides for docker libraries
- produce a -devel with docker source libraries
- accomodate golang rpm macros

* Tue Jul 01 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.0.0-6
- Resolves: rhbz#1114810 - CVE-2014-3499 (correct bz#)

* Tue Jul 01 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.0.0-5
- Resolves: rhbz#11114810 - CVE-2014-3499

* Tue Jun 24 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.0.0-4
- Set mode,user,group in docker.socket file

* Sat Jun 14 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.0.0-3
- correct bogus date

* Sat Jun 14 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.0.0-2
- RHBZ#1109533 patch libcontainer for finalize namespace error
- RHBZ#1109039 build with updated golang-github-syndtr-gocapability
- install Dockerfile.5 manpage

* Thu Jun 12 2014 Jamie Anderson <jamieand@amazon.com>
- import source package EPEL7/docker-io-1.0.0-1.el7
- import source package EPEL7/docker-io-0.11.1-3.el7
- import source package EPEL7/docker-io-0.10.0-2.el7
- import source package EPEL7/docker-io-0.9.1-1.el7
- import source package EPEL7/docker-io-0.9.0-3.el7

* Mon Jun 09 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 1.0.0-1
- upstream version bump to v1.0.0

* Mon Jun 09 2014 Lokesh Mandvekar <lsm5@fedoraproject.org> - 0.12.0-1
- RHBZ#1105789 Upstream bump to 0.12.0

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.11.1-12
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Thu Jun 05 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.11.1-11
- unitfile should Require socket file (revert change in release 10)

* Fri May 30 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.11.1-10
- do not require docker.socket in unitfile

* Thu May 29 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.11.1-9
- BZ: change systemd service type to 'notify'

* Thu May 29 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.11.1-8
- use systemd socket-activation version

* Thu May 29 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.11.1-7
- add "Provides: docker" as per FPC exception (Matthew Miller
        <mattdm@fedoraproject.org>)

* Thu May 29 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.11.1-6
- don't use docker.sysconfig meant for sysvinit (just to avoid confusion)

* Thu May 29 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.11.1-5
- Bug 1084232 - add /etc/sysconfig/docker for additional args

* Tue May 27 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.11.1-4
- patches for BZ 1088125, 1096375

* Fri May 09 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.11.1-3
- add selinux buildtag
- enable selinux in unitfile

* Fri May 09 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.11.1-2
- get rid of conditionals, separate out spec for each branch

* Thu May 08 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.11.1-1
- Bug 1095616 - upstream bump to 0.11.1
- manpages via pandoc

* Mon Apr 14 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.10.0-2
- regenerate btrfs removal patch
- update commit value

* Mon Apr 14 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.10.0-1
- include manpages from contrib

* Wed Apr 09 2014 Bobby Powers <bobbypowers@gmail.com> - 0.10.0-1
- Upstream version bump

* Thu Mar 27 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.9.1-1
- BZ 1080799 - upstream version bump

* Thu Mar 13 2014 Adam Miller <maxamillion@fedoraproject.org> - 0.9.0-3
- Add lxc requirement for EPEL6 and patch init script to use lxc driver
- Remove tar dep, no longer needed
- Require libcgroup only for EPEL6

* Tue Mar 11 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.9.0-2
- lxc removed (optional)
  http://blog.docker.io/2014/03/docker-0-9-introducing-execution-drivers-and-libcontainer/

* Tue Mar 11 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.9.0-1
- BZ 1074880 - upstream version bump to v0.9.0

* Tue Mar 11 2014 Jamie Anderson <jamieand@amazon.com>
- import source package F19/docker-io-0.9.0-2.fc19
- import source package F19/docker-io-0.9.0-1.fc19
- import source package F19/docker-io-0.8.1-1.fc19

* Wed Feb 19 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.8.1-1
- Bug 1066841 - upstream version bump to v0.8.1
- use sysvinit files from upstream contrib
- BR golang >= 1.2-7

* Thu Feb 13 2014 Adam Miller <maxamillion@fedoraproject.org> - 0.8.0-3
- Remove unneeded sysctl settings in initscript
  https://github.com/dotcloud/docker/pull/4125

* Sat Feb 08 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.8.0-2
- ignore btrfs for rhel7 and clones for now
- include vim syntax highlighting from contrib/syntax/vim

* Wed Feb 05 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.8.0-1
- upstream version bump
- don't use btrfs for rhel6 and clones (yet)

* Mon Jan 20 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.6-2
- bridge-utils only for rhel < 7
- discard freespace when image is removed

* Thu Jan 16 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.6-1
- upstream version bump v0.7.6
- built with golang >= 1.2

* Thu Jan 09 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.5-1
- upstream version bump to 0.7.5

* Thu Jan 09 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.4-1
- upstream version bump to 0.7.4 (BZ #1049793)
- udev rules file from upstream contrib
- unit file firewalld not used, description changes

* Mon Jan 06 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.3-3
- udev rules typo fixed (BZ 1048775)

* Sat Jan 04 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.3-2
- missed commit value in release 1, updated now
- upstream release monitoring (BZ 1048441)

* Sat Jan 04 2014 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.3-1
- upstream release bump to v0.7.3

* Thu Dec 19 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.2-2
- require xz to work with ubuntu images (BZ #1045220)

* Wed Dec 18 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.2-1
- upstream release bump to v0.7.2

* Fri Dec 06 2013 Vincent Batts <vbatts@redhat.com> - 0.7.1-1
- upstream release of v0.7.1

* Mon Dec 02 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.0-14
- sysvinit patch corrected (epel only)
- 80-docker.rules unified for udisks1 and udisks2

* Mon Dec 02 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.0-13
- removed firewall-cmd --add-masquerade

* Sat Nov 30 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.0-12
- systemd for fedora >= 18
- firewalld in unit file changed from Requires to Wants
- firewall-cmd --add-masquerade after docker daemon start in unit file
  (Michal Fojtik <mfojtik@redhat.com>), continue if not present (Michael Young
  <m.a.young@durham.ac.uk>)
- 80-docker.rules included for epel too, ENV variables need to be changed for
  udisks1

* Fri Nov 29 2013 Marek Goldmann <mgoldman@redhat.com> - 0.7.0-11
- Redirect docker log to /var/log/docker (epel only)
- Removed the '-b none' parameter from sysconfig, it's unnecessary since
  we create the bridge now automatically (epel only)
- Make sure we have the cgconfig service started before we start docker,
    RHBZ#1034919 (epel only)

* Thu Nov 28 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.0-10
- udev rules added for fedora >= 19 BZ 1034095
- epel testing pending

* Thu Nov 28 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.0-9
- requires and started after firewalld

* Thu Nov 28 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.0-8
- iptables-fix patch corrected

* Thu Nov 28 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.0-7
- use upstream tarball and patch with mgoldman's commit

* Thu Nov 28 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.0-6
- using mgoldman's shortcommit value 0ff9bc1 for package (BZ #1033606)
- https://github.com/dotcloud/docker/pull/2907

* Wed Nov 27 2013 Adam Miller <maxamillion@fedoraproject.org> - 0.7.0-5
- Fix up EL6 preun/postun to not fail on postun scripts

* Wed Nov 27 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.0-4
- brctl patch for rhel <= 7

* Wed Nov 27 2013 Vincent Batts <vbatts@redhat.com> - 0.7.0-3
- Patch how the bridge network is set up on RHEL (BZ #1035436)

* Wed Nov 27 2013 Vincent Batts <vbatts@redhat.com> - 0.7.0-2
- add libcgroup require (BZ #1034919)

* Tue Nov 26 2013 Marek Goldmann <mgoldman@redhat.com> - 0.7.0-1
- Upstream release 0.7.0
- Using upstream script to build the binary

* Mon Nov 25 2013 Vincent Batts <vbatts@redhat.com> - 0.7-0.20.rc7
- correct the build time defines (bz#1026545). Thanks dan-fedora.

* Fri Nov 22 2013 Adam Miller <maxamillion@fedoraproject.org> - 0.7-0.19.rc7
- Remove xinetd entry, added sysvinit

* Fri Nov 22 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-0.18.rc7
- rc version bump

* Wed Nov 20 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-0.17.rc6
- removed ExecStartPost lines from docker.service (BZ #1026045)
- dockerinit listed in files

* Wed Nov 20 2013 Vincent Batts <vbatts@redhat.com> - 0.7-0.16.rc6
- adding back the none bridge patch

* Wed Nov 20 2013 Vincent Batts <vbatts@redhat.com> - 0.7-0.15.rc6
- update docker source to crosbymichael/0.7.0-rc6
- bridge-patch is not needed on this branch

* Tue Nov 19 2013 Vincent Batts <vbatts@redhat.com> - 0.7-0.14.rc5
- update docker source to crosbymichael/0.7-rc5
- update docker source to 457375ea370a2da0df301d35b1aaa8f5964dabfe
- static magic
- place dockerinit in a libexec
- add sqlite dependency

* Sat Nov 02 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-0.13.dm
- docker.service file sets iptables rules to allow container networking, this
    is a stopgap approach, relevant pull request here:
    https://github.com/dotcloud/docker/pull/2527

* Sat Oct 26 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-0.12.dm
- dm branch
- dockerinit -> docker-init

* Tue Oct 22 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-0.11.rc4
- passing version information for docker build BZ #1017186

* Sat Oct 19 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-0.10.rc4
- rc version bump
- docker-init -> dockerinit
- zsh completion script installed to /usr/share/zsh/site-functions

* Fri Oct 18 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-0.9.rc3
- lxc-docker version matches package version

* Fri Oct 18 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-0.8.rc3
- double quotes removed from buildrequires as per existing golang rules

* Fri Oct 11 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-0.7.rc3
- xinetd file renamed to docker.xinetd for clarity

* Thu Oct 10 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-0.6.rc3
- patched for el6 to use sphinx-1.0-build

* Wed Oct 09 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-0.5.rc3
- rc3 version bump
- exclusivearch x86_64

* Wed Oct 09 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-0.4.rc2
- debuginfo not Go-ready yet, skipped

* Wed Oct 09 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-0.3.rc2
- debuginfo package generated
- buildrequires listed with versions where needed
- conditionals changed to reflect systemd or not
- docker commit value not needed
- versioned provides lxc-docker

* Mon Oct 07 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-2.rc2
- rc branch includes devmapper
- el6 BZ #1015865 fix included

* Sun Oct 06 2013 Lokesh Mandvekar <lsm5@redhat.com> - 0.7-1
- version bump, includes devicemapper
- epel conditionals included
- buildrequires sqlite-devel

* Fri Oct 04 2013 Lokesh Mandvekar <lsm5@fedoraproject.org> - 0.6.3-4.devicemapper
- docker-io service enables IPv4 and IPv6 forwarding
- docker user not needed
- golang not supported on ppc64, docker-io excluded too

* Thu Oct 03 2013 Lokesh Mandvekar <lsm5@fedoraproject.org> - 0.6.3-3.devicemapper
- Docker rebuilt with latest kr/pty, first run issue solved

* Fri Sep 27 2013 Marek Goldmann <mgoldman@redhat.com> - 0.6.3-2.devicemapper
- Remove setfcap from lxc.cap.drop to make setxattr() calls working in the
  containers, RHBZ#1012952

* Thu Sep 26 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.6.3-1.devicemapper
- version bump
- new version solves docker push issues

* Tue Sep 24 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.6.2-14.devicemapper
- package requires lxc

* Tue Sep 24 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.6.2-13.devicemapper
- package requires tar

* Tue Sep 24 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.6.2-12.devicemapper
- /var/lib/docker installed
- package also provides lxc-docker

* Mon Sep 23 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.6.2-11.devicemapper
- better looking url

* Mon Sep 23 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.6.2-10.devicemapper
- release tag changed to denote devicemapper patch

* Mon Sep 23 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.6.2-9
- device-mapper-devel is a buildrequires for alex's code
- docker.service listed as a separate source file

* Sun Sep 22 2013 Matthew Miller <mattdm@fedoraproject.org> 0.6.2-8
- install bash completion
- use -v for go build to show progress

* Sun Sep 22 2013 Matthew Miller <mattdm@fedoraproject.org> 0.6.2-7
- build and install separate docker-init

* Sun Sep 22 2013 Matthew Miller <mattdm@fedoraproject.org> 0.6.2-4
- update to use new source-only golang lib packages

* Sat Sep 21 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.6.2-3
- man page generation from docs/.
- systemd service file created
- dotcloud/tar no longer required

* Fri Sep 20 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.6.2-2
- patched with alex larsson's devmapper code

* Wed Sep 18 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.6.2-1
- Version bump

* Tue Sep 10 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.6.1-2
- buildrequires updated
- package renamed to docker-io

* Fri Aug 30 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.6.1-1
- Version bump
- Package name change from lxc-docker to docker
- Makefile patched from 0.5.3

* Wed Aug 28 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.5.3-5
- File permissions settings included

* Wed Aug 28 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.5.3-4
- Credits in changelog modified as per reference's request

* Tue Aug 27 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.5.3-3
- Dependencies listed as rpm packages instead of tars
- Install section added

* Mon Aug 26 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.5.3-2
- Github packaging
- Deps not downloaded at build time courtesy Elan RuusamÃ¤e
- Manpage and other docs installed

* Fri Aug 23 2013 Lokesh Mandvekar <lsm5@redhat.com> 0.5.3-1
- Initial fedora package
- Some credit to Elan RuusamÃ¤e (glen@pld-linux.org)

