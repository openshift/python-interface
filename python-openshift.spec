Name:       python-openshift
Version:    0.2
Release:    1%{?dist}
Summary:    Openshift REST API client

BuildArch:  noarch
Group:      Development/Libraries
License:    ASL 2.0
URL:        https://github.com/openshift/python-interface

# Source is created by
# wget https://github.com/openshift/python-interface/archive/master.tar.gz
Source0: python-interface-master.tar.gz

BuildRequires: python-devel
BuildRequires: python-requests
Requires: python-requests

%description
This is a python interface for the new Openshift REST API.


%prep
%setup -q


%install
python setup.py install --skip-build --root %{buildroot}
mkdir -p %{buildroot}/%{python2_sitelib}/oshift
cp -ar oshift/* %{buildroot}/%{python2_sitelib}/oshift/


%check
#unit2 tests/*.py


%files
%license LICENSE
%doc README
%{python2_sitelib}
%{_bindir}/oshift


%changelog
* Mon Jan 11 2016 Jakub Kadlčík <frostyx@email.cz> 0.2-1
- Initial .spec file

