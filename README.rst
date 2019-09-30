PyPICloud-swift
===============
PyPICloud-swift - OpenStack Swift storage backend for `PyPICloud <https://pypi.org/project/pypicloud/>`_.

Swift interaction is done using `python-swiftclient <https://pypi.org/project/python-swiftclient/>`_
Connection API.

Configure
---------
Configure storage backend in config field ``pypi.storage``, container name in
``storage.container`` and authentication options.
Example::

    pypi.storage = ppcswift.OpenStackSwiftStorage
    storage.container = pypicloud
    storage.auth_token = b0bb9dbc868d490288b5682a295fad0e
    storage.storage_url = http://127.0.0.1:8080/v1/AUTH_b0bb9dbc868d490288b5682a295fad0e

Configuration options
---------------------

- ``pypi.storage = pypicloud-swift.swift.OpenStackSwiftStorage``
- ``storage.auth_url``
- ``storage.auth_version``
- ``storage.password``
- ``storage.username``
- ``storage.user_id``
- ``storage.tenant_name``
- ``storage.tenant_id``
- ``storage.project_name``
- ``storage.project_id``
- ``storage.user_domain_name``
- ``storage.user_domain_id``
- ``storage.project_domain_name``
- ``storage.project_domain_id``
- ``storage.endpoint_type``
- ``storage.region_name``
- ``storage.auth_token``
- ``storage.storage_url``
- ``storage.storage_policy``
- ``storage.container``

.. note:: use at least options ``storage.auth_url``, ``storage.username`` and
   ``storage.key`` for keystone auth so swiftclient can reauthenticate.

If container is not existing on startup or listing (rebuild package list)
it will be created with storage policy ``storage.storage_policy``.
