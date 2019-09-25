""" Store packages in Openstack Swift object storage """
import logging
from contextlib import closing
from datetime import datetime

from pypicloud.storage.base import IStorage
from pypicloud.models import Package
from pypicloud.util import get_settings

from swiftclient import Connection, ClientException

from pyramid.response import Response

LOG = logging.getLogger(__name__)
SWIFT_METADATA_KEY_PREFIX = 'x-object-meta-pypicloud-'
SWIFT_METADATA_KEY_PREFIX_LEN = len(SWIFT_METADATA_KEY_PREFIX)


class OpenStackSwiftStorage(IStorage):

    """ Storage backend that uses OpenStack Swift """

    @classmethod
    def configure(cls, settings):
        kwargs = super(OpenStackSwiftStorage, cls).configure(settings)

        config = get_settings(
            settings,
            "storage.",
            auth_url=str,
            auth_version=str,
            password=str,
            username=str,
            user_id=str,
            tenant_name=str,
            tenant_id=str,
            project_name=str,
            project_id=str,
            user_domain_name=str,
            user_domain_id=str,
            project_domain_name=str,
            project_domain_id=str,
            endpoint_type=str,
            region_name=str,
            auth_token=str,
            storage_url=str,
            storage_policy=str,
            container=str
        )

        options = {
            'authurl': config.get('auth_url'),
            'auth_version': config.get('auth_version', None),
            'user': config.get('username'),
            'key': config.get('password'),
            'preauthtoken': config.get('auth_token', None),
            'preauthurl': config.get('storage_url', None),
            'os_options': {
                'username': config.get('username', None),
                'user_id': config.get('user_id', None),
                'user_domain_name': config.get('user_domain_name', None),
                'user_domain_id': config.get('user_domain_id', None),
                'project_domain_name': config.get('project_domain_name', None),
                'project_domain_id': config.get('project_domain_id', None),
                'tenant_id': config.get('tenant_id', None),
                'tenant_name': config.get('tenant_name', None),
                'project_id': config.get('project_id', None),
                'project_name': config.get('project_name', None),
                'endpoint_type': config.get('endpoint_type', None),
                'region_name': config.get('region_name', None),
            }
        }

        client = Connection(**options)
        container = config.get('container')
        storage_policy = config.get('storage_policy', None)

        try:
            headers = client.head_container(container)
            LOG.info('Container exist: object_count = %s, bytes_used = %s',
                     headers['x-container-object-count'],
                     headers['x-container-bytes-used'])
        except ClientException as e:
            if e.http_status != 404:
                LOG.error('Failed to check container existence "%s": %s',
                          container, e)
                raise
            create_container(client, container, storage_policy)

        kwargs['client'] = client
        kwargs['container'] = container
        kwargs['storage_policy'] = storage_policy
        return kwargs

    def __init__(self, request, client=None, container=None, **kwargs):
        super(OpenStackSwiftStorage, self).__init__(request)
        self.client = client
        self.container = container
        self.storage_policy = kwargs.get('storage_policy', None)

    def list(self, factory=Package):
        try:
            headers, objects = self.client.get_container(self.container)
        except ClientException as e:
            if e.http_status == 404:
                LOG.warning('Container was removed')
                create_container(self.client, self.container,
                                 self.storage_policy)
                return
            raise

        for obj_info in objects:
            try:
                name, version, filename = obj_info['name'].split('/', 3)
            except ValueError:
                LOG.warning('The object is not like a package: %s', obj_info)
                continue
            last_modified = datetime.strptime(obj_info['last_modified'],
                                              '%Y-%m-%dT%H:%M:%S.%f')
            # Get package metadata from object metadata
            headers = self.client.head_object(self.container, obj_info['name'])
            metadata = {}
            for k, v in headers.items():
                if SWIFT_METADATA_KEY_PREFIX not in k:
                    continue
                key = k[SWIFT_METADATA_KEY_PREFIX_LEN:]
                # Skip metadata that get from object path
                if key in ('name', 'version', 'filename', 'last_modified'):
                    continue
                metadata[key] = v

            yield factory(name, version, filename, last_modified, **metadata)

    def download_response(self, package):
        object_path = get_swift_path(package)
        try:
            headers, obj = self.client.get_object(self.container, object_path,
                                                  resp_chunk_size=65536)
            resp = Response(
                content_type=headers['content-type'],
                content_length=headers['content-length'],
                app_iter=obj,
                conditional_response=True)
        except ClientException as e:
            resp = Response(
                status=e.http_status,
                body=e.http_response_content,
                content_type=e.http_response_headers['content-type'],
                content_length=e.http_response_headers['content-length'])
            return resp

        return resp

    def upload(self, package, datastream):
        object_path = get_swift_path(package)
        metadata = {}
        if package.summary:
            metadata['%ssummary' % SWIFT_METADATA_KEY_PREFIX] = package.summary
        self.client.put_object(
            self.container,
            object_path,
            datastream,
            headers=metadata)

    def delete(self, package):
        object_path = get_swift_path(package)
        try:
            self.client.delete_object(self.container, object_path)
        except ClientException as e:
            if e.http_status != 404:
                LOG.error('Failed to delete object "%s": %s %s',
                          object_path, self.container,
                          e.http_status, e.http_reason)
                if e.http_response_content:
                    LOG.error(e.http_response_content)

    def open(self, package):
        object_path = get_swift_path(package)
        headers, obj = self.client.get_object(self.container, object_path,
                                              resp_chunk_size=65536)
        return closing(obj)

    def check_health(self):
        try:
            self.client.head_container(self.container)
        except ClientException as e:
            LOG.warning('Failed to check storage health: %s', e)
            return False, str(e)
        return True, ''


def get_swift_path(package):
    return '%s/%s/%s' % (package.name, package.version, package.filename)


def create_container(client, name, policy=None):
    LOG.warning('Create container "%s"', name)
    headers = None
    if policy:
        headers = {'x-storage-policy': policy}
    client.put_container(name, headers=headers)
