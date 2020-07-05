""" Store packages in Openstack Swift object storage """
import json
import logging
from contextlib import closing
from datetime import datetime

from pypicloud.storage.base import IStorage
from pypicloud.models import Package
from pypicloud.util import get_settings
from pyramid.httpexceptions import HTTPOk
from pyramid.httpexceptions import HTTPInternalServerError

from swiftclient import Connection
from swiftclient import ClientException
from swiftclient import swiftclient_version

from ppcswift._version import __version__


LOG = logging.getLogger(__name__)
SWIFT_KEY_SUMMARY_DEPRECATED = 'x-object-meta-pypicloud-summary'
SWIFT_METADATA_KEY_PREFIX = 'x-object-meta-pypi'
SWIFT_METADATA_KEY_PREFIX_LEN = len(SWIFT_METADATA_KEY_PREFIX)
USER_AGENT = 'pypicloud-swift/%s python-swiftclient/%s' % (
    __version__, swiftclient_version.version_string)


class OpenStackSwiftStorage(IStorage):
    """ Storage backend that uses OpenStack Swift """

    @classmethod
    def configure(cls, settings):
        kwargs = super(OpenStackSwiftStorage, cls).configure(settings)

        # noinspection PyTypeChecker
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
            },
            'force_auth_retry': True
        }

        client = Connection(**options)
        container = config.get('container')
        storage_policy = config.get('storage_policy', None)

        if storage_policy:
            try:
                caps = client.get_capabilities()
                LOG.debug('Swift capabilities: %s', caps)
            except ClientException as e:
                LOG.warning("Can't get swift capabilities: %s", e)
            else:
                policies = set()
                for policy in caps.get('swift', {}).get('policies', []):
                    policies.add(policy.get('name', '').lower())
                    for alias in policy.get('aliases', '').split(','):
                        policies.add(alias.strip().lower())
                if policies and storage_policy.lower() not in policies:
                    kwargs['storage_policy'] = storage_policy

        try:
            headers = client.head_container(
                container, headers={'user-agent': USER_AGENT})
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
        return kwargs

    def __init__(self, request, client=None, container=None, **kwargs):
        super(OpenStackSwiftStorage, self).__init__(request)
        self.client = client
        self.container = container
        self.storage_policy = kwargs.get('storage_policy', None)

    @staticmethod
    def get_path(package):
        return '%s/%s/%s' % (package.name, package.version, package.filename)

    @staticmethod
    def path_to_meta_path(path):
        return path + '.meta'

    def get_meta_path(self, package):
        return self.path_to_meta_path(self.get_path(package))

    def _get_old_metadata(self, object_path):
        """ Parse old package metadata stored in object user metadata

        version of old metadata format: 0.2.0
        """
        try:
            headers = self.client.head_object(
                self.container,
                object_path,
                headers={'user-agent': USER_AGENT})
        except ClientException as e:
            LOG.warning('Can\'t get old package metadata "%s": %s',
                        object_path, e)
            return

        metadata = {}
        summary_chunks = {}
        for k, v in headers.items():
            if SWIFT_METADATA_KEY_PREFIX not in k:
                continue
            if k == SWIFT_KEY_SUMMARY_DEPRECATED:
                metadata['summary'] = v
                continue

            key = k[SWIFT_METADATA_KEY_PREFIX_LEN + 1:]
            if key in ('name', 'version', 'filename', 'last_modified'):
                continue

            if 'summary' in key:
                try:
                    chunk_num = int(key.split('summary-', 1)[1])
                except ValueError:
                    LOG.warning('Can\'t parse summary chunk metadata '
                                'of object "%s": key = %s, value = %s',
                                object_path, key, v)
                else:
                    summary_chunks[chunk_num] = v
            else:
                metadata[key] = v

        if summary_chunks:
            summary = ''
            for k in sorted(summary_chunks.keys()):
                summary += summary_chunks[k]
            metadata['summary'] = summary
        return metadata

    def list(self, factory=Package):
        try:
            headers, objects = self.client.get_container(
                self.container, headers={'user-agent': USER_AGENT})
        except ClientException as e:
            if e.http_status == 404:
                LOG.warning('Container was removed')
                create_container(self.client, self.container,
                                 self.storage_policy)
                return
            LOG.error('Error while listing container: %s', e)
            raise HTTPInternalServerError()

        for obj_info in objects:
            object_path = obj_info['name']
            if object_path.endswith('.meta'):
                continue
            try:
                name, version, filename = object_path.split('/', 3)
            except ValueError:
                LOG.warning('The object is not like a package: %s', obj_info)
                continue
            last_modified = datetime.strptime(obj_info['last_modified'],
                                              '%Y-%m-%dT%H:%M:%S.%f')
            object_meta_path = self.path_to_meta_path(object_path)
            try:
                # Get package metadata from object
                headers, data = self.client.get_object(
                    self.container, object_meta_path,
                    headers={'user-agent': USER_AGENT})
            except ClientException as e:
                if e.http_status != 404:
                    LOG.warning('Can\'t get package metadata "%s": %s',
                                object_meta_path, e)
                    continue
                else:
                    # metadata stored in old place
                    metadata = self._get_old_metadata(object_path)
            else:
                metadata = json.loads(data)
            metadata = Package.read_metadata(metadata or {})

            yield factory(name, version, filename, last_modified, **metadata)

    def download_response(self, package):
        object_path = self.get_path(package)
        try:
            headers, data = self.client.get_object(
                self.container, object_path, resp_chunk_size=65536,
                headers={'user-agent': USER_AGENT})
            content_type = headers.get('content-type')
            resp = HTTPOk(content_type=content_type, app_iter=data,
                          conditional_response=True)
        except ClientException as e:
            LOG.error('Failed to get object "%s": %s',
                      object_path, e)
            resp = HTTPInternalServerError()

        return resp

    def upload(self, package, datastream):
        object_path = self.get_path(package)

        LOG.debug('PUT package "%s"', object_path)
        try:
            self.client.put_object(self.container, object_path, datastream,
                                   headers={'user-agent': USER_AGENT})
        except ClientException as e:
            LOG.error('Failed to store package "%s": %s', object_path, e)
            raise HTTPInternalServerError()

        object_meta_path = self.get_meta_path(package)
        metadata = json.dumps(package.get_metadata())
        LOG.debug('PUT package metadata "%s"', object_meta_path)
        try:
            self.client.put_object(self.container, object_meta_path, metadata,
                                   headers={'user-agent': USER_AGENT})
        except ClientException as e:
            LOG.error('Failed to store package metadata "%s": %s',
                      object_meta_path, e)
            raise HTTPInternalServerError()

    def delete(self, package):
        object_path = self.get_path(package)
        try:
            self.client.delete_object(self.container, object_path,
                                      headers={'user-agent': USER_AGENT})
        except ClientException as e:
            if e.http_status != 404:
                LOG.error('Failed to delete package "%s": %s %s',
                          object_path, e.http_status, e.http_reason)
                if e.http_response_content:
                    LOG.error(e.http_response_content)

        object_meta_path = self.get_meta_path(package)
        try:
            self.client.delete_object(self.container, object_meta_path,
                                      headers={'user-agent': USER_AGENT})
        except ClientException as e:
            if e.http_status != 404:
                LOG.error('Failed to delete package metadata "%s": %s %s',
                          object_path, e.http_status, e.http_reason)
                if e.http_response_content:
                    LOG.error(e.http_response_content)

    def open(self, package):
        object_path = self.get_path(package)
        try:
            headers, data = self.client.get_object(
                self.container, object_path, resp_chunk_size=65536,
                headers={'user-agent': USER_AGENT})
        except ClientException as e:
            LOG.error('Failed to get package "%s": %s', object_path, e)
            raise HTTPInternalServerError()
        return closing(data)

    def check_health(self):
        try:
            self.client.head_container(self.container,
                                       headers={'user-agent': USER_AGENT})
        except ClientException as e:
            LOG.warning('Failed to get container metadata: %s', e)
            return False, str(e)
        return True, ''


def create_container(client, name, policy=None):
    LOG.warning('Create container "%s"', name)
    headers = {'user-agent': USER_AGENT}
    if policy:
        headers['x-storage-policy'] = policy
    client.put_container(name, headers=headers)
