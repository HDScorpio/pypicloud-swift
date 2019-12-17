""" Store packages in Openstack Swift object storage """
import logging
from contextlib import closing
from datetime import datetime

from pypicloud.storage.base import IStorage
from pypicloud.models import Package
from pypicloud.util import get_settings
from pyramid.httpexceptions import HTTPOk
from pyramid.httpexceptions import HTTPInternalServerError

from swiftclient import Connection, ClientException
import six


LOG = logging.getLogger(__name__)
SWIFT_KEY_SUMMARY_DEPRECATED = 'x-object-meta-pypicloud-summary'
SWIFT_METADATA_KEY_PREFIX = 'x-object-meta-pypi'
SWIFT_METADATA_KEY_PREFIX_LEN = len(SWIFT_METADATA_KEY_PREFIX)


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

        try:
            caps = client.get_capabilities()
            LOG.debug('Swift capabilities: %s', caps)
            kwargs['swift'] = caps['swift']
        except ClientException as e:
            LOG.warning("Can't get swift capabilities: %s", e)

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
        limits = kwargs.get('swift', {})
        self.max_meta_value_length = limits.get('max_meta_value_length', 256)
        self.max_meta_count = limits.get('max_meta_count', 90)
        self.max_meta_overall_size = limits.get('max_meta_overall_size', 4096)

    def list(self, factory=Package):
        try:
            headers, objects = self.client.get_container(self.container)
        except ClientException as e:
            if e.http_status == 404:
                LOG.warning('Container was removed')
                create_container(self.client, self.container,
                                 self.storage_policy)
                return
            LOG.error('Error while listing container: %s', e)
            raise HTTPInternalServerError()

        for obj_info in objects:
            try:
                name, version, filename = obj_info['name'].split('/', 3)
            except ValueError:
                LOG.warning('The object is not like a package: %s', obj_info)
                continue
            last_modified = datetime.strptime(obj_info['last_modified'],
                                              '%Y-%m-%dT%H:%M:%S.%f')
            # Get package metadata from object metadata
            try:
                headers = self.client.head_object(self.container,
                                                  obj_info['name'])
            except ClientException as e:
                LOG.warning('Can\'t get object metadata "%s": %s',
                            obj_info['name'], e)
                continue
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
                                    obj_info['name'], key, v)
                    else:
                        summary_chunks[chunk_num] = v
                else:
                    metadata[key] = v

            if summary_chunks:
                summary = ''
                for k in sorted(summary_chunks.keys()):
                    summary += summary_chunks[k]
                metadata['summary'] = summary

            yield factory(name, version, filename, last_modified, **metadata)

    def download_response(self, package):
        object_path = get_swift_path(package)
        try:
            headers, obj = self.client.get_object(self.container, object_path,
                                                  resp_chunk_size=65536)
            content_type = six.ensure_str(headers.get('content-type'))
            resp = HTTPOk(content_type=content_type, app_iter=obj,
                          conditional_response=True)
        except ClientException as e:
            LOG.error('Failed to get object "%s": %s',
                      object_path, e)
            resp = HTTPInternalServerError()

        return resp

    def upload(self, package, datastream):
        object_path = get_swift_path(package)
        metadata = {}
        if package.summary:
            summary_len = len(package.summary)
            meta_index = 0
            pos = 0
            meta_overall_size = 0
            while (pos < summary_len and
                   meta_index < self.max_meta_count):
                key = '%s-summary-%d' % (SWIFT_METADATA_KEY_PREFIX, meta_index)
                value = package.summary[pos:pos + self.max_meta_value_length]
                meta_overall_size += len(key) + len(value)
                if meta_overall_size > self.max_meta_overall_size:
                    break
                metadata[key] = value
                pos += len(value)
                meta_index += 1

        try:
            LOG.debug('PUT object "%s" with metadata: %s',
                      object_path, metadata)
            self.client.put_object(
                self.container,
                object_path,
                datastream,
                headers=metadata)
        except ClientException as e:
            if (e.http_status == 400 and
                    'metadata' in e.http_response_content.lower() and
                    hasattr(datastream, 'seek')):
                LOG.warning('Metadata limits exceed: %s',
                            e.http_response_content)
                datastream.seek(0)
                try:
                    self.client.put_object(self.container, object_path,
                                           datastream)
                except ClientException as e:
                    LOG.error('Failed to put object "%s": %s', object_path, e)
                    raise HTTPInternalServerError()
            else:
                LOG.error('Failed to put object "%s": %s', object_path, e)
                raise HTTPInternalServerError()

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
        try:
            headers, obj = self.client.get_object(self.container, object_path,
                                                  resp_chunk_size=65536)
        except ClientException as e:
            LOG.error('Failed to get object "%s": %s', object_path, e)
            raise HTTPInternalServerError()
        return closing(obj)

    def check_health(self):
        try:
            self.client.head_container(self.container)
        except ClientException as e:
            LOG.warning('Failed to get container metadata: %s', e)
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
