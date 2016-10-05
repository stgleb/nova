# Copyright 2011 OpenStack Foundation
# Copyright 2013 IBM Corp.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import mock

import six
import webob

from nova.api.openstack.compute import quota_sets as quotas_v21
from nova.api.openstack.compute import tenant_networks
from nova.api.openstack import extensions
from nova import db
from nova import exception
from nova import quota
from nova import test
from nova.tests.unit.api.openstack import fakes


def quota_set(id, include_server_group_quotas=True):
    res = {'quota_set': {'id': id, 'metadata_items': 128,
           'ram': 51200, 'floating_ips': 10, 'fixed_ips': -1,
           'instances': 10, 'injected_files': 5, 'cores': 20,
           'injected_file_content_bytes': 10240,
           'security_groups': 10, 'security_group_rules': 20,
           'key_pairs': 100, 'injected_file_path_bytes': 255}}
    if include_server_group_quotas:
        res['quota_set']['server_groups'] = 10
        res['quota_set']['server_group_members'] = 10
    return res


class FakeProject(object):
    def __init__(self, project_id, parent_id=None):
        self.id = project_id
        self.parent_id = parent_id


class BaseQuotaSetsTest(test.TestCase):
    include_server_group_quotas = True

    fake_quotas = {'ram': {'limit': 51200,
                           'in_use': 12800,
                           'reserved': 12800},
                   'cores': {'limit': 20,
                             'in_use': 10,
                             'reserved': 5},
                   'instances': {'limit': 100,
                                 'in_use': 0,
                                 'reserved': 0}}

    def setUp(self):
        super(BaseQuotaSetsTest, self).setUp()
        self.default_quotas = {
            'instances': 10,
            'cores': 20,
            'ram': 51200,
            'floating_ips': 10,
            'fixed_ips': -1,
            'metadata_items': 128,
            'injected_files': 5,
            'injected_file_path_bytes': 255,
            'injected_file_content_bytes': 10240,
            'security_groups': 10,
            'security_group_rules': 20,
            'key_pairs': 100,
        }

        if self.include_server_group_quotas:
            self.default_quotas['server_groups'] = 10
            self.default_quotas['server_group_members'] = 10

    def fake_get_settable_quotas(self, context, project_id, user_id=None):
        return {
            'ram': {'minimum': self.fake_quotas['ram']['in_use'] +
                               self.fake_quotas['ram']['reserved'],
                    'maximum': -1},
            'cores': {'minimum': self.fake_quotas['cores']['in_use'] +
                                 self.fake_quotas['cores']['reserved'],
                      'maximum': -1},
            'instances': {'minimum': self.fake_quotas['instances']['in_use'] +
                                     self.fake_quotas['instances']['reserved'],
                          'maximum': -1},
        }

    def get_delete_status_int(self, res):
        # NOTE: on v2.1, http status code is set as wsgi_code of API
        # method instead of status_int in a response object.
        return self.controller.delete.wsgi_code

    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_authorize_show")
    @mock.patch("nova.api.openstack.compute.quota_sets.context.KEYSTONE."
                "get_project")
    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_get_quotas")
    def _test_quotas_show(self, get_quotas_mock, get_project_mock,
                          authorize_mock, project=None, quotas=None, req=None):
        if req is None:
            req = self._get_http_request()

        get_project_mock.return_value = project
        get_quotas_mock.return_value = quotas['quota_set']
        authorize_mock.return_value = True
        res_dict = self.controller.show(req, project.id)

        ref_quota_set = quota_set(str(project.id),
                                  self.include_server_group_quotas)
        self.assertEqual(get_quotas_mock.called, 1)
        self.assertEqual(ref_quota_set, res_dict)

    def _prepare_quotas(self):
        parent_quotas = {}
        child_quotas = {}

        for key, value in six.iteritems(self.default_quotas):
            parent_quotas[key] = {
                'limit': value,
                'in_use': value,
                'reserved': value,
                'child_hard_limits': value
            }

            child_quotas = {
                'limit': value,
                'in_use': value,
                'reserved': value,
                'child_hard_limits': value
            }

        return parent_quotas, child_quotas

    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_authorize_update_or_delete")
    @mock.patch("nova.api.openstack.compute.quota_sets.context.KEYSTONE."
                "get_project")
    @mock.patch("nova.api.openstack.compute.quota_sets.quota.QUOTAS."
                "get_project_quotas")
    @mock.patch("nova.api.openstack.compute.quota_sets.quota.QUOTAS."
                "get_settable_quotas")
    @mock.patch("nova.api.openstack.compute.quota_sets.objects."
                "Quotas.create_limit")
    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_validate_quota_limit")
    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_validate_quota_hierarchy")
    @mock.patch("nova.api.openstack.compute.quota_sets.sqlalchemy_api."
                "quota_allocated_update")
    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_get_quotas")
    @mock.patch('nova.api.validation.validators._SchemaValidator.validate')
    def _test_quotas_update(self, validate_mock, get_quotas_mock,
                            quota_allocated_update_mock,
                            _validate_quota_hierarchy_mock,
                            _validate_quota_limit_mock,
                            create_limit_mock,
                            get_settable_quotas_mock,
                            get_project_quotas_mock, get_project_mock,
                            authorize_mock, body, result, project, req=None, force=False):

        parent_quotas, child_quotas = self._prepare_quotas()
        get_project_mock.return_value = project
        authorize_mock.side_effect = None
        create_limit_mock.side_effect = None
        _validate_quota_limit_mock.side_effect = None
        get_project_quotas_mock.side_effect = [parent_quotas,
                                               child_quotas]
        get_settable_quotas_mock.side_effect = self.fake_get_settable_quotas
        _validate_quota_hierarchy_mock.return_value = 0
        get_quotas_mock.return_value = result['quota_set']

        # Remove force from response body, to pass last assert
        if force:
            result['quota_set'].pop('force')

        if req is None:
            req = self._get_http_request()

        res_dict = self.controller.update(req, 'update_me', body=body)
        self.assertEqual(body, res_dict)
        self.assertTrue(create_limit_mock.called)
        self.assertTrue(authorize_mock.called)

        if not force:
            self.assertTrue(_validate_quota_limit_mock.called)
        self.assertTrue(quota_allocated_update_mock.called)
        self.assertTrue(get_quotas_mock.called)
        self.assertEqual(len(body['quota_set'].keys()),
                         len(create_limit_mock.mock_calls))

    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_authorize_update_or_delete")
    @mock.patch("nova.api.openstack.compute.quota_sets.context.KEYSTONE."
                "get_project")
    @mock.patch("nova.api.openstack.compute.quota_sets.quota.QUOTAS."
                "get_project_quotas")
    @mock.patch("nova.api.openstack.compute.quota_sets.quota.QUOTAS."
                "get_settable_quotas")
    @mock.patch('nova.api.validation.validators._SchemaValidator.validate')
    @mock.patch("nova.api.openstack.compute.quota_sets.objects."
                "Quotas.create_limit")
    def _test_quotas_update_bad_request(self, mock_create_limit,
                                        mock_validate, get_settable_quotas_mock,
                                        get_project_quotas_mock, get_project_mock,
                                        authorize_mock, body, req=None):
        project = FakeProject(1, 2)
        get_project_mock.return_value = project
        authorize_mock.side_effect = None
        parent_quotas, child_quotas = self._prepare_quotas()
        get_project_quotas_mock.side_effect = [parent_quotas,
                                               child_quotas]
        get_settable_quotas_mock.side_effect = self.fake_get_settable_quotas

        if req is None:
            req = self._get_http_request()

        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.update,
                          req, 'update_me', body=body)
        self.assertEqual(0,
                         len(mock_create_limit.mock_calls))


class QuotaSetsTestV21(BaseQuotaSetsTest):
    plugin = quotas_v21
    validation_error = exception.ValidationError

    def setUp(self):
        super(QuotaSetsTestV21, self).setUp()
        self._setup_controller()

    def _setup_controller(self):
        self.ext_mgr = self.mox.CreateMock(extensions.ExtensionManager)
        self.controller = self.plugin.QuotaSetsController(self.ext_mgr)

    def _get_http_request(self, url=''):
        return fakes.HTTPRequest.blank(url)

    def test_format_quota_set(self):
        quota_set = self.controller._format_quota_set('1234',
                                                      self.default_quotas,
                                                      [])
        qs = quota_set['quota_set']

        self.assertEqual(qs['id'], '1234')
        self.assertEqual(qs['instances'], 10)
        self.assertEqual(qs['cores'], 20)
        self.assertEqual(qs['ram'], 51200)
        self.assertEqual(qs['floating_ips'], 10)
        self.assertEqual(qs['fixed_ips'], -1)
        self.assertEqual(qs['metadata_items'], 128)
        self.assertEqual(qs['injected_files'], 5)
        self.assertEqual(qs['injected_file_path_bytes'], 255)
        self.assertEqual(qs['injected_file_content_bytes'], 10240)
        self.assertEqual(qs['security_groups'], 10)
        self.assertEqual(qs['security_group_rules'], 20)
        self.assertEqual(qs['key_pairs'], 100)
        if self.include_server_group_quotas:
            self.assertEqual(qs['server_groups'], 10)
            self.assertEqual(qs['server_group_members'], 10)

    def test_validate_quota_limit(self):
        resource = 'fake'

        # Valid - finite values
        self.assertIsNone(self.controller._validate_quota_limit(resource,
                                                                50, 10, 100))

        # Valid - finite limit and infinite maximum
        self.assertIsNone(self.controller._validate_quota_limit(resource,
                                                                50, 10, -1))

        # Valid - infinite limit and infinite maximum
        self.assertIsNone(self.controller._validate_quota_limit(resource,
                                                                -1, 10, -1))

        # Valid - all infinite
        self.assertIsNone(self.controller._validate_quota_limit(resource,
                                                                -1, -1, -1))

        # Invalid - limit is less than -1
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._validate_quota_limit,
                          resource, -2, 10, 100)

        # Invalid - limit is less than minimum
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._validate_quota_limit,
                          resource, 5, 10, 100)

        # Invalid - limit is greater than maximum
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._validate_quota_limit,
                          resource, 200, 10, 100)

        # Invalid - infinite limit is greater than maximum
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._validate_quota_limit,
                          resource, -1, 10, 100)

        # Invalid - limit is less than infinite minimum
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._validate_quota_limit,
                          resource, 50, -1, -1)

        # Invalid - limit is larger than 0x7FFFFFFF
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._validate_quota_limit,
                          resource, db.MAX_INT + 1, -1, -1)

    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_authorize_update_or_delete")
    @mock.patch("nova.api.openstack.compute.quota_sets.context.KEYSTONE."
                "get_project")
    @mock.patch("nova.api.openstack.compute.quota_sets.quota.QUOTAS."
                "get_defaults")
    def test_quotas_defaults(self, get_defaults_mock, get_project_mock,
                             auth_mock):
        uri = '/v2/fake_tenant/os-quota-sets/fake_tenant/defaults'
        project = FakeProject(1, 2)
        get_project_mock.return_value = project
        req = fakes.HTTPRequest.blank(uri)
        self.default_quotas.update({'id': str(project.id)})
        get_defaults_mock.return_value = self.default_quotas
        expected = {'quota_set': self.default_quotas}
        res_dict = self.controller.defaults(req, project.id)
        self.assertEqual(expected, res_dict)
        self.assertTrue(get_defaults_mock.called)
        self.assertTrue(get_project_mock.called)

    def test_quotas_show(self):
        project = FakeProject(1, 2)

        quotas = {'quota_set': {'cores': 20,
                                'fixed_ips': -1,
                                'floating_ips': 10,
                                'id': str(project.id),
                                'injected_file_content_bytes': 10240,
                                'injected_file_path_bytes': 255,
                                'injected_files': 5,
                                'instances': 10,
                                'key_pairs': 100,
                                'metadata_items': 128,
                                'ram': 51200,
                                'security_group_rules': 20,
                                'server_group_members': 10,
                                'security_groups': 10,
                                'server_groups': 10}}

        self._test_quotas_show(quotas=quotas, project=project)

    def test_quotas_update_success(self):
        project = FakeProject(1, 2)
        self.default_quotas.update({
            'instances': 50,
            'cores': 50
        })
        body = {'quota_set': self.default_quotas}
        quotas_result = {'quota_set': {'cores': 50,
                                       'fixed_ips': -1,
                                       'floating_ips': 10,
                                       'injected_file_content_bytes': 10240,
                                       'injected_file_path_bytes': 255,
                                       'injected_files': 5,
                                       'instances': 50,
                                       'key_pairs': 100,
                                       'metadata_items': 128,
                                       'ram': 51200,
                                       'security_group_rules': 20,
                                       'server_group_members': 10,
                                       'security_groups': 10,
                                       'server_groups': 10}}

        self._test_quotas_update(body=body, result=quotas_result,
                                 project=project)

    def test_quotas_update_zero_value(self):
        self.default_quotas.update({
            'instances': 0,
            'cores': 0,
            'ram': 0
        })

        project = FakeProject(1, 2)
        quotas_result = {'quota_set': {'cores': 0,
                                       'fixed_ips': -1,
                                       'floating_ips': 10,
                                       'injected_file_content_bytes': 10240,
                                       'injected_file_path_bytes': 255,
                                       'injected_files': 5,
                                       'instances': 0,
                                       'key_pairs': 100,
                                       'metadata_items': 128,
                                       'ram': 0,
                                       'security_group_rules': 20,
                                       'server_group_members': 10,
                                       'security_groups': 10,
                                       'server_groups': 10}}
        body = {'quota_set': self.default_quotas}

        self._test_quotas_update(body=body,
                                 result=quotas_result,
                                 project=project)

    def _quotas_update_bad_request_case(self, body):
        req = self._get_http_request()
        self.assertRaises(self.validation_error, self.controller.update,
                          req, 'update_me', body=body)

    def test_quotas_update_invalid_key(self):
        body = {'quota_set': {'instances2': -2, 'cores': -2,
                              'ram': -2, 'floating_ips': -2,
                              'metadata_items': -2, 'injected_files': -2,
                              'injected_file_content_bytes': -2}}
        self._test_quotas_update_bad_request(body=body)

    def test_quotas_update_invalid_limit(self):
        body = {'quota_set': {'instances': -2, 'cores': -2,
                              'ram': -2, 'floating_ips': -2, 'fixed_ips': -2,
                              'metadata_items': -2, 'injected_files': -2,
                              'injected_file_content_bytes': -2}}
        self._test_quotas_update_bad_request(body=body)

    def test_quotas_update_empty_body(self):
        body = {}
        self._test_quotas_update_bad_request(body=body)

    def test_quotas_update_invalid_value_non_int(self):
        # when PUT non integer value
        self.default_quotas.update({
            'instances': 'test'
        })
        body = {'quota_set': self.default_quotas}
        self._test_quotas_update_bad_request(body=body)

    def test_quotas_update_invalid_value_with_float(self):
        # when PUT non integer value
        self.default_quotas.update({
            'instances': 50.5
        })
        body = {'quota_set': self.default_quotas}
        self._test_quotas_update_bad_request(body=body)

    def test_quotas_update_invalid_value_with_unicode(self):
        # when PUT non integer value
        self.default_quotas.update({
            'instances': u'\u30aa\u30fc\u30d7\u30f3'
        })
        body = {'quota_set': self.default_quotas}
        self._test_quotas_update_bad_request(body=body)

    def test_quotas_delete(self):
        req = self._get_http_request()
        self.mox.StubOutWithMock(quota.QUOTAS,
                                 "destroy_all_by_project")
        quota.QUOTAS.destroy_all_by_project(req.environ['nova.context'],
                                            1234)
        self.mox.ReplayAll()
        res = self.controller.delete(req, 1234)
        self.mox.VerifyAll()
        self.assertEqual(202, self.get_delete_status_int(res))

    def test_update_network_quota_disabled(self):
        self.flags(enable_network_quota=False)
        body = {'quota_set': {'networks': 1}}

        self._test_quotas_update_bad_request(body=body)

    def test_update_network_quota_enabled(self):
        self.flags(enable_network_quota=True)
        tenant_networks._register_network_quota()
        body = {'quota_set': {'networks': 1}}
        self.default_quotas['networks'] = 10
        self._test_quotas_update_bad_request(body=body)
        del self.default_quotas['networks']
        del quota.QUOTAS._resources['networks']


class ExtendedQuotasTestV21(BaseQuotaSetsTest):
    plugin = quotas_v21

    def setUp(self):
        super(ExtendedQuotasTestV21, self).setUp()
        self._setup_controller()

    def _setup_controller(self):
        self.ext_mgr = self.mox.CreateMock(extensions.ExtensionManager)
        self.controller = self.plugin.QuotaSetsController(self.ext_mgr)

    def fake_get_quotas(self, context, id, user_id=None, usages=False):
        if usages:
            return self.fake_quotas
        else:
            return {k: v['limit'] for k, v in self.fake_quotas.items()}

    def _get_http_request(self, url=''):
        return fakes.HTTPRequest.blank(url)

    def test_quotas_update_exceed_in_used(self):
        body = {'quota_set': {'instances': 60}}
        self._test_quotas_update_bad_request(body=body)

    def test_quotas_force_update_exceed_in_used(self):
        body = {'quota_set': {'cores': 10, 'force': 'True'}}
        project = FakeProject(1, 2)
        self._test_quotas_update(body=body, project=project, result=body,
                                 force=True)

    def test_quotas_update_good_data(self):
        body = {'quota_set': {'cores': 1,
                              'instances': 1}}
        project = FakeProject(1, 2)
        req = fakes.HTTPRequest.blank('/v2/fake4/os-quota-sets/update_me',
                                      use_admin_context=True)
        self._test_quotas_update(body=body, result=body, project=project,
                                 req=req)

    def test_quotas_update_bad_data(self):
        body = {'quota_set': {'cores': 10,
                              'instances': 1}}
        req = fakes.HTTPRequest.blank('/v2/fake4/os-quota-sets/update_me',
                                      use_admin_context=True)
        self._test_quotas_update_bad_request(body=body, req=req)


class UserQuotasTestV21(BaseQuotaSetsTest):
    plugin = quotas_v21
    include_server_group_quotas = True

    def setUp(self):
        super(UserQuotasTestV21, self).setUp()
        self._setup_controller()

    def _get_http_request(self, url=''):
        return fakes.HTTPRequest.blank(url)

    def _setup_controller(self):
        self.ext_mgr = self.mox.CreateMock(extensions.ExtensionManager)
        self.controller = self.plugin.QuotaSetsController(self.ext_mgr)

    def test_user_quotas_show(self):
        req = self._get_http_request('/v2/fake4/os-quota-sets/1234?user_id=1')
        project = FakeProject(1, 2)
        quotas = {'quota_set': {'cores': 20,
                                'fixed_ips': -1,
                                'floating_ips': 10,
                                'id': str(project.id),
                                'injected_file_content_bytes': 10240,
                                'injected_file_path_bytes': 255,
                                'injected_files': 5,
                                'instances': 10,
                                'key_pairs': 100,
                                'metadata_items': 128,
                                'ram': 51200,
                                'security_group_rules': 20,
                                'server_group_members': 10,
                                'security_groups': 10,
                                'server_groups': 10}}

        self._test_quotas_show(quotas=quotas, project=project, req=req)

    def test_user_quotas_update_success(self):
        body = {'quota_set': {'instances': 10, 'cores': 20,
                              'ram': 51200, 'floating_ips': 10,
                              'fixed_ips': -1, 'metadata_items': 128,
                              'injected_files': 5,
                              'injected_file_content_bytes': 10240,
                              'injected_file_path_bytes': 255,
                              'security_groups': 10,
                              'security_group_rules': 20,
                              'key_pairs': 100}}

        if self.include_server_group_quotas:
            body['quota_set']['server_groups'] = 10
            body['quota_set']['server_group_members'] = 10

        url = '/v2/fake4/os-quota-sets/update_me?user_id=1'
        req = self._get_http_request(url)
        project = FakeProject(1, 2)
        self._test_quotas_update(req=req, project=project, body=body,
                                 result=body)

    def test_user_quotas_update_exceed_project(self):
        body = {'quota_set': {'instances': 100}}

        url = '/v2/fake4/os-quota-sets/update_me?user_id=1'
        req = self._get_http_request(url)
        self._test_quotas_update_bad_request(req=req,
                                             body=body)

    def test_user_quotas_update_good_data(self):
        body = {'quota_set': {'instances': 1,
                              'cores': 1}}

        url = '/v2/fake4/os-quota-sets/update_me?user_id=1'
        req = fakes.HTTPRequest.blank(url, use_admin_context=True)
        project = FakeProject(1, 2)
        self._test_quotas_update(req=req, project=project, body=body,
                                 result=body)

    def test_user_quotas_update_bad_data(self):
        body = {'quota_set': {'instances': -20,
                              'cores': 1}}

        url = '/v2/fake4/os-quota-sets/update_me?user_id=1'
        req = fakes.HTTPRequest.blank(url, use_admin_context=True)
        self._test_quotas_update_bad_request(req=req,
                                             body=body)

    def test_user_quotas_delete(self):
        url = '/v2/fake4/os-quota-sets/1234?user_id=1'
        req = self._get_http_request(url)
        self.mox.StubOutWithMock(quota.QUOTAS,
                                 "destroy_all_by_project_and_user")
        quota.QUOTAS.destroy_all_by_project_and_user(
            req.environ['nova.context'], 1234, '1')
        self.mox.ReplayAll()
        res = self.controller.delete(req, 1234)
        self.mox.VerifyAll()
        self.assertEqual(202, self.get_delete_status_int(res))


class QuotaSetsPolicyEnforcementV21(test.NoDBTestCase):

    def setUp(self):
        super(QuotaSetsPolicyEnforcementV21, self).setUp()
        self.controller = quotas_v21.QuotaSetsController()
        self.req = fakes.HTTPRequest.blank('')

    def test_delete_policy_failed(self):
        rule_name = "os_compute_api:os-quota-sets:delete"
        self.policy.set_rules({rule_name: "project_id:non_fake"})
        exc = self.assertRaises(
            exception.PolicyNotAuthorized,
            self.controller.delete, self.req, fakes.FAKE_UUID)
        self.assertEqual(
            "Policy doesn't allow %s to be performed." % rule_name,
            exc.format_message())

    def test_defaults_policy_failed(self):
        rule_name = "os_compute_api:os-quota-sets:defaults"
        self.policy.set_rules({rule_name: "project_id:non_fake"})
        exc = self.assertRaises(
            exception.PolicyNotAuthorized,
            self.controller.defaults, self.req, fakes.FAKE_UUID)
        self.assertEqual(
            "Policy doesn't allow %s to be performed." % rule_name,
            exc.format_message())

    def test_show_policy_failed(self):
        rule_name = "os_compute_api:os-quota-sets:show"
        self.policy.set_rules({rule_name: "project_id:non_fake"})
        exc = self.assertRaises(
            exception.PolicyNotAuthorized,
            self.controller.show, self.req, fakes.FAKE_UUID)
        self.assertEqual(
            "Policy doesn't allow %s to be performed." % rule_name,
            exc.format_message())

    def test_detail_policy_failed(self):
        rule_name = "os_compute_api:os-quota-sets:detail"
        self.policy.set_rules({rule_name: "project_id:non_fake"})
        exc = self.assertRaises(
            exception.PolicyNotAuthorized,
            self.controller.detail, self.req, fakes.FAKE_UUID)
        self.assertEqual(
            "Policy doesn't allow %s to be performed." % rule_name,
            exc.format_message())

    def test_update_policy_failed(self):
        rule_name = "os_compute_api:os-quota-sets:update"
        self.policy.set_rules({rule_name: "project_id:non_fake"})
        exc = self.assertRaises(
            exception.PolicyNotAuthorized,
            self.controller.update, self.req, fakes.FAKE_UUID,
            body={'quota_set': {}})
        self.assertEqual(
            "Policy doesn't allow %s to be performed." % rule_name,
            exc.format_message())


class QuotaSetsTestV236(test.NoDBTestCase):

    def setUp(self):
        super(QuotaSetsTestV236, self).setUp()
        self.flags(enable_network_quota=True)
        tenant_networks._register_network_quota()
        self.old_req = fakes.HTTPRequest.blank('', version='2.1')
        self.filtered_quotas = ['fixed_ips', 'floating_ips', 'networks',
            'security_group_rules', 'security_groups']
        self.controller = quotas_v21.QuotaSetsController()
        self.req = fakes.HTTPRequest.blank('', version='2.36')
        self.addCleanup(self._remove_network_quota)

    def _remove_network_quota(self):
        del quota.QUOTAS._resources['networks']

    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_authorize_show")
    @mock.patch("nova.api.openstack.compute.quota_sets.context.KEYSTONE."
                "get_project")
    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_get_quotas")
    def _ensure_filtered_quotas_existed_in_old_api(self, get_quotas_mock,
                                                   get_project_mock,
                                                   authorize_mock):
        project = FakeProject(1, 2)
        quotas = {'cores': 20,
                  'fixed_ips': -1,
                  'floating_ips': 10,
                  'id': str(project.id),
                  'injected_file_content_bytes': 10240,
                  'injected_file_path_bytes': 255,
                  'injected_files': 5,
                  'instances': 10,
                  'key_pairs': 100,
                  'metadata_items': 128,
                  'ram': 51200,
                  'networks': 1,
                  'security_group_rules': 20,
                  'server_group_members': 10,
                  'security_groups': 10,
                  'server_groups': 10}

        get_project_mock.return_value = project
        get_quotas_mock.return_value = quotas
        authorize_mock.return_value = True
        res_dict = self.controller.show(self.old_req, project.id)
        ref_quota_set = {'quota_set': quotas}

        self.assertEqual(get_quotas_mock.called, 1)
        self.assertEqual(ref_quota_set, res_dict)
        for filtered in self.filtered_quotas:
            self.assertIn(filtered, res_dict['quota_set'])

    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_authorize_show")
    @mock.patch("nova.api.openstack.compute.quota_sets.context.KEYSTONE."
                "get_project")
    def test_quotas_show_filtered(self, authorize_mock, get_project_mock):
        project = FakeProject(1)
        get_project_mock.return_value = project
        res_dict = self.controller.show(self.req, 1234)
        for filtered in self.filtered_quotas:
            self.assertNotIn(filtered, res_dict['quota_set'])

    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_authorize_update_or_delete")
    @mock.patch("nova.api.openstack.compute.quota_sets.context.KEYSTONE."
                "get_project")
    @mock.patch("nova.api.openstack.compute.quota_sets.quota.QUOTAS."
                "get_defaults")
    def test_quotas_default_filtered(self, get_defaults_mock,
                                     get_project_mock,
                                     auth_mock):
        self._ensure_filtered_quotas_existed_in_old_api()
        response_body = {'cores': 100}
        project = FakeProject(1, 2)
        get_project_mock.return_value = project
        response_body.update({'id': str(project.id)})
        get_defaults_mock.return_value = response_body
        expected = {'quota_set': response_body}
        res_dict = self.controller.defaults(self.old_req, project.id)
        self.assertEqual(expected, res_dict)
        self.assertTrue(get_defaults_mock.called)
        self.assertTrue(get_project_mock.called)

        for filtered in self.filtered_quotas:
            self.assertNotIn(filtered, res_dict['quota_set'])

    def test_quotas_detail_filtered(self):
        self._ensure_filtered_quotas_existed_in_old_api()
        res_dict = self.controller.detail(self.req, 1234)
        for filtered in self.filtered_quotas:
            self.assertNotIn(filtered, res_dict['quota_set'])

    def test_quotas_update_input_filtered(self):
        self._ensure_filtered_quotas_existed_in_old_api()
        for filtered in self.filtered_quotas:
            self.assertRaises(exception.ValidationError,
                              self.controller.update, self.req, 1234,
                              body={'quota_set': {filtered: 100}})

    def _prepare_quotas(self, input):
        quotas = {}

        for key, value in six.iteritems(input):
            quotas[key] = {
                'limit': value,
                'in_use': value,
                'reserved': value,
                'child_hard_limits': value
            }

        return quotas

    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_authorize_update_or_delete")
    @mock.patch("nova.api.openstack.compute.quota_sets.context.KEYSTONE."
                "get_project")
    @mock.patch("nova.api.openstack.compute.quota_sets.quota.QUOTAS."
                "get_project_quotas")
    @mock.patch("nova.api.openstack.compute.quota_sets.quota.QUOTAS."
                "get_settable_quotas")
    @mock.patch("nova.api.openstack.compute.quota_sets.objects."
                "Quotas.create_limit")
    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_validate_quota_limit")
    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_validate_quota_hierarchy")
    @mock.patch("nova.api.openstack.compute.quota_sets.sqlalchemy_api."
                "quota_allocated_update")
    @mock.patch("nova.api.openstack.compute.quota_sets.QuotaSetsController."
                "_get_quotas")
    def test_quotas_update_output_filtered(self, get_quotas_mock,
                                           quota_allocated_update_mock,
                                           _validate_quota_hierarchy_mock,
                                           _validate_quota_limit_mock,
                                           create_limit_mock,
                                           get_settable_quotas_mock,
                                           get_project_quotas_mock, get_project_mock,
                                           authorize_mock):
        self._ensure_filtered_quotas_existed_in_old_api()
        body = {'quota_set':
                {'cores': 100}}

        project = FakeProject(1, 2)
        parent_quotas = self._prepare_quotas(body['quota_set'])
        child_quotas = self._prepare_quotas(body['quota_set'])

        get_project_mock.return_value = project
        authorize_mock.side_effect = None
        create_limit_mock.side_effect = None
        _validate_quota_limit_mock.side_effect = None
        get_quotas_mock.return_value = body['quota_set']
        get_project_quotas_mock.side_effect = [parent_quotas,
                                               child_quotas]
        get_settable_quotas_mock.side_effect = [{}]
        _validate_quota_hierarchy_mock.return_value = 0

        res_dict = self.controller.update(self.req, 1234, body=body)
        self.assertEqual(body, res_dict)
        self.assertTrue(create_limit_mock.called)
        self.assertTrue(authorize_mock.called)

        self.assertTrue(quota_allocated_update_mock.called)
        self.assertTrue(get_quotas_mock.called)
        self.assertEqual(len(body['quota_set'].keys()),
                         len(create_limit_mock.mock_calls))
        for filtered in self.filtered_quotas:
            self.assertNotIn(filtered, res_dict['quota_set'])
