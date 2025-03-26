# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import os

from huaweicloud_common import BaseTest

HUAWEICLOUD_CONFIG = {
    'HUAWEI_DEFAULT_REGION': 'cn-north-4',
    'HUAWEI_ACCESS_KEY_ID': 'access_key_id',
    'HUAWEI_SECRET_ACCESS_KEY': 'secret_access_key',
    'HUAWEI_PROJECT_ID': 'cn-north-4',
}


def init_huaweicloud_config():
    for k, v in HUAWEICLOUD_CONFIG.items():
        os.environ[k] = v


class ConfigTest(BaseTest):
    init_huaweicloud_config()

    def test_config_tracker_query(self):
        factory = self.replay_flight_data('config_tracker')
        p = self.load_policy({
            'name': 'config_tracker_delete_and_retention',
            'resource': 'huaweicloud.config-tracker', },
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_config_tracker_retention(self):
        factory = self.replay_flight_data('config_tracker')
        p = self.load_policy({
            'name': 'config_tracker_delete_and_retention',
            'resource': 'huaweicloud.config-tracker',
            "filters": [{
                "type": "retention",
                "key": "retention_period_in_days",
                "value": 30,
                "op": "eq"
            }],
        },
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_config_tracker_delete(self):
        factory = self.replay_flight_data('config_tracker')
        p = self.load_policy({
            'name': 'config_tracker_delete_and_retention',
            'resource': 'huaweicloud.config-tracker',
            'actions': [{
                "type": "delete-tracker",
            }]
        },
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
