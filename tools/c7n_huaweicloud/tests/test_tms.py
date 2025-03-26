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


class TMSTest(BaseTest):
    init_huaweicloud_config()

    def test_tms_tag_count(self):
        factory = self.replay_flight_data('tms-test')
        p = self.load_policy({
            'name': 'all-volumes',
            'resource': 'huaweicloud.volume',
            "filters": [{
                "type": "tag-count",
                "count": 3,
                "op": "gte"
            }]
        },
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_tms_tag(self):
        factory = self.replay_flight_data('tms-test')
        p = self.load_policy({
            'name': 'all-volumes',
            'resource': 'huaweicloud.volume',
            'actions': [{
                "type": "tag",
                "tags": {
                    "test-key": "test-value",
                }
            }]
        },
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_tms_untag(self):
        factory = self.replay_flight_data('tms-test')
        p = self.load_policy({
            'name': 'all-volumes',
            'resource': 'huaweicloud.volume',
            'actions': [{
                "type": "untag",
                "tags": [
                    "test-key",
                ]
            }]
        },
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_tms_rename_tag(self):
        factory = self.replay_flight_data('tms-test')
        p = self.load_policy({
            'name': 'all-volumes',
            'resource': 'huaweicloud.volume',
            'actions': [{
                "type": "rename-tag",
                "old_key": "test-key",
                "new_key": "test-key-new"
            }]
        },
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_tms_normalize_tag(self):
        factory = self.replay_flight_data('tms-test')
        p = self.load_policy({
            'name': 'all-volumes',
            'resource': 'huaweicloud.volume',
            'actions': [{
                "type": "normalize-tag",
                "action": "strip",
                "key": "test-key",
                "old_sub_str": "123"
            }]
        },
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_tms_tag_trim(self):
        factory = self.replay_flight_data('tms-test')
        p = self.load_policy({
            'name': 'all-volumes',
            'resource': 'huaweicloud.volume',
            'actions': [{
                "type": "tag-trim",
                "space": "5"
            }]
        },
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
