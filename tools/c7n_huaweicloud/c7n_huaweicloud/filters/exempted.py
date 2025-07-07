import json
import logging

from c7n import utils
from c7n.filters import Filter
from c7n.exceptions import PolicyValidationError
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkiam.v3 import KeystoneListProjectsRequest
from huaweicloudsdktms.v1 import ResqTagResource, ListResourceRequest
from requests.exceptions import HTTPError

log = logging.getLogger("custodian.huaweicloud.filters.exempted")


def register_exempted_filters(filters):
    filters.register('exempted', ExemptedFilter)
    filters.register('restricted', RestrictedFilter)


def get_obs_name(obs_url):
    # 找到最后一个 ".obs" 的索引位置
    last_obs_index = obs_url.rfind(".obs")
    return obs_url[:last_obs_index]


def get_obs_server(obs_url):
    # 找到最后一个 ".obs" 的索引位置
    last_obs_index = obs_url.rfind(".obs")
    remaining_after_obs = obs_url[last_obs_index:]
    split_res = remaining_after_obs.split("/", 1)
    return split_res[0].lstrip(".")


def get_file_path(obs_url):
    # 找到最后一个 ".obs" 的索引位置
    last_obs_index = obs_url.rfind(".obs")
    remaining_after_obs = obs_url[last_obs_index:]
    split_res = remaining_after_obs.split("/", 1)
    return split_res[1]


def get_values_from_resource(resource, field):
    if field == "tags":
        return get_tags_from_resource(resource).keys()
    elif field in resource:
        value = resource[field]
        if isinstance(value, (str, int)):
            return [value]
        log.error(f"{field} type error in resource {resource['id']}")
        raise TypeError(f"{field} type error in resource {resource['id']}")
    else:
        log.error(f"{field} is required in resource {resource['id']}")
        raise KeyError(f"{field} is required in resource {resource['id']}")


def get_tags_from_resource(resource):
    if "tags" not in resource:
        log.error(f"tags is required in resource {resource['id']}")
        raise KeyError(f"tags is required in resource {resource['id']}")
    try:
        tags = resource["tags"]
        if isinstance(tags, dict):
            return tags
        elif isinstance(tags, list):
            if all(isinstance(item, dict) and len(item) == 1 for item in tags):
                # [{k1: v1}, {k2: v2}]
                result = {}
                for item in tags:
                    key, value = list(item.items())[0]
                    result[key] = value
                return result
            elif all(isinstance(item, str) and '=' in item for item in tags):
                # ["k1=v1", "k2=v2"]
                result = {}
                for item in tags:
                    key, value = item.split('=', 1)
                    result[key] = value
                return result
            elif all(isinstance(item, dict) and 'key' in item and 'value' in item for item in
                     tags):
                # [{"key": k1, "value": v1}, {"key": k2, "value": v2}]
                return {item['key']: item['value'] for item in tags}
        raise PolicyValidationError(f"tags:{tags} type error "
                                    f"in resource {resource['id']}")
    except Exception:
        log.error(f"tags:{tags} type error "
                  f"in resource {resource['id']}")
        raise PolicyValidationError(f"tags:{tags} type error "
                                    f"in resource {resource['id']}")


class ExemptedFilter(Filter):
    """Filter resource by exempted field from obs.

    . code-block :: yaml

        - filters:
           - type: exempted
             field: tags
             exempted_values: [k1, k2]

        - filters:
           - type: exempted
             field: tags
             exempted_values:
                - k1
                - k2

        - filters:
           - type: exempted
             field: tags
             obs_url: https://test.obs.regionid.myhuaweicloud.com//test.json
             group_key: exempted_tags

       - filters:
           - type: exempted
             field: tags
             exempted_values: [k1, k2]
             obs_url: https://test.obs.regionid.myhuaweicloud.com//test.json
             group_key: exempted_tags

    """
    schema = utils.type_schema(
        'exempted',
        field={'type': 'string'},
        exempted_values={'type': 'array'},
        obs_url={'type': 'string'},
        group_key={'type': 'string'})
    schema_alias = True
    need_get_tags_from_tms = False
    tms_resource_tag_map = {}

    def validate(self):
        field = self.data.get('field', None)
        if field is None or field == '':
            self.log.error("field is required in filter exempted")
            raise PolicyValidationError("field is required in filter exempted")

        exempted_values = self.data.get('exempted_values', [])
        obs_url = self.data.get('obs_url', None)
        if obs_url is None and not exempted_values:
            self.log.warning("exempted_values or obs_url is required in filter exempted")
            raise PolicyValidationError("exempted_values or obs_url is required in filter exempted")
        return self

    def process(self, resources, event=None):
        field = self.data.get('field', None)
        exempted_values = self.data.get('exempted_values', [])
        obs_url = self.data.get('obs_url', None)
        group_key = self.data.get('group_key', 'exempted')
        if obs_url is not None:
            exempted_values.extend(self.get_exempted_values_from_obs(obs_url, group_key))

        self.need_get_tags_from_tms = (
                field == 'tags' and any('tags' not in resource for resource in resources))
        if self.need_get_tags_from_tms:
            if 'tag_resource_type' in resources[0].keys():
                self.tms_resource_tag_map = (
                    self.get_resource_tag_map_from_tms(resources[0]['tag_resource_type']))
            else:
                self.log.error("Need get resource tag map from tms, "
                               "but not found tag_resource_type")
                raise PolicyValidationError("Need get resource tag map from tms, "
                                            "but not found tag_resource_type")

        results = []
        for resource in resources:
            if self.filter_single_resource(resource, field, exempted_values):
                results.append(resource)
        return results

    def filter_single_resource(self, i, field, exempted_values):
        if len(exempted_values) == 0:
            return True
        try:
            if self.need_get_tags_from_tms and i["id"] in self.tms_resource_tag_map.keys():
                tag_map_list = self.tms_resource_tag_map.get(i["id"])
                resource_values = [tag_map.key for tag_map in tag_map_list]
            elif self.need_get_tags_from_tms and i["id"] not in self.tms_resource_tag_map.keys():
                self.log.warning(f"Need get resource tag map from tms, "
                                 f"but {i['id']} not get from tms")
                resource_values = get_values_from_resource(i, field)
            else:
                resource_values = get_values_from_resource(i, field)
        except TypeError:
            self.log.warning(f"{field} type error in resource {i['id']}, "
                             f"only support int or string, not filter the resource")
            return True
        except KeyError:
            self.log.warning(f"{field} not in resource {i['id']}, not filter the resource")
            return True
        except Exception:
            self.log.warning(f"get {field} in resource {i['id']} failed, not filter the resource")
            return True
        resource_values = set(resource_values)
        exempted_values = set(exempted_values)
        return len(resource_values & exempted_values) == 0

    def get_exempted_values_from_obs(self, obs_url, group_key):
        try:
            obs_client = utils.local_session(self.manager.session_factory).client("obs")
            # 1. 提取第一个变量：从 "https://" 到最后一个 "obs" 的部分
            protocol_end = len("https://")
            # 去除协议头后的完整路径
            path_without_protocol = obs_url[protocol_end:]
            obs_bucket_name = get_obs_name(path_without_protocol)
            obs_server = get_obs_server(path_without_protocol)
            obs_file = get_file_path(path_without_protocol)
            obs_client.server = obs_server
            resp = obs_client.getObject(bucketName=obs_bucket_name,
                                        objectKey=obs_file,
                                        loadStreamInMemory=True)
            if resp.status < 300:
                exempted_values_obs = json.loads(resp.body.buffer)[group_key]
                return exempted_values_obs
            else:
                self.log.error(f"get obs object failed: {resp.errorCode}, {resp.errorMessage}")
                raise HTTPError(resp.status, resp.body)
        except exceptions.ClientRequestException as e:
            self.log.error("get obs object failed, ", e.status_code, e.request_id,
                           e.error_code, e.error_msg)
            raise
        except Exception:
            self.log.error("get_exempted_values_from_obs occur error")
            raise

    def get_resource_tag_map_from_tms(self, tag_resource_type):
        try:
            resource_tag_map = {}
            project_id = self.get_project_id()
            tms_client = utils.local_session(self.manager.session_factory).client("tms")
            limit = 200
            offset = 0
            while True:
                request_body = ResqTagResource(
                    project_id=project_id,
                    resource_types=[tag_resource_type],
                    without_any_tag=False,
                    tags=[],
                    limit=limit,
                    offset=offset
                )
                request = ListResourceRequest(body=request_body)
                response = tms_client.list_resource(request=request)
                if len(response.errors) == 0:
                    resource_tag_list = response.resources
                    total_count = response.total_count
                    for resource_tag in resource_tag_list:
                        resource_tag_map[resource_tag.resource_id] = resource_tag.tags
                    if len(resource_tag_map) >= total_count:
                        break
                    else:
                        offset = offset + limit
                else:
                    self.log.error(f"get tms resources failed: {response.errors}")
                    raise HTTPError(200, response.errors)

            return resource_tag_map
        except exceptions.ClientRequestException as e:
            self.log.error("get resource from tms failed, ", e.status_code, e.request_id,
                           e.error_code, e.error_msg)
            raise
        except Exception:
            self.log.error("get_resource_tag_map_from_tms occur error")
            raise

    def get_project_id(self):
        iam_client = utils.local_session(self.manager.session_factory).client("iam-v3")

        region = utils.local_session(self.manager.session_factory).region
        request = KeystoneListProjectsRequest(name=region)
        response = iam_client.keystone_list_projects(request=request)
        for project in response.projects:
            if region == project.name:
                return project.id

        self.log.error("Can not get project_id for %s", region)
        raise PolicyExecutionError("Can not get project_id for %s", region)


class RestrictedFilter(Filter):
    """Filter resource by restricted field from obs.

    . code-block :: yaml

        - filters:
           - type: restricted
             field: tags
             restricted_values: [k1, k2]

        - filters:
           - type: restricted
             field: tags
             restricted_values:
                - k1
                - k2

        - filters:
           - type: restricted
             field: tags
             obs_url: https://test.obs.regionid.myhuaweicloud.com//test.json
             group_key: restricted_tags

       - filters:
           - type: restricted
             field: tags
             restricted_values: [k1, k2]
             obs_url: https://test.obs.regionid.myhuaweicloud.com//test.json
             group_key: restricted_tags

    """
    schema = utils.type_schema(
        'restricted',
        field={'type': 'string'},
        restricted_values={'type': 'array'},
        obs_url={'type': 'string'},
        group_key={'type': 'string'})
    schema_alias = True

    def validate(self):
        field = self.data.get('field', None)
        if field is None or field == '':
            self.log.error("field is required in filter restricted")
            raise PolicyValidationError("field is required in filter restricted")

        restricted_values = self.data.get('restricted_values', [])
        obs_url = self.data.get('obs_url', None)
        if obs_url is None and not restricted_values:
            self.log.warning("restricted_values or obs_url is required in filter restricted")
            raise PolicyValidationError(
                "restricted_values or obs_url is required in filter restricted")
        return self

    def process(self, resources, event=None):
        field = self.data.get('field', None)
        restricted_values = self.data.get('restricted_values', [])
        obs_url = self.data.get('obs_url', None)
        group_key = self.data.get('group_key', 'restricted')
        if obs_url is not None:
            restricted_values.extend(self.get_restricted_values_from_obs(obs_url, group_key))

        results = []
        for resource in resources:
            if self.filter_single_resource(resource, field, restricted_values):
                results.append(resource)
        return results

    def filter_single_resource(self, i, field, restricted_values):
        if len(restricted_values) == 0:
            return True
        try:
            resource_values = get_values_from_resource(i, field)
        except TypeError:
            self.log.warning(f"{field} type error in resource {i['id']}, "
                             f"only support int or string, not filter the resource")
            return True
        except KeyError:
            self.log.warning(f"{field} not in resource {i['id']}, not filter the resource")
            return True
        except Exception:
            self.log.warning(f"get {field} in resource {i['id']} failed, not filter the resource")
            return True
        resource_values = set(resource_values)
        restricted_values = set(restricted_values)
        return len(resource_values & restricted_values) > 0

    def get_restricted_values_from_obs(self, obs_url, group_key):
        try:
            obs_client = utils.local_session(self.manager.session_factory).client("obs")
            # 1. 提取第一个变量：从 "https://" 到最后一个 "obs" 的部分
            protocol_end = len("https://")
            # 去除协议头后的完整路径
            path_without_protocol = obs_url[protocol_end:]
            obs_bucket_name = get_obs_name(path_without_protocol)
            obs_server = get_obs_server(path_without_protocol)
            obs_file = get_file_path(path_without_protocol)
            obs_client.server = obs_server
            resp = obs_client.getObject(bucketName=obs_bucket_name,
                                        objectKey=obs_file,
                                        loadStreamInMemory=True)
            if resp.status < 300:
                restricted_values_obs = json.loads(resp.body.buffer)[group_key]
                return restricted_values_obs
            else:
                self.log.error(f"get obs object failed: {resp.errorCode}, {resp.errorMessage}")
                raise HTTPError(resp.status, resp.body)
        except exceptions.ClientRequestException as e:
            self.log.error("get obs object failed, ", e.status_code, e.request_id,
                           e.error_code, e.error_msg)
            raise
        except Exception:
            self.log.error("get_restricted_values_from_obs occur error")
            raise
