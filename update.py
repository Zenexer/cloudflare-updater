#!python3
from abc import ABC
from typing import cast, Optional, Dict, Any, Union, List, Collection, Set, Tuple, Hashable, FrozenSet, NamedTuple, \
    Generator, Iterator, overload, TypeVar, Generic#, Literal -- needs Python 3.8
from argparse import ArgumentParser, Namespace
from CloudFlare import CloudFlare
import yaml

# Types suffixed with Data represent the underlying data, usually in the form of a list or dict, that is used to
# instantiate a class of the same name without the Data suffix.
#
# Types prefixed with Config contain data retrieved from config.yaml.
#
# Types prefixed with Api contain data retrieved from the Cloudflare API.

# Underlying config data.  These are used to initialize the full classes, which have the same names without the -Data
# suffix.
ConfigDomainCollectionData = Collection[str]
ConfigRecordData           = Dict[str, Any]
ConfigRecordCollectionData = List[ConfigRecordData]
ConfigGroupData            = Dict[str, Union[ConfigRecordCollectionData, ConfigDomainCollectionData]]
ConfigGroupCollectionData  = Collection[ConfigGroupData]
ConfigSettingsData         = Dict[str, Any]
ConfigData                 = Dict[str, Union[ConfigSettingsData, ConfigGroupCollectionData]]

ApiResultItem              = Dict[str, Any]
ApiResult                  = List[ApiResultItem]
ApiResultInfo              = Dict[str, int]
ApiRawResult               = Dict[str, Union[ApiResult, ApiResultInfo]]

ApiZoneData                = Dict[str, Any]
ApiZoneCollectionData      = List[ApiZoneData]
ApiRecordData              = Dict[str, Any]
ApiRecordCollectionData    = List[ApiRecordData]

# RecordKey is used to locate identical or similar records.  If an ApiRecord has an overlapping key with a ConfigRecord,
# the ApiRecord is either identical or can use the record update API.  Otherwise, an unmatched ApiRecord needs to be
# deleted, and an unmatched ConfigRecord needs to be created.
#
# ConfigRecords will only have one key, but ApiRecords will often have multiple keys.  This accounts for the fact that
# ConfigRecords will often not have FQDNs in the name and content fields.  ApiRecord will create multiple keys if it's
# able to replace the zone name with placeholders in the name and/or content fields.
RecordKey = NamedTuple('RecordKey', [
    ('name',    str),
    ('type',    str),
    ('content', str),
])


T = TypeVar('T')


class FrozenSetImpl(ABC, Generic[T], Collection[T]):
    """
    As of Python 3.7.2, typing.FrozenSet can't be used as a base class.  This works around that, thereby permitting
    frozen sets with custom initialization logic and additional methods.
    """

    _items: FrozenSet[T]

    def __init__(self, items: Iterator[T]) -> None:
        self._items = frozenset(items)

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[T]:
        return iter(self._items)

    @overload
    def __contains__(self, x: T) -> bool:
        pass

    @overload
    def __contains__(self, x: Any) -> bool: # Literal[False]: -- requires Python 3.8
        pass

    def __contains__(self, x: object) -> bool:
        return x in self._items


class DomainCollection(FrozenSetImpl[str]):
    def __init__(self, data: ConfigDomainCollectionData) -> None:
        super().__init__(str(x) for x in data)


class ApiZone(Hashable):
    id:      str
    name:    str

    def __init__(self, data: ApiZoneData) -> None:
        self.id   = str(data['id'])
        self.name = str(data['name']).strip('.').lower()

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other) -> bool:
        return other is not None and type(other) == type(self) and other.id == other.name

    def __str__(self) -> str:
        return f"zone {self.name} ({self.id})"


class Record(ABC, Hashable):
    name:     str
    type:     str
    content:  str
    keys:     FrozenSet[RecordKey]
    ttl:      Optional[int]         = None
    priority: Optional[int]         = None
    proxied:  Optional[bool]        = None

    def __init__(self, data: ConfigRecordData) -> None:
        self.name     = str(data['name']).strip('.').lower()
        self.type     = str(data['type']).upper()
        self.content  = str(data['content'])

        if 'ttl' in data:
            if data['ttl'] == 'auto':
                self.ttl = 1
            else:
                self.ttl = int(data['ttl'])

        if 'priority' in data:
            self.priority = int(data['priority'])

        if 'proxied' in data:
            self.proxied = bool(data['proxied'])

    def __str__(self) -> str:
        return f"{self.name} {self.type} {self.content}"

    def _members(self) -> tuple:
        # self.keys is deliberately omitted here
        return (self.name, self.type, self.content, self.ttl, self.priority, self.proxied)

    def __eq__(self, other) -> bool:
        return other is not None and type(other) == type(self) and self._members() == other._members()


class ConfigRecord(Record):
    _hash: int

    def __init__(self, data: ConfigRecordData) -> None:
        super().__init__(data)

        if self.name.endswith('.@'):
            self.name = self.name[:-2]

        key: RecordKey = RecordKey(self.name, self.type, self.content)

        self.keys  = frozenset({key})
        self._hash = hash(key)

    def __hash__(self) -> int:
        return self._hash

    def get_content_for_zone(self, zone: ApiZone) -> str:
        return self.content.format(zone=zone)

    def get_name_for_zone(self, zone: ApiZone) -> str:
        name = zone.name

        if self.name != '@':
            name = f"{self.name}.{name}"

        return name

    def get_api_data(self, zone: ApiZone) -> ConfigRecordData:
        data: ConfigRecordData = {
            'name':    self.get_name_for_zone(zone),
            'type':    self.type,
            'content': self.get_content_for_zone(zone),
        }

        if self.ttl is not None:
            data['ttl'] = self.ttl

        if self.priority is not None:
            data['priority'] = self.priority

        if self.proxied is not None:
            data['proxied'] = self.proxied

        return data


class ApiRecord(Record):
    id:   str
    zone: ApiZone

    def __init__(self, data: ConfigRecordData, zone: ApiZone) -> None:
        super().__init__(data)

        self.id              = data['id']
        self.zone            = zone

        generic_name:    str = self.get_generic_name()
        generic_content: str = self.get_generic_content()

        keys: Set[RecordKey] = {RecordKey(self.name, self.type, self.content)}

        if generic_name != self.name:
            keys.add(RecordKey(generic_name, self.type, self.content))

        if generic_content != self.content:
            keys.add(RecordKey(self.name, self.type, generic_content))

        if generic_name != self.name and generic_content != self.content:
            keys.add(RecordKey(generic_name, self.type, generic_content))

        self.keys = frozenset(keys)

    def __hash__(self) -> int:
        return hash(self.id)

    def _members(self) -> tuple:
        return (self.id, )

    def __str__(self) -> str:
        return f"{super().__str__()} ({self.id})"

    def get_generic_content(self) -> str:
        return self.content \
            .replace('{', '{{') \
            .replace('}', '}}') \
            .replace(self.zone.name, '{zone.name}')

    def get_generic_name(self) -> str:
        suffix: str = '.' + self.zone.name

        if self.name == self.zone.name:
            return '@'
        elif self.name.endswith(suffix):
            return self.name[:-len(suffix)]
        else:
            return self.name

    def satisfies(self, o: ConfigRecord) -> bool:
        if o.type != self.type or o.get_name_for_zone(self.zone) != self.name:
            return False

        if o.get_content_for_zone(self.zone) != self.content:
            return False

        if o.ttl is not None and o.ttl != self.ttl:
            return False

        if o.proxied is not None and o.proxied != self.proxied:
            return False

        if o.priority is not None and o.priority != self.priority:
            return False

        return True


class RecordCollection(FrozenSetImpl[ConfigRecord]):
    _matcher: Dict[RecordKey, ConfigRecord]

    def __init__(self, data: ConfigRecordCollectionData) -> None:
        super().__init__(ConfigRecord(x) for x in data)

        self._matcher = dict(self._generate_matcher_pairs())

    def _generate_matcher_pairs(self) -> Generator[Tuple[RecordKey, ConfigRecord], None, None]:
        for record in self:
            for key in record.keys:
                yield key, record

    def match(self, record: ApiRecord) -> Optional[ConfigRecord]:
        for key in record.keys:
            if key in self._matcher:
                return self._matcher[key]

        return None


class Group:
    records: RecordCollection
    domains: DomainCollection

    def __init__(self, data: ConfigGroupData) -> None:
        self.records = RecordCollection(cast(ConfigRecordCollectionData, data['records']))
        self.domains = DomainCollection(cast(ConfigDomainCollectionData, data['domains']))


class GroupCollection(List[Group]):
    def __init__(self, data: ConfigGroupCollectionData) -> None:
        super().__init__(Group(x) for x in data)


class Settings:
    dry_run:          bool
    api_batch_size:   int
    cloudflare_email: Optional[str]
    cloudflare_token: Optional[str]

    def __init__(self, data: ConfigSettingsData) -> None:
        self.dry_run          = data.get('dry_run',          False)
        self.api_batch_size   = data.get('api_batch_size',   None)  or 100
        self.cloudflare_email = data.get('cloudflare_email', None)
        self.cloudflare_token = data.get('cloudflare_token', None)


class Config:
    settings: Settings
    groups:   GroupCollection

    def __init__(self, config_file: Optional[str] = None) -> None:
        with open(config_file or 'config.yaml', 'r') as f:
            data: ConfigData = yaml.safe_load(f)

        self.settings = Settings(cast(ConfigSettingsData, data['settings']))
        self.groups   = GroupCollection(cast(ConfigGroupCollectionData, data['groups']))


class ApiZoneCollection(FrozenSetImpl[ApiZone]):
    _dict: Dict[str, ApiZone]

    def __init__(self, data: ApiZoneCollectionData) -> None:
        super().__init__(ApiZone(x) for x in data)

        self._dict = dict((z.name, z) for z in self)

    def by_name(self, name: str) -> Optional[ApiZone]:
        return self._dict.get(name)


class ApiRecordCollection(FrozenSetImpl[ApiRecord]):
    def __init__(self, data: ApiRecordCollectionData, zone: ApiZone) -> None:
        super().__init__(ApiRecord(x, zone) for x in data)


class Updater:
    config:    Config
    debug:     bool
    dry_run:   bool
    verbosity: int
    cf:        CloudFlare
    cache:     Dict[str, Any]

    def __init__(self, config_file: Optional[str] = None, dry_run: bool = False, debug: bool = False, verbosity: int = 0) -> None:
        self.config    = Config(config_file)
        self.debug     = debug
        self.dry_run   = dry_run or debug or self.config.settings.dry_run
        self.verbosity = verbosity
        self.cf        = CloudFlare(
            raw=True,
            email=self.config.settings.cloudflare_email,
            token=self.config.settings.cloudflare_token,
        )

    def get_all(self, api: Any, *args, extra_params: Optional[Dict[str, Any]] = None, **kwargs) -> ApiResult:
        total_pages: int            = 1  # Just so we pass the test the first time
        full_result: ApiResult      = []
        params:      Dict[str, Any] = extra_params and extra_params.copy() or dict()

        params['per_page']          = self.config.settings.api_batch_size
        params['page']              = 0

        while params['page'] < total_pages:
            params['page'] += 1

            raw:         ApiRawResult  = api.get(*args, params=params, **kwargs)
            result:      ApiResult     = cast(ApiResult, raw['result'])
            result_info: ApiResultInfo = cast(ApiResultInfo, raw['result_info'])

            full_result += result
            total_pages  = result_info['total_pages']

        return full_result

    def get_zones(self) -> ApiZoneCollection:
        return ApiZoneCollection(self.get_all(self.cf.zones))

    def get_records(self, zone: ApiZone) -> ApiRecordCollection:
        data: ApiRecordCollectionData

        if zone.id in self.cache:
            data = self.cache[zone.id]
        else:
            data = self.get_all(self.cf.zones.dns_records, zone.id)
            self.cache[zone.id] = data

        return ApiRecordCollection(data, zone)

    def invalidate_cache(self, zone: ApiZone):
        try:
            del self.cache[zone.id]
        except KeyError:
            pass

    def get_action(self, not_dry_run: str, dry_run: str) -> str:
        if self.dry_run:
            return dry_run
        else:
            return not_dry_run

    def update_record(self, zone: ApiZone, old_record: ApiRecord, new_record: ConfigRecord) -> None:
        data: ConfigRecordData = new_record.get_api_data(zone)

        self.log(0, f"{self.get_action('Updating', 'Would update')} record for {zone}: from {old_record} to {new_record}")

        if not self.dry_run:
            self.invalidate_cache(zone)
            self.cf.zones.dns_records.put(zone.id, old_record.id, data=data)

    def delete_record(self, zone: ApiZone, record: ApiRecord) -> None:
        self.log(0, f"{self.get_action('Deleting', 'Would delete')} record for {zone}: {record}")

        if not self.dry_run:
            self.invalidate_cache(zone)
            self.cf.zones.dns_records.delete(zone.id, record.id)

    def create_record(self, zone: ApiZone, record: ConfigRecord) -> None:
        data: ConfigRecordData = record.get_api_data(zone)

        self.log(0, f"{self.get_action('Creating', 'Would create')} record for {zone}: {record}")

        if not self.dry_run:
            self.invalidate_cache(zone)
            self.cf.zones.dns_records.post(zone.id, data=data)

    def load_cache(self) -> None:
        try:
            with open('.cache.yaml', 'r') as f:
                self.cache = yaml.safe_load(f)
        except FileNotFoundError:
            self.cache = dict()

    def save_cache(self) -> None:
        with open('.cache.yaml', 'w') as f:
            yaml.dump(self.cache, f)

    def log(self, verbosity: int, message: str) -> None:
        if self.verbosity >= verbosity:
            print(message)

    def run(self) -> None:
        if not self.config.groups:
            self.log(-1, "Warning: no groups in config file; doing nothing")
            return

        self.log(2, "Loading cache")
        self.load_cache()

        managed_domains: Set[str] = set()

        for group in self.config.groups:
            for domain in group.domains:
                domain = domain.strip('.').lower()

                if domain in managed_domains:
                    self.log(-2, f"Error: Domain {domain} appears multiple times in the config.")
                    return

                managed_domains.add(domain)

        self.log(2, "Retrieving zones")
        zones: ApiZoneCollection = self.get_zones()

        if not zones:
            self.log(-1, "Warning: no zones in Cloudflare account; doing nothing")
            return

        self.log(2, "Retrieving DNS records for zones")
        zone_records: Dict[ApiZone, ApiRecordCollection] = {}
        for z in zones:
            if z.name in managed_domains:
                self.log(2, f"Retrieving DNS records for {z}")
                zone_records[z] = self.get_records(z)
            else:
                self.log(0, f"Skipping {z} because it doesn't appear in any groups.")

        domains_are_missing: bool = False

        for group in self.config.groups:
            self.log(2, "Starting group")

            for domain in group.domains:
                zone: Optional[ApiZone] = zones.by_name(domain)

                if zone is None:
                    domains_are_missing = True
                    self.log(-2, f"Error: Domain {domain} isn't in Cloudflare.")
                    return

                if not domains_are_missing:
                    api_records: ApiRecordCollection = zone_records[zone]
                    found:       Set[ConfigRecord]   = set()

                    for api_record in api_records:
                        match: Optional[ConfigRecord] = group.records.match(api_record)

                        if match is None:
                            self.delete_record(zone, api_record)
                        elif api_record.satisfies(match):
                            self.log(1, f"Leaving record for {zone}: {api_record}")
                            found.add(match)
                        else:
                            self.update_record(zone, api_record, match)
                            found.add(match)

                    for config_record in group.records:
                        if config_record not in found:
                            self.create_record(zone, config_record)

        if domains_are_missing:
            return

        self.log(2, "Saving cache")
        self.save_cache()

        self.log(0, "Done.")


def main():
    parser: ArgumentParser = ArgumentParser()
    parser.add_argument(
        '-c', '--config',
        type=str,
        help="use a non-default path to config.yaml",
    )
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        dest='verbosity',
        help="increase output verbosity",
    )
    parser.add_argument(
        '-n', '--dry-run',
        dest='dry_run',
        action='store_true',
        help="retrieve data from Cloudflare for processing and describe actions that would be taken, but don't submit "
             "any changes",
    )
    parser.add_argument(
        '-d', '--debug',
        action='store_true',
        help="only useful during development; implies --dry-run",
    )
    args: Namespace = parser.parse_args()

    updater: Updater = Updater(
        config_file=args.config,
        debug=args.debug,
        verbosity=args.verbosity,
        dry_run=args.dry_run,
    )
    updater.run()


if __name__ == '__main__':
    main()
