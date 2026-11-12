"""Bounded readers for additional local inventory metadata; never execute contents."""
import io
import json
import re
import struct
import xml.etree.ElementTree as ET
import zipfile

MAVEN = {
    'META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.properties': 'com.fasterxml.jackson.core:jackson-databind',
    'META-INF/maven/tools.jackson.core/jackson-databind/pom.properties': 'tools.jackson.core:jackson-databind',
    'META-INF/maven/org.keycloak/keycloak-services/pom.properties': 'org.keycloak:keycloak-services',
}
MAX_JAR = 8 * 1024 * 1024
MAX_PROPERTIES = 16 * 1024
MAX_JAR_ENTRIES = 4096


def check_zip_directory(data):
    # Bound the central directory before ZipFile allocates an object per member.
    # Support ordinary single-disk ZIPs only; ZIP64 is unnecessary for <=8 MiB JARs.
    end = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data): raise ValueError('missing ZIP directory')
    _, disk, directory_disk, count_disk, count, size, offset, comment = struct.unpack_from('<4s4H2LH', data, end)
    if (disk or directory_disk or count != count_disk or count > MAX_JAR_ENTRIES
            or end + 22 + comment != len(data) or offset + size != end):
        raise ValueError('unsupported ZIP directory')
    position, actual = offset, 0
    while position < end:
        if actual >= MAX_JAR_ENTRIES or position + 46 > end or data[position:position + 4] != b'PK\x01\x02':
            raise ValueError('invalid or oversized ZIP directory')
        lengths = struct.unpack_from('<3H', data, position + 28)
        position += 46 + sum(lengths)
        actual += 1
    if position != end or actual != count: raise ValueError('inconsistent ZIP directory')


def properties(data):
    result = {}
    for line in data.decode('ascii').splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '!')): continue
        # Maven-generated identity properties use simple literals. Escaped or
        # continued Java property syntax is deliberately unsupported, not guessed.
        if '\\' in line: raise ValueError('escaped Maven properties')
        match = re.fullmatch(r'(groupId|artifactId|version)\s*[=:]\s*(.*)', line)
        if match:
            if match[1] in result: raise ValueError('duplicate Maven property')
            result[match[1]] = match[2]
    if not {'groupId', 'artifactId', 'version'} <= result.keys():
        raise ValueError('missing Maven identity')
    return result


def jar(scan, fd, path, name):
    data, info = scan.read(fd, name, max_size=MAX_JAR)
    check_zip_directory(data)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_JAR_ENTRIES: raise ValueError('too many JAR entries')
        targets = [entry for entry in entries if entry.filename in MAVEN]
        if len({entry.filename for entry in targets}) != len(targets):
            raise ValueError('duplicate JAR metadata')
        if not targets: raise ValueError('missing Maven metadata')
        pending = []
        for entry in targets:
            if not scan.available(): return
            scan.entries += 1
            if entry.file_size > MAX_PROPERTIES or entry.flag_bits & 1:
                raise ValueError('oversized/encrypted Maven metadata')
            with archive.open(entry) as stream:
                raw = stream.read(MAX_PROPERTIES + 1)
            if len(raw) > MAX_PROPERTIES: raise ValueError('oversized Maven properties')
            row = properties(raw)
            identity = row['groupId'] + ':' + row['artifactId']
            if identity != MAVEN[entry.filename]: raise ValueError('mismatched Maven identity')
            pending.append((identity, row['version']))
        # Reject all metadata on a malformed archive rather than retaining a
        # potentially misleading fixed finding from its first entry.
        for identity, version in pending:
            scan.record(identity, version, path / name, 'maven_archive_metadata', data, info)


def inspect(scan, fd, path, name):
    """Return True only when this file is handled as an additional metadata type."""
    item = path / name
    if re.fullmatch(r'(jackson-databind|keycloak-services)(?:-[^/]+)?\.jar', name):
        jar(scan, fd, path, name)
        return True
    if name == 'version.php' and path.name == 'wp-includes':
        data, info = scan.read(fd, name)
        text = data.decode('utf-8')
        if not text.lstrip().startswith('<?php'): raise ValueError('invalid WordPress version file')
        text = re.sub(r'/\*.*?\*/|//[^\n]*|\#[^\n]*', '', text, flags=re.S)
        assignments = re.findall(r'\$wp_version\s*=', text)
        literals = re.findall(r'''(?m)^\s*\$wp_version\s*=\s*(['"])([^'"\n]*)\1\s*;\s*$''', text)
        version = literals[0][1] if len(assignments) == len(literals) == 1 else ''
        if not version: scan.issue('ambiguous_wordpress_version')
        scan.record('wordpress', version, item, 'cms_metadata', data, info)
        return True
    if name == 'style.css' and path.parent.name == 'themes' and path.parent.parent.name == 'wp-content':
        data, info = scan.read(fd, name)
        # WordPress reads theme headers from the first 8 KiB; require the Avada
        # vendor URI as well as the name, and exclude child themes.
        text = data[:8192].decode('utf-8')
        comment = re.match(r'\s*/\*(.*?)\*/', text, re.S)
        if not comment: return True
        headers = {}
        for line in comment[1].splitlines():
            match = re.fullmatch(r'\s*\*?\s*([A-Za-z ]+):\s*(.*?)\s*', line)
            if match:
                key = match[1].strip().lower()
                if key not in {'theme name', 'theme uri', 'version', 'template'}: continue
                if key in headers: raise ValueError('duplicate theme header')
                headers[key] = match[2]
        if (headers.get('theme name') == 'Avada' and not headers.get('template')
                and re.fullmatch(r'https?://(?:avada\.com|avada\.theme-fusion\.com|theme-fusion\.com)/?', headers.get('theme uri', ''))):
            scan.record('avada', headers.get('version', ''), item, 'theme_metadata_candidate', data, info)
        return True
    if name == 'info.xml' and path.name == 'appinfo':
        data, info = scan.read(fd, name)
        text = data.decode('utf-8')
        if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
            raise ValueError('XML declarations are not accepted')
        root = ET.fromstring(text)
        if root.tag != 'info': raise ValueError('invalid Nextcloud info')
        ids = root.findall('id')
        if len(ids) != 1: raise ValueError('ambiguous Nextcloud identity')
        if ids[0].text == 'richdocumentscode':
            versions = root.findall('version')
            if len(versions) != 1: raise ValueError('ambiguous Nextcloud version')
            scan.record('richdocumentscode', versions[0].text or '', item, 'nextcloud_app_metadata', data, info)
        return True
    if name == 'VERSION' and path.name == 'gitlab-rails':
        data, info = scan.read(fd, name)
        scan.record('gitlab', data.decode('ascii').strip(), item, 'gitlab_version_metadata', data, info)
        return True
    if name == 'INSTALL_RECEIPT.json' and path.name == '.metadata' and path.parent.name == 'clickhouse':
        data, info = scan.read(fd, name)
        row = json.loads(data)
        source = row.get('source', {})
        version = source.get('version', '')
        if source.get('tap') != 'homebrew/cask': version = 'unverified-cask-metadata'
        scan.record('clickhouse', version, item, 'cask_version_metadata', data, info)
        return True
    return False
