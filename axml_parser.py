"""
Android Binary XML (AXML) parser.
APK files store AndroidManifest.xml in a binary format — this parses it back to structured data.
"""
import struct


class AXMLParser:
    RES_NULL_TYPE                 = 0x0000
    RES_STRING_POOL_TYPE          = 0x0001
    RES_XML_TYPE                  = 0x0003
    RES_XML_START_NAMESPACE_TYPE  = 0x0100
    RES_XML_END_NAMESPACE_TYPE    = 0x0101
    RES_XML_START_ELEMENT_TYPE    = 0x0102
    RES_XML_END_ELEMENT_TYPE      = 0x0103
    RES_XML_CDATA_TYPE            = 0x0104

    TYPE_NULL       = 0x00
    TYPE_REFERENCE  = 0x01
    TYPE_ATTRIBUTE  = 0x02
    TYPE_STRING     = 0x03
    TYPE_INT_DEC    = 0x10
    TYPE_INT_HEX    = 0x11
    TYPE_INT_BOOL   = 0x12

    def __init__(self, data: bytes):
        self.data = data
        self.pos  = 0
        self.strings: list[str] = []
        self.namespaces: dict[str, str] = {}  # uri -> prefix

    # ------------------------------------------------------------------ helpers
    def _u16(self): v = struct.unpack_from('<H', self.data, self.pos)[0]; self.pos += 2; return v
    def _u32(self): v = struct.unpack_from('<I', self.data, self.pos)[0]; self.pos += 4; return v
    def _i32(self): v = struct.unpack_from('<i', self.data, self.pos)[0]; self.pos += 4; return v
    def _str(self, idx: int) -> str:
        if idx < 0 or idx >= len(self.strings): return ''
        return self.strings[idx]

    # ------------------------------------------------------------------ string pool
    def _parse_string_pool(self, chunk_start: int, header_size: int, chunk_size: int):
        string_count = self._u32()
        _style_count = self._u32()
        flags        = self._u32()
        strings_start = self._u32()
        _styles_start = self._u32()

        is_utf8 = bool(flags & 0x100)

        offsets = [self._u32() for _ in range(string_count)]

        base = chunk_start + strings_start
        result = []
        for off in offsets:
            pos = base + off
            try:
                if is_utf8:
                    # skip char-count (1 or 2 bytes)
                    b0 = self.data[pos]; pos += 1
                    if b0 & 0x80: pos += 1
                    # byte length (1 or 2 bytes)
                    b1 = self.data[pos]; pos += 1
                    byte_len = b1
                    if b1 & 0x80:
                        b2 = self.data[pos]; pos += 1
                        byte_len = ((b1 & 0x7F) << 8) | b2
                    s = self.data[pos:pos + byte_len].decode('utf-8', errors='replace')
                else:
                    char_len = struct.unpack_from('<H', self.data, pos)[0]; pos += 2
                    if char_len & 0x8000:
                        hi = struct.unpack_from('<H', self.data, pos)[0]; pos += 2
                        char_len = ((char_len & 0x7FFF) << 16) | hi
                    s = self.data[pos:pos + char_len * 2].decode('utf-16-le', errors='replace')
                result.append(s)
            except Exception:
                result.append('')

        self.strings = result

    # ------------------------------------------------------------------ public
    def parse(self) -> list[tuple]:
        """
        Returns a flat event list: ('start', name, ns, attrs_dict, line) |
                                   ('end',   name, line)                 |
                                   ('ns',    prefix, uri)
        """
        # file header
        res_type = self._u16()
        header_size = self._u16()
        file_size   = self._u32()

        if res_type != self.RES_XML_TYPE:
            raise ValueError(f'Not an AXML file (magic={res_type:#06x})')

        events: list[tuple] = []

        while self.pos < len(self.data):
            chunk_start  = self.pos
            chunk_type   = self._u16()
            chunk_hdr_sz = self._u16()
            chunk_size   = self._u32()

            if chunk_size == 0:
                break

            body_start = chunk_start + 8  # after the 8-byte ResChunk_header

            if chunk_type == self.RES_STRING_POOL_TYPE:
                self._parse_string_pool(chunk_start, chunk_hdr_sz, chunk_size)

            elif chunk_type in (self.RES_XML_START_NAMESPACE_TYPE, self.RES_XML_END_NAMESPACE_TYPE):
                self.pos = body_start
                _line    = self._u32()
                _comment = self._i32()
                prefix   = self._str(self._i32())
                uri      = self._str(self._i32())
                if chunk_type == self.RES_XML_START_NAMESPACE_TYPE:
                    self.namespaces[uri] = prefix
                    events.append(('ns', prefix, uri))

            elif chunk_type == self.RES_XML_START_ELEMENT_TYPE:
                self.pos = body_start
                line     = self._u32()
                _comment = self._i32()
                ns_idx   = self._i32()
                name_idx = self._i32()
                _attr_start = self._u16()
                _attr_size  = self._u16()
                attr_count  = self._u16()
                _id_idx     = self._u16()
                _cls_idx    = self._u16()
                _sty_idx    = self._u16()

                name = self._str(name_idx)
                ns   = self._str(ns_idx) if ns_idx >= 0 else ''

                attrs: dict[str, str] = {}
                for _ in range(attr_count):
                    # Each ResXMLTree_attribute is exactly 20 bytes:
                    # ns(i32=4) + name(i32=4) + rawValue(i32=4) +
                    # ResValue{ size(u16=2) + res0(u8=1) + dataType(u8=1) + data(u32=4) }
                    a_ns   = self._i32()   # 4
                    a_name = self._i32()   # 4
                    a_raw  = self._i32()   # 4
                    _vsize = self._u16()   # 2  (ResValue.size — always 8)
                    _res0  = struct.unpack_from('B', self.data, self.pos)[0]; self.pos += 1  # 1
                    a_type_byte = struct.unpack_from('B', self.data, self.pos)[0]; self.pos += 1  # 1
                    a_data = self._u32()   # 4  → total 20 bytes ✓

                    key = self._str(a_name)

                    if a_type_byte == self.TYPE_STRING:
                        val = self._str(a_raw) if a_raw >= 0 else ''
                    elif a_type_byte == self.TYPE_INT_DEC:
                        val = str(a_data)
                    elif a_type_byte == self.TYPE_INT_HEX:
                        val = hex(a_data)
                    elif a_type_byte == self.TYPE_INT_BOOL:
                        val = 'true' if a_data else 'false'
                    elif a_type_byte == self.TYPE_REFERENCE:
                        val = f'@0x{a_data:08x}'
                    elif a_raw >= 0:
                        val = self._str(a_raw)
                    else:
                        val = str(a_data)

                    if key:
                        attrs[key] = val

                events.append(('start', name, ns, attrs, line))

            elif chunk_type == self.RES_XML_END_ELEMENT_TYPE:
                self.pos = body_start
                line     = self._u32()
                _comment = self._i32()
                _ns      = self._i32()
                name_idx = self._i32()
                events.append(('end', self._str(name_idx), line))

            # advance to next chunk
            self.pos = chunk_start + chunk_size

        return events


def parse_manifest(data: bytes) -> dict:
    """
    Parse binary AndroidManifest.xml bytes → structured dict:
      package, versionCode, versionName, minSdkVersion, targetSdkVersion,
      permissions, activities, services, receivers, providers, application attrs
    """
    parser = AXMLParser(data)
    try:
        events = parser.parse()
    except Exception as e:
        return {'error': str(e)}

    result = {
        'package': '',
        'versionCode': '',
        'versionName': '',
        'minSdkVersion': '',
        'targetSdkVersion': '',
        'compileSdkVersion': '',
        'permissions': [],
        'activities': [],
        'services': [],
        'receivers': [],
        'providers': [],
        'application': {},
    }

    stack = []
    for event in events:
        if event[0] == 'start':
            _, name, ns, attrs, line = event
            stack.append(name)

            if name == 'manifest':
                result['package']      = attrs.get('package', '')
                result['versionCode']  = attrs.get('versionCode', '')
                result['versionName']  = attrs.get('versionName', '')

            elif name == 'uses-sdk':
                result['minSdkVersion']      = attrs.get('minSdkVersion', '')
                result['targetSdkVersion']   = attrs.get('targetSdkVersion', '')
                result['compileSdkVersion']  = attrs.get('compileSdkVersion', '')

            elif name == 'uses-permission':
                perm = attrs.get('name', '')
                if perm:
                    result['permissions'].append(perm)

            elif name == 'application':
                result['application'] = attrs

            elif name == 'activity':
                result['activities'].append(attrs)

            elif name == 'service':
                result['services'].append(attrs)

            elif name == 'receiver':
                result['receivers'].append(attrs)

            elif name == 'provider':
                result['providers'].append(attrs)

        elif event[0] == 'end':
            if stack:
                stack.pop()

    return result
