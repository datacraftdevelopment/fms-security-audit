"""Read accounts, privilege sets and extended privileges from a FileMaker Save as XML export.

The FMSaveAsXML format differs between FileMaker versions, so this parser does not
depend on exact paths. It looks for Account, PrivilegeSet and ExtendedPrivilege
elements anywhere in the document and reads the attributes and child elements it
recognises. Anything it can't find is left as None, and the matching rule reports
Not checked. Validate against a real export from each FileMaker version you support.
"""

from pathlib import Path

from lxml import etree

TRUE = {"true", "yes", "1", "on", "enabled", "all", "modifiable", "allow"}


def _local(tag):
    return etree.QName(tag).localname if isinstance(tag, str) else ""


def _find_all(root, name):
    return [el for el in root.iter() if _local(el.tag) == name]


def _attr(el, *names):
    lower = {k.lower(): v for k, v in el.attrib.items()}
    for n in names:
        if n.lower() in lower:
            return lower[n.lower()]
    return None


def _flag(value):
    if value is None:
        return None
    return str(value).strip().lower() in TRUE


def _child(el, *names):
    for child in el.iter():
        if child is not el and _local(child.tag) in names:
            return child
    return None


def _set_ref(el):
    ref = _child(el, "PrivilegeSetReference", "PrivilegeSet")
    if ref is not None:
        return _attr(ref, "name")
    return _attr(el, "privilegeSet", "privilegeSetName")


def _modifies(value):
    if value is None:
        return None
    v = str(value).strip().lower()
    return "modif" in v or v in ("all", "true", "yes", "1")


def _privilege_set(el):
    def opt(*names):
        for n in names:
            v = _attr(el, n)
            if v is not None:
                return v
            child = _child(el, n)
            if child is not None:
                return _attr(child, "value", "access") or (child.text or "").strip() or None
        return None

    records = opt("records", "Records")
    return {
        "name": _attr(el, "name"),
        "records": records,
        "broad_delete": None if records is None else "delete" in records.lower() or records.lower() == "all",
        "layouts_modify": _modifies(opt("layouts", "Layouts")),
        "scripts_modify": _modifies(opt("scripts", "Scripts")),
        "value_lists_modify": _modifies(opt("valueLists", "ValueLists")),
        "manage_accounts": _flag(opt("manageAccounts", "ManageAccounts")),
        "export": _flag(opt("allowExporting", "exporting", "Exporting")),
        "print": _flag(opt("allowPrinting", "printing", "Printing")),
        "ext_privs": [],
    }


def parse_file(path):
    tree = etree.parse(str(path), etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=True))
    root = tree.getroot()

    sets = {}
    for el in _find_all(root, "PrivilegeSet"):
        if _attr(el, "name") and (len(el) or len(el.attrib) > 2):
            ps = _privilege_set(el)
            sets.setdefault(ps["name"], ps)

    for el in _find_all(root, "ExtendedPrivilege"):
        keyword = _attr(el, "name", "keyword")
        if not keyword:
            continue
        for ref in el.iter():
            if _local(ref.tag) in ("PrivilegeSetReference", "PrivilegeSet") and ref is not el:
                name = _attr(ref, "name")
                if name in sets:
                    sets[name]["ext_privs"].append(keyword)
                elif name:
                    sets[name] = {"name": name, "ext_privs": [keyword]}

    accounts = []
    for el in _find_all(root, "Account"):
        name = _attr(el, "name")
        if not name:
            continue
        status = _attr(el, "status", "active", "enabled")
        accounts.append(
            {
                "name": name,
                "privilege_set": _set_ref(el),
                "active": True if status is None else _flag(status) or str(status).lower() == "active",
                "type": _attr(el, "type", "authenticationType") or "FileMaker",
            }
        )

    return {
        "name": Path(path).stem + ".fmp12",
        "accounts": accounts,
        "privilege_sets": list(sets.values()),
        "guest_enabled": next((a["active"] for a in accounts if a["name"].strip("[]").lower() == "guest"), None),
    }


def parse_folder(folder, delete=True):
    folder = Path(folder)
    xml_dir = folder / "xml"
    files = []
    for path in sorted(xml_dir.glob("*.xml")):
        files.append(parse_file(path))
        if delete:
            path.unlink()
    return {"files": files}
