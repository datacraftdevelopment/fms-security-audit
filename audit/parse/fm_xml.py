"""Read accounts, privilege sets and extended privileges from a FileMaker Save as XML export.

Built against a real FileMaker 26 export (tests/fixtures/saxml-fm26-accounts.xml):

    AccountsCatalog/ObjectList/Account[@enable, @type]
        Authentication/AccountName            the account name (text)
        Authentication/PasswordEncrypted      a password hash: never read or kept
        PrivilegeSetReference[@name]
    PrivilegeSetsCatalog/ObjectList/PrivilegeSet[@name]
        access/Records[@Create @Edit @Delete | @View="ReadOnly"]
        access/Layouts, ValueLists, Scripts   same attributes
        access/Other[@Print @Export @manageAccounts]
    ExtendedPrivilegesCatalog/ObjectList/ExtendedPrivilege[@name]
        ObjectList/PrivilegeSetReference[@name]   the sets that have it

Elements are found by name anywhere in the document, so a split-catalog export
works too. A value the parser can't read is left as None, and the matching rule
reports Not checked rather than guessing.
"""

from pathlib import Path

from lxml import etree


def _local(tag):
    return etree.QName(tag).localname if isinstance(tag, str) else ""


def _find_all(root, name):
    return [el for el in root.iter() if _local(el.tag) == name]


def _first(el, name):
    return next((c for c in el.iter() if c is not el and _local(c.tag) == name), None)


def _bool(value):
    return None if value is None else str(value).strip().lower() == "true"


def _modifies(el):
    """True if the privilege set can edit this kind of object, False if view or none, None if custom."""
    if el is None:
        return None
    if el.get("Edit") is not None:
        return _bool(el.get("Edit"))
    if el.get("View") is not None:
        return False
    return None


def _privilege_set(el):
    access = _first(el, "access")
    part = lambda name: _first(access, name) if access is not None else None  # noqa: E731
    records, other = part("Records"), part("Other")
    if records is None:
        rec_text, delete = None, None
    elif records.get("Delete") is not None:
        delete = _bool(records.get("Delete"))
        verbs = [v.lower() for v in ("Create", "Edit", "Delete") if _bool(records.get(v))]
        rec_text = (", ".join(verbs) + " in all tables") if verbs else "no access"
    elif records.get("View") is not None:
        rec_text, delete = "view only", False
    else:
        rec_text, delete = "custom", None
    flag = lambda name: _bool(other.get(name)) if other is not None else None  # noqa: E731
    return {
        "name": el.get("name"),
        "records": rec_text,
        "broad_delete": delete,
        "layouts_modify": _modifies(part("Layouts")),
        "scripts_modify": _modifies(part("Scripts")),
        "value_lists_modify": _modifies(part("ValueLists")),
        "manage_accounts": flag("manageAccounts"),
        "export": flag("Export"),
        "print": flag("Print"),
        "ext_privs": [],
    }


def _account(el):
    name_el = _first(el, "AccountName")
    name = (name_el.text or "").strip() if name_el is not None else el.get("name")
    if not name:
        return None
    ref = _first(el, "PrivilegeSetReference")
    enable = el.get("enable")
    return {
        "name": name,
        "privilege_set": ref.get("name") if ref is not None else None,
        "active": True if enable is None else _bool(enable),
        "type": el.get("type") or "FileMaker",
    }


def parse_file(path):
    tree = etree.parse(str(path), etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=True))
    root = tree.getroot()

    sets = {}
    for el in _find_all(root, "PrivilegeSet"):
        if el.get("name") and _first(el, "access") is not None:
            sets.setdefault(el.get("name"), _privilege_set(el))

    for el in _find_all(root, "ExtendedPrivilege"):
        keyword = el.get("name")
        if not keyword:
            continue
        for ref in _find_all(el, "PrivilegeSetReference"):
            name = ref.get("name")
            if name in sets:
                sets[name]["ext_privs"].append(keyword)

    accounts = [a for a in map(_account, _find_all(root, "Account")) if a]

    file_name = root.get("File") or Path(path).stem + ".fmp12"
    return {
        "name": file_name,
        "accounts": accounts,
        "privilege_sets": list(sets.values()),
        "guest_enabled": next((a["active"] for a in accounts if a["name"].strip("[]").lower() == "guest"), None),
    }


def parse_folder(folder, delete=True):
    folder = Path(folder)
    xml_dir = folder / "xml"
    paths = sorted(xml_dir.glob("*.xml"))
    files = [parse_file(path) for path in paths]  # a bad export raises here, before anything is deleted
    if delete:
        for path in paths:
            path.unlink()
    return {"files": files}
