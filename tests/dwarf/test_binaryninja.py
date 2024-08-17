"""
Make sure we can correctly process DWARF files generated by
BinaryNinja: https://docs.binary.ninja/guide/debuginfo.html
"""
import lief
import pytest
from utils import get_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_dwo():
    target = lief.dwarf.load(get_sample("private/DWARF/binaryninja/dxp.debug"))
    units = list(target.compilation_units)
    assert len(units) == 1

    CU = units[0]
    assert CU.producer == "Binary Ninja DWARF Export Plugin"

    assert CU.find_function("toto") is None
    dp_sys_readlinkat = CU.find_function("dp_sys_readlinkat")
    assert dp_sys_readlinkat is not None

    assert dp_sys_readlinkat.address == 0x14a10
    assert dp_sys_readlinkat.type is not None
    ret_type = dp_sys_readlinkat.type
    assert ret_type.name == "int32_t"
    assert ret_type.size == 4

    #parameters = dp_sys_readlinkat.parameters
    #assert len(parameters) == 4
    #assert parameters[0].name == "dirfd"
    #assert parameters[0].type.name == "int32_t"

    #assert parameters[1].name == "pathname"
    #assert isinstance(parameters[1].type, lief.dwarf.types.Pointer)
    #pointer = parameters[1].type
    #assert pointer.underlying_type.name == "char[0x0]"
    #assert pointer.underlying_type.size == 1

    #assert parameters[2].name == "buf"

    #assert parameters[3].name == "bufsiz"
    #assert parameters[3].type.name == "size_t"

def test_structures():
    binaryninja_dxp = lief.dwarf.load(get_sample("private/DWARF/binaryninja/dxp.debug"))
    CU = list(binaryninja_dxp.compilation_units)[0]
    dp_init_mp3_info = CU.find_function("dp_init_mp3_info")

    #arg1 = dp_init_mp3_info.parameters[1]
    #assert arg1.name == "classes"
    #dp_mp3_class_t = arg1.type.underlying_type
    #assert isinstance(dp_mp3_class_t, lief.dwarf.types.Structure)
    #assert dp_mp3_class_t.name == "dp_mp3_class_t"
    #assert dp_mp3_class_t.size == 4
    #members = dp_mp3_class_t.members
    #assert len(members) == 1
    #assert members[0].name == "name_offset"
    #assert members[0].offset == 0
    #assert members[0].type.name == "uint32_t"


def test_find():
    binaryninja_dxp = lief.dwarf.load(get_sample("private/DWARF/binaryninja/dxp.debug"))
    CU = list(binaryninja_dxp.compilation_units)[0]
    var = CU.find_variable(0x78be0)
    assert var is not None
    assert var.name == "g_protections_conf"

    assert binaryninja_dxp.find_function(0x0004fb44) is not None

def test_types():
    binaryninja_liblinker = lief.dwarf.load(get_sample("private/DWARF/binaryninja/liblinker.debug"))
    dp_ctx_t: lief.dwarf.types.Structure = binaryninja_liblinker.find_type("dp_ctx_t")
    assert isinstance(dp_ctx_t, lief.dwarf.types.Structure)
    #dp_ctx_p0_t = dp_ctx_t.find_member(0)
    #assert dp_ctx_t.find_member(0x8).name == "dp_ctx_p0"
    #assert dp_ctx_t.find_member(0xd0).name == "relro_xxx"

    CU = next(binaryninja_liblinker.compilation_units)
    dp_get_env_info = CU.find_function("dp_get_env_info")
    assert dp_get_env_info is not None

def test_variables():
    binaryninja_liblinker = lief.dwarf.load(get_sample("private/DWARF/binaryninja/liblinker.debug"))
    assert binaryninja_liblinker.find_variable("protected_lib").address == 0x30000
    assert binaryninja_liblinker.find_variable(0x30000).name == "protected_lib"
