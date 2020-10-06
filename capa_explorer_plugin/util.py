from . import chardet
import json
import cutter
import itertools
import CutterBindings

def log(msg):
    """log to cutter console

    @param msg: message to log
    """
    cutter.message(f"[capa explorer]: {msg}")


def get_config_color(conf_name):
    return CutterBindings.Configuration.instance().getColor(conf_name)

def define_function(location, name):
    try:
        cutter.core().createFunctionAt(location, name)
    except Exception as e:
        log(str(e))

def rename_function(location, new_name):
    try:
        cutter.core().renameFunction(location, new_name)
    except Exception as e:
        log(str(e))

def analyze_and_rename_function(location, name):
    cutter.cmd('af @ %s' % str(hex(location)))
    old_name = cutter.cmdj('afij @%s' % location)[0]['name']
    if ('fcn.' in old_name):
        rename_function(location, name)
    else: 
        rename_function(location, f'{old_name}_AND_{name}')
    
def create_flagspace(flagspace):
    cutter.cmd('fs %s' % flagspace)

def create_flag(name, location):
    cutter.cmd('f+%s @ %s' % (name, location))

def highlight_locations(locations):
    cutter.cmd('ecHi red @@=%s' % ' '.join([str(x) for x in locations])) 
    cutter.refresh()

def unhighlight_locations(locations):
    cutter.cmd('ecH- @@=%s' % ' '.join([str(x) for x in locations]))
    cutter.refresh()

def highlight_instruction(location):
    cutter.cmd('ecHi red @@=%s' % location)   
    cutter.refresh()

def unhighlight_instruction(location):
    cutter.cmd('ecH- @@=%s' % location)
    cutter.refresh()

def seek(location):
    cutter.core().seek(location)

def load_capa_json(path):
    with open(path, 'rb') as f:
        rdata = f.read()
        sdata = rdata.decode(chardet.detect(rdata)['encoding'])
        data = json.loads(sdata)
    return data

def get_name(location):
    function_info = cutter.cmdj('afij @%s' % location)
    if len(function_info):
        fn_name = function_info[0]['name']
        match_name = f"{fn_name}"
    else:
        match_name = 'undefined.%s' % location
    return match_name

def get_function_boundries_at_current_location():
    function_info = cutter.cmdj('afij')
    if len(function_info):
        return (function_info[0]['minbound'], function_info[0]['maxbound'])
    else:
        return None

def get_disasm(location):
    feature_disasm = cutter.cmdj("pdj 1 @%s" % location)

    if feature_disasm[0].get('disasm'):
        disasm = feature_disasm[0].get('disasm')
    else:
        disasm = 'N/A'
    return disasm

from operator import itemgetter, attrgetter

def capability_rules(doc):
    """enumerate the rules in (namespace, name) order that are 'capability' rules (not lib/subscope/disposition/etc)."""

    for (_, _, rule) in sorted(
        map(lambda rule: (rule["meta"].get("namespace", ""), rule["meta"]["name"], rule), doc["rules"].values())
    , key=itemgetter(1)):
        if rule["meta"].get("lib"):
            continue
        if rule["meta"].get("capa/subscope"):
            continue
        if rule["meta"].get("maec/analysis-conclusion"):
            continue
        if rule["meta"].get("maec/analysis-conclusion-ov"):
            continue
        if rule["meta"].get("maec/malware-category"):
            continue
        if rule["meta"].get("maec/malware-category-ov"):
            continue

        yield rule
