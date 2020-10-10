from . import chardet
import json
import cutter
import itertools
import CutterBindings
from operator import itemgetter, attrgetter
import re

def log(msg):
    """log to cutter console

    @param msg: message to log
    """
    cutter.message(f"[capa explorer]: {msg}")

def trigger_flags_changed():
    cutter.core().triggerFlagsChanged()

def trigger_function_renamed(rva, new_name):
    cutter.core().triggerFunctionRenamed(rva, new_name)

def trigger_refresh():
    cutter.refresh()

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

def smart_rename_function(location, name):
    
    # Get function info
    function_info = cutter.cmdj('afij @%s' % location)

    if not len(function_info):
        # no function at location, trigger analysis
        # and refetch function info
        cutter.cmd('af @ %s' % location)
        function_info = cutter.cmdj('afij @%s' % location)
    
    old_fn_name = function_info[0]['name']

    # Sometimes the vivisect feature extractor identifies
    # adresses in the middle of functions as function starts
    # for some reason. We get the actual addr with r2. 
    actual_offset = function_info[0]['offset']
    
    if old_fn_name.startswith('fcn.'):
        # Function has default name, replace all of it.
        cutter.cmd('afn {} @ {}'.format(name, actual_offset))
    else: 
        # Function does not have generic name keep old name as prefix
        name = f'{old_fn_name}__{name}'
        cutter.cmd('afn {} @ {}'.format(name, actual_offset))

def create_flagspace(flagspace):
    cutter.cmd('fs %s' % flagspace)

def create_flag(name, location):
    try:
        cutter.cmd('f %s @ %s' % (name, location))
    except Exception as e:
        log(str(e))

def highlight_locations(locations):
    cutter.cmd('ecHi red @@=%s' % ' '.join([str(x) for x in locations])) 
    cutter.refresh()

def unhighlight_locations(locations):
    cutter.cmd('ecH- @@=%s' % ' '.join([str(x) for x in locations]))
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

def r2_rule_name(rule_info):
    return re.sub(r'.\(\d+ matches\)','', rule_info).replace(' ', '_')

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
