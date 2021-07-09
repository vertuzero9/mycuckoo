import sys
import json
import time
import os
import datetime
import collections
import cuckoo.common.vrtt as vrtt

class sample_unit(object):
    LABEL_SIGNIFICANCE_COUNT = 5
    POSITIVE_RATE = 2 * LABEL_SIGNIFICANCE_COUNT
    
    def __init__(self):
        self.json_path = ""
        self.name = ""
        self.report = None
        self.total = None
        self.positives = None
        self.scans = None
        self.label = None
        self.features = {}
        self.oldvt = vrtt.oldVRTT()

    def load_json(self, json_file):
        if isinstance(json_file, str):
            self.json_path = json_file
            with open(json_file, "r") as f:
                try:
                    self.report = json.load(f)
                except Exception as Ex:
                    print >> sys.stderr, "Can't load file {}.".format(f)
                    print >> sys.stderr, "Exception: {}.".format(Ex)
                    sys.exit(1)
                    
        elif isinstance(json_file, dict):
            self.report = json_file
        else:
            print >> sys.stderr, "Can't load json, datatype not is dict."

        self.name = os.path.basename(json_file)

        virustotal = self.report.get("virustotal", {})

        self.total = virustotal.get("total")
        self.positives = virustotal.get("positives")
        self.scans = virustotal.get("scans")


    def label_sample(self, external_labels=None, label_type="family"):
        merged_labels = []

        if external_labels is None and self.scans is not None:
            for vendor in self.scans:
                merged_labels += self.oldvt.normalize(self.scans[vendor]["result"])[label_type]

        elif external_labels is not None and self.scans is None:
            merged_labels = external_labels

        if not merged_labels:
            self.label = "none"
            return

        labels_frequency = collections.Counter(merged_labels)
        
        top_label, top_label_count = labels_frequency.most_common(1)[0]
       
        if top_label_count >= self.LABEL_SIGNIFICANCE_COUNT:
            self.label = top_label.encode("ascii", "ignore")
        else:
            self.label = "none"


    def update(self, element, location):
        element_to_update = self.report
        
        for l in location[:-1]:
            etu = element_to_update[l]
            
            if etu is None:
                element_to_update[l] = {}
                element_to_update = element_to_update[l]
            else:
                element_to_update = etu
                
        element_to_update[location[-1]] = element


    def save_json(self, root_dir):
        with open(root_dir + self.name, "w") as f:
            json.dump(self.report, f)


    def ext_features(self):
        self.feature_static_meta()
        self.feature_static_packer()
        self.feature_static_pe()
        self.feature_static_imports()
        self.feature_dynamic_imports()
        self.feature_dynamic_filesystem()
        self.feature_dynamic_network()
        self.feature_dynamic_registry()
        self.feature_dynamic_apistats()
        self.feature_signatures()
        
    def feature_static_meta(self):
        if "meta" not in self.features:
            self.features["meta"] = {}
        
        static = self.report.get("static", {})

        str_dt = static.get("pe_timestamp")
        
        ts = None
        
        if str_dt is not None:
            dt = datetime.datetime.strptime(str_dt, "%Y-%m-%d %H:%M:%S")
            ts = int(time.mktime(dt.timetuple()))
            
        self.features["meta"]["timestamp"] = ts
        
        target_file = self.report.get("target", {}).get("file", {})
        
        self.features["meta"]["size"] = target_file.get("size")

        et_tokens = ["FileDescription", "OriginalFilename"]
        
        for token in et_tokens:
            self.features["meta"][token] = None
            
        for attr in static.get("pe_versioninfo", []):
            attr_name = attr["name"]
            if attr_name in et_tokens:
                self.features["meta"][attr_name] = attr.get("value")

        self.features["meta"]["magic_byte"] = target_file.get("type")


    def feature_static_packer(self):
        self.features["packer"] = self.report.get("static", {}).get("peid_signatures", None)


    def feature_static_pe(self):
        if "pe" not in self.features:
            self.features["pe"] = {}
            
        static = self.report.get("static", {})

        self.features["pe"]["section_attrs"] = {}
        
        for d in static.get("pe_sections", {}):
            n = d["name"]
            e = d["entropy"]
            if n and d:
                self.features["pe"]["section_attrs"][n] = e
                
        self.features["pe"]["resource_attrs"] = {}
        
        for d in static.get("pe_resources", {}):
            n = d["name"]
            f = d["filetype"]
            if n and f:
                self.features["pe"]["resource_attrs"][n] = f


    def feature_static_imports(self):
        if "static_imports" not in self.features:
            self.features["static_imports"] = {}

        static = self.report.get("static", {})

        self.features["static_imports"]["count"] = static.get("imported_dll_count", None)

        for d in static.get("pe_imports", []):
            ddl_name = d["dll"]
            
            if not ddl_name:
                continue
            
            self.features["static_imports"][ddl_name] = []
            for i in d["imports"]:
                ref = i["name"]
                if ref is not None:
                    self.features["static_imports"][ddl_name].append(ref)


    def feature_dynamic_imports(self):            
        summary = self.report.get("behavior", {}).get("summary", {})
        
        if "mutex" not in self.features and "mutex" in summary:
            self.features["mutex"] = summary.get("mutex", {})

        if "processes" not in self.features:
            self.features["processes"] = []
        for p in self.report.get("behavior", {}).get("processes", {}):
            p_name = p["process_name"]
            if p_name and p_name not in self.features["processes"]:
                self.features["processes"].append(p_name)

        if "dynamic_imports" not in self.features:
            self.features["dynamic_imports"] = {}
            
        self.features["dynamic_imports"] = summary.get("dll_loaded", {})


    def feature_dynamic_filesystem(self):
        def p(s):
            rs = []
            for i in s:
                rs += i
            return rs

        if "filesystem" not in self.features:
            self.features["filesystem"] = {}
            
        summary = self.report.get("behavior", {}).get("summary", {})

        tagA = ["file_read", "file_written", "file_deleted"]

        for tag in tagA:
            t = summary.get(tag, [])
            self.features["filesystem"][tag] = t
            self.features["filesystem"][tag[:4] + 's' + tag[4:]] = len(t)
        
        if "file_copied" in summary:
            self.features["filesystem"]["file_copied"] = p(summary.get("file_copied", []))
            self.features["filesystem"]["files_copied"] = len(summary.get("file_copied", []))
        
        if "file_moved" in summary:
            self.features["filesystem"]["file_renamed"] = p(summary.get("file_moved", []))
            self.features["filesystem"]["files_renamed"] = len(summary.get("file_moved", []))
        
        tagB = ["file_opened", "file_exists", "file_failed"]
        
        for tag in tagB: 
            self.features["filesystem"][tag[:4] + 's' + tag[4:]] = len(summary.get(tag, []))

        file_operations = summary.get("file_read", []) + summary.get("file_written", []) + summary.get("file_deleted", []) + p(summary.get("file_copied", [])) + p(summary.get("file_moved", [])) + summary.get("file_recreated", []) + summary.get("file_opened", []) + summary.get("file_exists", []) + summary.get("file_failed", [])

        self.features["filesystem"]["files_operations"] = len(list(set(file_operations)))


    def feature_dynamic_network(self):
        if "network" not in self.features:
            self.features["network"] = {}
        
        network = self.report.get("network", {})
        
        protocols = ['dead_hosts', 
                    'http', 
                    'icmp', 
                    'irc', 
                    'mitm', 
                    'smtp', 
                    'tcp',
                    'tls', 
                    'udp']       
        
        for p in protocols:
            if p in network:
                self.features["network"][p] = len(network.get(p, []))


    def feature_dynamic_registry(self):
        if "registrys" not in self.features:
            self.features["registrys"] = {}
            
        summary = self.report.get("behavior", {}).get("summary", {})
        
        self.features["registrys"]["regkey_written"] = summary.get("regkey_written", [])
        self.features["registrys"]["regkey_deleted"] = summary.get("regkey_deleted", [])


    def feature_dynamic_apistats(self):        
        behavior = self.report.get("behavior", {})
        
        if "apistats" not in self.features:
            self.features["apistats"] = {}
        
        if "apistats" in behavior:
            apistats = behavior["apistats"]
        elif "api_stats" in behavior:            
            apistats = behavior["api_stats"]
        else:
            return
        
        for api in apistats:
            for e in apistats[api]:
                if e not in self.features["apistats"]:
                    self.features["apistats"][e] = 0
                    
                self.features["apistats"][e] += apistats[api][e]


    def feature_signatures(self):
        if "signatures" not in self.features:
            self.features["signatures"] = []

        for s in self.report.get("signatures", {}):
            name = s["name"]
            description = s["description"]
            if name and name != 'mySig':
                self.features["signatures"].append(name)
            elif description:
                self.features["signatures"].append(hash(description))
                
    
                
    def init(self, data, isPath = False):
        if data != None:
            if isPath:
                self.load_json(data)
            else:
                self.name = str(data["info"]["id"])
                self.report = data
                
            self.label_sample()
            self.ext_features()
