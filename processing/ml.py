import os
import sys
import itertools
import pandas as pd
from cuckoo.common.config import Config
from cuckoo.common.constants import CUCKOO_ROOT
from cuckoo.processing.mlcore import mlcore
from cuckoo.processing.samples_loader import samples_loader
from cuckoo.processing.sample_unit import sample_unit
from pprint import pprint
class RunML(object):
    def __init__(self):
        self.mlc = mlcore()
        self.new_sample = sample_unit()
        #self.new_sample.init(results, isPath)
        
        #self.mlc.loadState()        
        
        #cl_args = [i for i in cfg.ml.clustering_parameters.split(",")]

        ## Select clustering algorithm
        #cl_args= [int(i) for i in cl_args]
        #self.mlc.clustering["min_samples"] = cl_args[0]
        #self.mlc.clustering["min_cluster_size"] = cl_args[1]
        
        #pprint(self.mlc.clustering["clustering"])
        
        self.init()
    
    @classmethod
    def init_features(self):
        cfg = Config("ml")
        
        loader = samples_loader()
        loader.load_binaries(os.path.join(CUCKOO_ROOT, cfg.ml.data_directory))
        #loader.load_binaries(cfg.ml.data_directory)

        features_dict = loader.get_features()
        labels_dict = loader.get_labels()

        self.mlc = mlcore()
        self.mlc.load_features(features_dict)
        self.mlc.load_labels(labels_dict)
        
        self.mlc.features.to_csv("features.csv", encoding="utf-8")
        self.mlc.labels.to_csv("labels.csv", encoding="utf-8")
    
    def init(self):
        cfg = Config("ml")
        self.mlc.features = pd.read_csv("features.csv", encoding="utf-8")
        self.mlc.labels = pd.read_csv("labels.csv", encoding="utf-8")
        ##cfg = Config("ml")

        #loader = samples_loader()
        #loader.load_binaries(os.path.join(CUCKOO_ROOT, cfg.ml.data_directory))
        ##loader.load_binaries(cfg.ml.data_directory)

        #features_dict = loader.get_features()
        #labels_dict = loader.get_labels()

        ##self.mlc = mlcore()
        #self.mlc.load_features(features_dict)
        #self.mlc.load_labels(labels_dict)

        #features_nominal = self.mlc.feature_category(":count:", complement=True)
        features_numerical = self.mlc.feature_category()

        selected_features = []
            
        selected_features.append(features_numerical)

        data = []
        for f, d in itertools.izip("filter_dataset", selected_features):
            data.append(self.mlc.filter_dataset(d))
                
        data = pd.concat(data, axis=1)

        # Parse clustering parameters
        cl_args = [i for i in cfg.ml.clustering_parameters.split(",")]

        # Select clustering algorithm
        cl_args= [int(i) for i in cl_args]
        self.mlc.cluster_hdbscan(data, *cl_args)

        # Save clustering fit
        clf = {}
        clf["clustering+noise"] = self.mlc.assess_clustering(self.mlc.clustering["clustering"], self.mlc.labels, data, discard_noise=False)
        clf["clustering"] = self.mlc.assess_clustering(self.mlc.clustering["clustering"], self.mlc.labels, data, discard_noise=True)
        
        pd.DataFrame(clf).to_csv("clustering_fit.csv", encoding="utf-8")
            
        self.mlc.clustering["clustering"].to_csv("clustering_results.csv", encoding="utf-8")
            
        self.mlc.clustering_label_distribution(self.mlc.clustering["clustering"], self.mlc.labels).to_csv("cluster_label_distribution.csv", encoding="utf-8")

        # Save abnormal behaviour stats?
        #if cfg.ml.abnormal_behaviour:
            #self.mlc.detect_abnormal_behaviour(features_numerical).to_csv("abnormal_behaviour.csv", encoding="utf-8")

        if cfg.ml.anomalies_detection:
            ad = pd.DataFrame(self.mlc.clustering["clustering"]["label"])
            ad.columns = ["cluster"]
            ad_dict = self.mlc.anomaly_detection()
            for i in ad_dict:
                if isinstance(ad_dict[i], list):
                    ad[i] = pd.Series([1] * len(ad_dict[i]), index = ad_dict[i])
                elif isinstance(ad_dict[i], dict):
                    in_list = []
                    for j in ad_dict[i]:
                        in_list += ad_dict[i][j]
                    ad[i] = pd.Series([1] * len(in_list), index = in_list)
            ad.to_csv("anomalies.csv", encoding="utf-8")

        #self.mlc.saveState()
        #pprint(self.mlc.clustering["clustering"])
    
    def run(self, results = None, isPath = False):
        self.new_sample.init(results, isPath)
        if self.new_sample is not None:
            t = self.mlc.compare_sample(self.new_sample)
            print >> sys.stderr, "------------------->COMPARE SAMPLE<-------------------"
            print >> sys.stderr, t
            print >> sys.stderr, "-------------------><><><><><><><><-------------------"
            #t.to_csv("test_samples.csv", encoding="utf-8")
            
            self.mlc.saveState(index=False)
        return t
