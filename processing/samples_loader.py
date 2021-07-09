import os
import json
from cuckoo.processing.sample_unit import sample_unit

class samples_loader(object):
    def __init__(self):
        self.binaries = {}
        self.binaries_location = ""
        self.binaries_updated = False

    def load_binaries(self, directory):
        self.binaries_location = directory + "/"
        for f in os.listdir(directory):
            self.binaries[f] = sample_unit()
            self.binaries[f].init(data = os.path.join(directory, f), isPath = True)
            

    def update_binaries(self, elements, root, locations):
        self.binaries_updated = True
            
        for i in self.binaries:
            self.binaries[i].update(elements, root+[locations])


    def get_labels(self):
        labels = {}
        
        for i in self.binaries:
            labels[i] = self.binaries[i].label
            
        return labels

    def get_features(self):
        features = {}
        
        for i in self.binaries:
            features[i] = self.binaries[i].features
            
        return features

    def get_simple_features(self):
        simple_features = {}
        
        for i in self.binaries:
            simple_features[i] = self.binaries[i].basic_features
            
        return simple_features
