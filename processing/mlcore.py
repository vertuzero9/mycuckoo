import collections
import itertools
import json
import os
import re
import sys
from cuckoo.common.config import Config
from cuckoo.common.constants import CUCKOO_ROOT
from math import log
from pprint import pprint

from cuckoo.processing.sample_unit import sample_unit
from cuckoo.processing.samples_loader import samples_loader

import matplotlib.pyplot as plt
#matplotlib.use('Agg')
import numpy as np
import pandas as pd
from hdbscan import HDBSCAN
from sklearn import metrics
import seaborn as sns
from sklearn.manifold import TSNE
from cuckoo.processing.ccml_common import SIMPLE_CATEGORIES, CATEGORIES, PATTERNS

class mlcore(object):
    SIMPLE_CATEGORIES = SIMPLE_CATEGORIES
    CATEGORIES = CATEGORIES
    PATTERNS = PATTERNS

    def __init__(self, context="standalone"):
        self.context = context
        self.labels = None
        self.features = None
        self.clustering = {
            "min_samples": None,
            "min_cluster_size": None,
            "clustering": None
        }


    def ext_labels(self, labels):
        return pd.DataFrame(labels, index=["label"]).T


    def load_labels(self, labels):
        self.labels = self.ext_labels(labels)


    def ext_features(self, features, include_API_calls = False, include_API_calls_count = False):        
        def loop(key, value):
            if not value:
                return {}
            
            rs = {}
            if isinstance(value, dict):
                for k, v in value.items():
                    rs = dict(rs.items() + loop("{}:{}".format(key, k), v).items())
            elif isinstance(value, list):
                for v in value:
                    rs = dict(rs.items() + loop(key, v).items())
            else:
                if isinstance(value, unicode):
                    value = value.encode('utf-8')
                if isinstance(value, str):
                    rs["{}:{}".format(key, value)] = 1
                else:
                    rs[key] = value

            return rs
        
        rs = {}
        
        for e in features:
            rs[e] = loop("", features[e])
            
        features_pd = pd.DataFrame(rs).T
        features_pd.fillna(0, inplace=True)
        
        return features_pd


    def load_features(self, features, include_API_calls=False, include_API_calls_count=False):
        self.features = self.ext_features(features, include_API_calls, include_API_calls_count)


    def feature_category(self, category=None, complement=False):
        if self.features is None:
            print "Please load FEATURES"
            return None
        
        ext = []
        
        if category != None:
            category = [category]
            
            for col in self.features:
                for c in category:
                    if complement and not col.startswith(c):
                        ext.append(col)
                    elif not complement and col.startswith(c):
                        ext.append(col)
        else:
            for col in self.features:
                ext.append(col)
        
        return self.features.loc[:, ext]


    def filter_dataset(self, dataset=None, feature_coverage=0.1, complement=False):
        if dataset is None:
            dataset = self.features.copy()

        row_count = dataset.shape[0]
        remove_features = []
        for col in dataset:
            zero_count = .0
            for row in dataset[col]:
                if not row:
                    zero_count += 1

            if complement != (row_count - zero_count) / row_count < feature_coverage:
                remove_features.append(col)
        dataset.drop(remove_features, axis=1, inplace=True)

        return dataset


    def cluster_hdbscan(self, features=None, min_samples=1, min_cluster_size=5):
        if features is None:
            print "Not features be loaded"
            if self.features is None:
                print "Have no ML features"
                return
            else:
                features = self.features

        hdbscan = HDBSCAN(min_samples=min_samples, min_cluster_size=min_cluster_size)
        hdbscan_fit = hdbscan.fit(features)
        pprint(hdbscan_fit.labels_)
        hdbscan_stats = np.column_stack([hdbscan_fit.labels_, hdbscan_fit.probabilities_, hdbscan_fit.outlier_scores_])

        rs = {
            "min_samples":min_samples,
            "min_cluster_size":min_cluster_size,
            "clustering":pd.DataFrame(hdbscan_stats, index=features.index, columns=["label", "probability", "outlier_score"])
        }

        self.clustering = rs
        
        return rs


    def anomaly_detection(self, samples=None, labels=None, probability_threshold=0.897, outlier_threshold=0.532, homogeneity_threshold=0.223):
        if labels is None:
            labels = self.labels
            
        if samples is None:
            samples = self.clustering["clustering"]
            
        sample = samples.copy()
        sample.rename(columns={"label": "cluster"}, inplace=True)
        sample = pd.concat([sample, labels], axis=1)

        anomalies = {}

        anomalies["outliers"] = sample[sample.cluster == -1].index.tolist()

        anomalies["low_probability"] = sample.loc[sample.probability < probability_threshold] .loc[sample.cluster != -1].index.tolist()
        
        anomalies["high_outlier_score"] = sample.loc[sample.outlier_score > outlier_threshold] .loc[sample.cluster != -1].index.tolist()

        anomalies["homogeneity_suspects"] = {}
        
        for i in set(sample["cluster"].tolist()):
            c = collections.Counter(sample[sample.cluster == i]["label"].tolist())
            
            total = float(sum(c.values()))
            
            suspicious = [j for j in c if c[j] / total < homogeneity_threshold]

            anomalies["homogeneity_suspects"][i] = []

            for j in suspicious:
                anomalies["homogeneity_suspects"][i] += sample.loc[sample.cluster == i].loc[sample.label == j] .index.tolist()

        return anomalies


    def compare_sample(self, sample, amend=False):
        if isinstance(sample, sample_unit):
            features = self.ext_features({"current_" + sample.name : sample.features})
            
            extended_features = pd.concat([self.features, features])
            extended_features.fillna(0, inplace=True)
            clustering = self.cluster_hdbscan(features=extended_features, dry=True)
            clustering_result = clustering["clustering"].loc["current_" + sample.name]

            if amend:
                root = ["info", "clustering", "hdbscan"]
                sample.update(clustering_result["label"], root + ["clusterID"])
                sample.update(clustering_result["probability"], root + ["clusterProbability"])
                sample.update(clustering_result["outlier_score"], root + ["outlierScore"])
                sample.update(clustering["min_samples"], "min_samples")
                sample.update(clustering["min_cluster_size"], "min_cluster_size")
                sample.save_json(os.path.dirname(sample.json_path) + "/")
                
        elif isinstance(sample, samples_loader):
            clustering_result = pd.DataFrame()

        return clustering_result


    def assess_clustering(self, clustering, labels, data=None, discard_noise=False):
        def performance_metric(clustering, labels, data, noise):
            performance_metrics = {}
            performance_metrics["Adjusted Random Index"] = metrics.adjusted_rand_score(labels, clustering)
            performance_metrics["Adjusted Mutual Information Score"] = metrics.adjusted_mutual_info_score(labels, clustering)
            performance_metrics["Homogeneity"] = metrics.homogeneity_score(labels, clustering)
            performance_metrics["Completeness"] = metrics.completeness_score(labels, clustering)
            performance_metrics["V-measure"] = metrics.v_measure_score(labels, clustering)

            if data is None or noise:
                return performance_metrics
            performance_metrics["Silhouette Coefficient"] = metrics.silhouette_score(data, np.array(clustering))

            return performance_metrics

        cluster_label = clustering["label"].tolist()
        ground_label = labels["label"].tolist()

        if discard_noise:
            clustering= []
            labels = []
            noise_clustering = []
            noise_labels = []
            
            for c, g in itertools.izip(cluster_label, ground_label):
                if c == -1:
                    noise_clustering.append(c)
                    noise_labels.append(g)
                else:
                    clustering.append(c)
                    labels.append(g)
        else:
            clustering = cluster_label
            labels = ground_label

        return performance_metric(clustering, labels, data, discard_noise)

    def clustering_label_distribution(self, clustering, labels, plot=False):
        cluster_ids = set(clustering["label"].tolist())
        labels_ids = set(labels["label"].tolist())
        cluster_distribution = {}
        for i in cluster_ids:
            cluster_distribution[i] = {}
            for j in labels_ids:
                cluster_distribution[i][j] = 0

        for i in clustering.index:
            cluster_distribution[clustering["label"][i]][labels["label"][i]] += 1

        if plot:
            for i in cluster_distribution:
                fig = plt.figure()
                ax = fig.add_subplot(111)
                yticks = []
                counter = 0
                for j in cluster_distribution[i]:
                    if cluster_distribution[i][j]:
                        ax.barh(counter, cluster_distribution[i][j])
                        counter += 1
                        yticks.append(j)
                yticks_range = [l+.4 for l in range(len(yticks))]
                plt.yticks(yticks_range, yticks)
                ax.set_ylim([0, yticks_range[-1]+.4])
                plt.title("Cluster_{}".format(i))
                if self.context == "notebook":
                    plt.show()
                else:
                    plt.savefig("cluster_{}.png".format(i), bbox_inches="tight")
                    plt.close()
        else:
            cluster_distribution = pd.DataFrame(cluster_distribution).T
            cluster_distribution.index.name = "cluster_id"
            return cluster_distribution
    
    def saveState(self, **kwargs):       
        pd.DataFrame(self.labels).to_csv("labels.csv", encoding = "utf-8", **kwargs)
        pd.DataFrame(self.features).to_csv("features.csv", encoding = "utf-8", **kwargs)
        pd.DataFrame(self.clustering["clustering"]).to_csv("clustering.csv", encoding = "utf-8", **kwargs)
        
    def loadState(self, **kwargs):
        self.labels = pd.read_csv("labels.csv", encoding = "utf-8", **kwargs)
        self.features = pd.read_csv("features.csv", encoding = "utf-8", **kwargs)
        self.clustering["clustering"] = pd.read_csv("clustering.csv", encoding = "utf-8", **kwargs)

    def visualise_data(self, data=None, labels=None, learning_rate = 100, fig_name = "custom"):
        if data is None:
            data = self.features
        if labels is None:
            labels = self.labels

        tsne = TSNE(learning_rate = learning_rate)
        tsne_fit = tsne.fit_transform(data)
        tsne_df = pd.DataFrame(tsne_fit, index = data.index, columns = ['0', '1'])
        tsne_dfl = pd.concat([tsne_df, labels], axis = 1)

        sns.lmplot("0", "1", data = tsne_dfl, fit_reg = False, hue = "label",
                   scatter_kws = {"marker":"D", "s":50}, legend_out=True)
        plt.title("{}_lr:{}".format(fig_name, str(learning_rate)))
        
        if self.context == "notebook":
            plt.show()
        else:
            plt.savefig("{}_{}.png".format(fig_name, str(learning_rate)), bbox_inches='tight', pad_inches=.5)
            plt.close()
