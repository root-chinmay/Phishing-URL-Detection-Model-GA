import json
import os
import numpy as np
from sklearn.tree import DecisionTreeClassifier

def export_tree_to_json(tree_model: DecisionTreeClassifier, feature_names: list, output_path: str = "models/exported/student_model.json") -> dict:
    """
    Distill and export a DecisionTreeClassifier into a pure, lightweight JSON structure
    that can be executed by a tiny Python interpreter on mobile devices without scikit-learn.
    """
    tree = tree_model.tree_
    feature = tree.feature.tolist()
    threshold = [round(float(t), 5) for t in tree.threshold.tolist()]
    children_left = tree.children_left.tolist()
    children_right = tree.children_right.tolist()
    
    # Extract leaf probabilities: value shape is (n_nodes, 1, n_classes)
    values = []
    for val in tree.value:
        counts = val[0]
        total = sum(counts)
        prob_malicious = round(float(counts[1] / total), 4) if total > 0 else 0.5
        values.append(prob_malicious)

    model_dict = {
        "version": "1.0.0",
        "architecture": "distilled_pure_tree_interpreter",
        "n_nodes": int(tree.node_count),
        "max_depth": int(tree.max_depth),
        "feature_names": feature_names,
        "feature": feature,
        "threshold": threshold,
        "children_left": children_left,
        "children_right": children_right,
        "leaf_probabilities": values
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(model_dict, f, indent=2)

    return model_dict

class LightweightTreeInterpreter:
    """
    Pure Python decision tree interpreter.
    Evaluates distilled tree models without requiring scikit-learn, C-extensions, or network access.
    Perfect for Android (Kivy/python-for-android) offline execution.
    """
    def __init__(self, model_dict: dict):
        self.feature = model_dict["feature"]
        self.threshold = model_dict["threshold"]
        self.children_left = model_dict["children_left"]
        self.children_right = model_dict["children_right"]
        self.leaf_probs = model_dict["leaf_probabilities"]
        self.feature_names = model_dict["feature_names"]

    @classmethod
    def load_from_json(cls, json_path: str = "models/exported/student_model.json"):
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(data)

    def predict_proba_single(self, feature_vector: list) -> float:
        """Traverse tree for a single feature vector, returning P(Malicious)."""
        node = 0
        while self.children_left[node] != -1: # Not a leaf
            feat_idx = self.feature[node]
            val = feature_vector[feat_idx]
            if val <= self.threshold[node]:
                node = self.children_left[node]
            else:
                node = self.children_right[node]
        return float(self.leaf_probs[node])

    def predict_proba_batch(self, feature_matrix: list) -> list:
        """Batch inference in pure Python."""
        return [self.predict_proba_single(x) for x in feature_matrix]
