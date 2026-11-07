import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedShuffleSplit, GroupShuffleSplit

def create_random_stratified_split(df: pd.DataFrame, test_size: float = 0.30, random_state: int = 42):
    """Create standard stratified random split for train and test/calibration sets."""
    sss = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_idx, test_idx = next(sss.split(df, df["target"]))
    return df.iloc[train_idx].copy().reset_index(drop=True), df.iloc[test_idx].copy().reset_index(drop=True)

def create_domain_disjoint_split(df: pd.DataFrame, test_size: float = 0.30, random_state: int = 42):
    """
    Create domain-grouped split ensuring NO domain appears in both train and test.
    Crucial for measuring true zero-day and unseen domain generalization (Research Gap 1).
    """
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_idx, test_idx = next(gss.split(df, df["target"], groups=df["registered_domain"]))
    return df.iloc[train_idx].copy().reset_index(drop=True), df.iloc[test_idx].copy().reset_index(drop=True)
