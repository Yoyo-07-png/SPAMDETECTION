import re
from pathlib import Path
import string

import pandas as pd
import numpy as np
from imblearn.over_sampling import RandomOverSampler

from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB


class NaiveBayesModel():
    
    def __init__(self):
        
        self.csv_file_path = Path(__file__).resolve().parent / "email.csv"
        # self.count_vectorizer = CountVectorizer() switched to Tfidvectorizer
        self.tfid_vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            stop_words='english'
        )
        self.nb = MultinomialNB()
        self.ros = RandomOverSampler(random_state=42)
        
        self.pd_file = None
        self.vectorized_msgs = None
        
        # Initialize model on startup.
        self.on_init = self.prepare_model()
        
    def normalize_text(self, text):
        
        if isinstance(text, list):
            text = text[0]
        
        text = re.sub(r"[€$£]\s?\d[\d,\.]*", " MONEY ", text)  # €2000, $2,000
        text = re.sub(r"\d[\d,\.]*%?", " NUM ", text)          # 14,892, 88%
        
        text = text.translate(str.maketrans('', '', string.punctuation)) # removes punctuation.
        return text
        
    def load_from_memory(self):
        pass # FOR LATER.
    
    def load_pandas(self):
        try:
            self.pd_file = pd.read_csv(self.csv_file_path)
        except FileNotFoundError:
            return 1 # Requested file could not be found.
    
    def prepare_model(self):
        
        worked = self.load_pandas()
        
        if worked == 1 and not self.pd_file:
            return 1
        
        try:
        # for the specific file used: it has a redundant row down at the bottom.
        # this code snippet here is used to remove it.
        # delete this, if you're willing to change the file.
            self.pd_file = self.pd_file.iloc[:-1]
            
            
            if self.pd_file.duplicated().any():
                self.pd_file.drop_duplicates(inplace=True)
            # First: turn spam, ham into 1, 0.
            self.pd_file["Spam"] = self.pd_file["Category"].apply(lambda x: 1 if x == "spam" else 0)
            
            # Normalize
            self.pd_file["Message"] = self.pd_file["Message"].apply(self.normalize_text)
            
            # Deal with class imbalance:
            X_resampled, y_resampled = self.ros.fit_resample(self.pd_file[['Message']],
                                                             self.pd_file['Spam'])
            
            
            self.vectorized_msgs = self.tfid_vectorizer.fit_transform(X_resampled['Message'].values)
            
            
            # train model:
            self.nb.fit(self.vectorized_msgs,
                        y_resampled.values)
            
            return 0
        except Exception as e:
            return 1 # for now...... TODO: FIX ERROR HANDLING!!@!@!@!@!@!@!
        
    def use_model(self, body):
        
        analysis = self.analyze(body)
        if isinstance(analysis, str):
            return analysis

        return (
            f"{analysis['label']} "
            f"({analysis['confidence']:.0f}% Confidence)"
        )

    def analyze(self, body, top_n=6):
        # text is returned through CHUNKS. JOIN THEM TOGETHER.
        if isinstance(body, str):
            body = [body]
        full_text_block = " ".join(chunk.strip() for chunk in body if chunk)
        
        # "" is falsy!
        if not full_text_block:
            return "No text was extracted from the email!"
        
        # normalize numbers, turn text into 1 and 0 vectors by words.
        # the words are based by the fitted csv file.
        full_text_block = self.normalize_text(full_text_block)
        full_text_block_normalized = self.tfid_vectorizer.transform([full_text_block])
        
        predictions = self.nb.predict_proba(full_text_block_normalized)
        class_positions = {
            int(class_label): index
            for index, class_label in enumerate(self.nb.classes_)
        }
        spam_prob = float(predictions[0][class_positions[1]])
        ham_prob = float(predictions[0][class_positions[0]])

        spam_position = class_positions[1]
        ham_position = class_positions[0]
        spam_log_prob = self.nb.feature_log_prob_[spam_position]
        ham_log_prob = self.nb.feature_log_prob_[ham_position]
        feature_names = self.tfid_vectorizer.get_feature_names_out()
        row = full_text_block_normalized.tocsr()
        contributions = []

        for feature_index, value in zip(row.indices, row.data):
            log_odds = float(
                value * (spam_log_prob[feature_index] - ham_log_prob[feature_index])
            )
            contributions.append({
                "term": feature_names[feature_index],
                "log_odds": log_odds,
            })

        spam_evidence = sorted(
            (item for item in contributions if item["log_odds"] > 0),
            key=lambda item: item["log_odds"],
            reverse=True,
        )[:top_n]
        ham_evidence = sorted(
            (item for item in contributions if item["log_odds"] < 0),
            key=lambda item: item["log_odds"],
        )[:top_n]
        label = "Spam" if spam_prob > ham_prob else "Ham"

        return {
            "label": label,
            "spam_probability": spam_prob,
            "ham_probability": ham_prob,
            "confidence": max(spam_prob, ham_prob) * 100,
            "spam_evidence": spam_evidence,
            "ham_evidence": ham_evidence,
            "matched_features": int(row.nnz),
        }
        
        