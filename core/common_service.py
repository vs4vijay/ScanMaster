import os
import sys
import string

import nltk.corpus
from nltk import word_tokenize
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

sys.path.append('.')

CONFIG = {
    'DUPLICATE_MATCH_PERCENTAGE_THRESHOLD': os.getenv('DUPLICATE_MATCH_PERCENTAGE_THRESHOLD')
}

class CommonService:

    def __init__(self):
        nltk.download('stopwords')
        nltk.download('punkt')

        self.stopwords = nltk.corpus.stopwords.words('english')
        self.stopwords.extend(string.punctuation)
        self.stopwords.append('')

    def is_duplicate(self, dict_a, dict_b):

        match_treshold = CONFIG['DUPLICATE_MATCH_PERCENTAGE_THRESHOLD']
        print('match_treshold', match_treshold)

        string_a = dict_a['name']
        string_b = dict_b['name']

        tokens_a = [token.lower().strip(string.punctuation) for token in nltk.word_tokenize(string_a) \
                    if token.lower().strip(string.punctuation) not in self.stopwords]
        tokens_b = [token.lower().strip(string.punctuation) for token in nltk.word_tokenize(string_b) \
                            if token.lower().strip(string.punctuation) not in self.stopwords]

        ratio = len(set(tokens_a).intersection(tokens_b)) / float(len(set(tokens_a).union(tokens_b)))
        match_percentage = ratio * 100
        print(f'{string_a} : {string_b} == {match_percentage}')

        return False
