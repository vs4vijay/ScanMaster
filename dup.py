#!/usr/bin/env python3

import string

import nltk.corpus
from nltk import word_tokenize

nltk.download('stopwords')
nltk.download('punkt')

stopwords = nltk.corpus.stopwords.words('english')
stopwords.extend(string.punctuation)
stopwords.append('')

# ed_sent_1_5 = nltk.edit_distance(sent1,sent5)

# print('Edit Distance between sent1 and sent5: ', ed_sent_1_5)

# print(1 - (float(ed_sent_1_5) / max(len(sent1), len(sent5)))) * 100


a = 'Vijay Soni'
b = 'Ajay Soni'


tokens_a = [token.lower().strip(string.punctuation) for token in nltk.word_tokenize(a) \
                    if token.lower().strip(string.punctuation) not in stopwords]
tokens_b = [token.lower().strip(string.punctuation) for token in nltk.word_tokenize(b) \
                    if token.lower().strip(string.punctuation) not in stopwords]

ratio = len(set(tokens_a).intersection(tokens_b)) / float(len(set(tokens_a).union(tokens_b)))
match_percentage = ratio * 100
print('match_percentage: ', match_percentage)