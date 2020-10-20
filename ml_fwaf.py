import pyshark
import argparse
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cross_validation import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn import metrics
import urllib.parse

#Extract Data from internal packets to adapt the learning for internal use
#Assume no malicious activities as of yet
def packet_uri_extraction(pcap_file_in):
    uri_list = []
    cap = pyshark.FileCapture(pcap_file_in, display_filter='http')
    for pkt in cap:
        uri = str(pkt.http.request_full_uri).split()
        uri = uri[6:].join()
        uri_list.append(uri)
    return uri_list



def loadFile(name):
    directory = str(os.getcwd())
    filepath = os.path.join(directory, name)
    with open(filepath,'r') as f:
        data = f.readlines()
    data = list(set(data))
    result = []
    for d in data:
        d = str(urllib.parse.unquote(d))   #converting url encoded data to simple string
        result.append(d)
    return result



def main(goodQueries, badQueries, internalQueries):
    #Data prep
    badQueries = list(set(badQueries))
    goodQueries = list(set(goodQueries))
    goodQueries= goodQueries.extend(internalQueries)
    allQueries = badQueries+goodQueries
    yBad = [1 for i in range(0, len(badQueries))]
    yGood = [0 for i in range(0, len(goodQueries))]
    y = yBad+yGood
    queries = allQueries

    vectorizer = TfidfVectorizer(min_df = 0.0, analyzer='char', sublinear_tf=True, ngram_range=(1,3))
    X = vectorizer.fit_transform(queries)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state=42)

    badCount = len(badQueries)
    goodCount = len(goodQueries)

    #Training
    lgs = LogisticRegression(class_weight={1: 2* goodCount / badCount, 0: 1.0})
    lgs.fit(X_train, y_train)

    '''
    Note that SVM/neural networks can also be used in place of logistic regression, but this is the fastest
    '''

    #Evaluation
    predicted = lgs.predict(X_test)
    fpr, tpr, _ = metrics.roc_curve(y_test, (lgs.predict_proba(X_test)[:,1]))
    auc = metrics.auc(fpr, tpr)

    print("Bad samples: %d" % badCount)
    print("Good samples: %d" % goodCount)
    print("Baseline Constant negative: %.6f" % (goodCount / (goodCount + badCount)))
    print("------------")
    print("Accuracy: %f" % lgs.score(X_test, y_test))  # checking the accuracy
    print("Precision: %f" % metrics.precision_score(y_test, predicted))
    print("Recall: %f" % metrics.recall_score(y_test, predicted))
    print("F1-Score: %f" % metrics.f1_score(y_test, predicted))
    print("AUC: %f" % auc)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', metavar='<pcap file name>', help='pcap file to parse')
    parser.add_argument('--goodqueries', metavar='<good queries file name>', help='text file for good queries')
    parser.add_argument('--malqueries', metavar='<malicious queries file name>', help='text file for malicious queries')
    args = parser.parse_args()

    internalQueries = packet_uri_extraction(args.pcap)
    badQueries = loadFile(args.malqueries)
    goodQueries = loadFile(args.goodqueries)
    main(goodQueries, badQueries, internalQueries)
