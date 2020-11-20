import re

import pandas as pd
import numpy as np
import scipy.stats as ss
from sklearn.neural_network import MLPClassifier
# from tld import get_tld
import seaborn as sns
# import tldextract


# import publicsuffixlist
from pandas.plotting import scatter_matrix
from sklearn.decomposition import PCA
from headerclassifier_code.headerclassifier.PANACEA_functions import HKEY_existence, DMARC_existence, \
    reg_domain2, DOMAIN, ORIGINATOR_domain, DKIM_STATUS
# from headerclassifier_code.headerclassifier.temp_main import *
import matplotlib.pyplot as plt
import seaborn as sns
from numpy.random import randint
from scipy.stats import pearsonr


# features_rules = ['class','from=originator','from!=originator','from_dom=ret_path','from_dom!=ret_path',
#                   'from=reply_to','from!=reply_to','originator=ret_path','originator!=ret_path','SPF(neutral))','SPF(exist)',
#                   'SPF(pass)','SPFfail)','DMARC(exist)', 'DMARC(pass/fail)']
from headerclassifier_code.headerclassifier.temp_main import header_b, header_ph


def plot_correlation_hmap(data):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    cax = ax.matshow(corr,cmap='coolwarm', vmin=-1, vmax=1)
    fig.colorbar(cax)
    ticks = np.arange(0,len(data.columns),1)
    ax.set_xticks(ticks)
    plt.xticks(rotation=90)
    ax.set_yticks(ticks)
    ax.set_xticklabels(data.columns)
    ax.set_yticklabels(data.columns)
    plt.show()

def cramers_v(x, y):
    confusion_matrix = pd.crosstab(x,y)
    chi2 = ss.chi2_contingency(confusion_matrix)[0]
    n = confusion_matrix.sum().sum()
    phi2 = chi2/n
    r,k = confusion_matrix.shape
    phi2corr = max(0, phi2-((k-1)*(r-1))/(n-1))
    rcorr = r-((r-1)**2)/(n-1)
    kcorr = k-((k-1)**2)/(n-1)
    return np.sqrt(phi2corr/min((kcorr-1),(rcorr-1)))

features_rules = ['Class(Benign)','from=originator','from!=originator','from_dom=ret_path','from_dom!=ret_path',
                  'from=reply_to','from!=reply_to','originator=ret_path','originator!=ret_path',
                  'SPF(pass)', 'DMARC(exist)','DMARC(pass)']

zer = 1
yey = 2
ney = 0
def _feature_learning(HEADER_LIST_B,HEADER_LIST_PH,zer,yey,ney):
    count = 0
    hdrs = []
    cls = 1
    dummy = '^'
    for HEADER_LIST in [HEADER_LIST_B,HEADER_LIST_PH]:
        for hdr in HEADER_LIST:
            hdrf = []
            hdr_key = hdr.keys()
            #class
            hdrf.append(cls)
            if 'from' in hdr_key:
                # from_dom = extract_domain(hdr,'from')
                # from_dom = None
                from_dom = DOMAIN(hdr,'from')
                if not from_dom:
                    from_dom = '$!'
            else:
                from_dom = '$!'

            if 'reply-to' in hdr_key:
                repto_dom = DOMAIN(hdr,'reply-to')
                if not repto_dom:
                    repto_dom = '!&'
            else:
                repto_dom = '!&'

            if 'return-path' in hdr_key:
                retpath = DOMAIN(hdr,'return-path')
                if not retpath:
                    retpath = '#&'
            else:
                retpath = '#&'

            # 'from=originator'
            if 'received' in hdr_key:
                if from_dom in ORIGINATOR_domain(hdr):
                    hdrf.append(yey)
                else:
                    hdrf.append(ney)
            else:
                hdrf.append(zer)
            # 'from!=originator'
            if 'received' in hdr_key:
                if from_dom not in ORIGINATOR_domain(hdr):
                    hdrf.append(yey)
                else:
                    hdrf.append(ney)
            else:
                hdrf.append(zer)

            # 'from_dom=ret_path'
            if 'return-path' in hdr_key:
                if retpath in from_dom:
                    hdrf.append(yey)
                else:
                    hdrf.append(ney)
            else:
                hdrf.append(zer)

            # 'from_dom!=ret_path'
            if 'return-path' in hdr_key:
                if retpath not in from_dom:
                    hdrf.append(yey)
                else:
                    hdrf.append(ney)
            else:
                hdrf.append(zer)

            # 'from=reply_to'
            if 'reply-to' in hdr_key and 'from' in hdr_key:
                if from_dom in repto_dom:
                    hdrf.append(yey)
                else:
                    hdrf.append(ney)
            else:
                hdrf.append(zer)
            # 'from!=reply_to'
            if 'from' in hdr_key and 'reply-to' in hdr_key:
                if from_dom not in repto_dom:
                    hdrf.append(yey)
                else:
                    hdrf.append(ney)
            else:
                hdrf.append(zer)
            # 'originator=ret_path'
            if 'received' in hdr_key and 'return-path' in hdr_key:
                if retpath in ORIGINATOR_domain(hdr):
                    hdrf.append(yey)
                else:
                    hdrf.append(ney)
            else:
                hdrf.append(zer)
            # 'originator!=ret_path'
            if 'received' in hdr_key and 'return-path' in hdr_key:
                if ORIGINATOR_domain(hdr) not in retpath :
                    hdrf.append(yey)
                else:
                    hdrf.append(ney)
            else:
                hdrf.append(zer)
            # 'SPF(neutral)'
            # if HKEY_existence(hdr, 'received-spf') == 1:
            #     if hdr['received-spf'][0].startswith('neutral'):
            #         hdrf.append(yey)
            #     else:
            #         hdrf.append(ney)
            # else:
            #     hdrf.append(zer)
            # # 'SPF(exist)'
            # if HKEY_existence(hdr, 'received-spf') == 1:
            #     hdrf.append(yey)
            # else:
            #     hdrf.append(ney)

            # 'SPF(pass\fail)'
            if HKEY_existence(hdr, 'received-spf') == 1:
                if hdr['received-spf'][0].startswith('pass'):
                    hdrf.append(yey)
                elif hdr['received-spf'][0].startswith('fail'):
                    hdrf.append(ney)
                else:
                    hdrf.append(ney)
            else:
                hdrf.append(zer)

            # 'DMARC(exist)'
            if DMARC_existence(hdr) == 1:
                hdrf.append(yey)
            else:
                hdrf.append(zer)

            # 'DMARC(pass)'
            if DMARC_existence(hdr) == 1:
                print('exist')
                if 'dmarc=pass' in ' '.join(hdr['authentication-results']):
                    hdrf.append(yey)
                elif 'dmarc=fail' in ' '.join(hdr['authentication-results']):
                    hdrf.append(zer)
                else:
                    hdrf.append(zer)
            else:
                hdrf.append(zer)
            hdrs.append(hdrf)
            print('item: ', count)
            count += 1
        cls = -1
    return hdrs

instances = _feature_learning(header_b,header_ph,zer,yey,ney)
print(len(instances))
ruleset = pd.DataFrame(instances,columns=features_rules)
corr = ruleset.corr('spearman')
plot_correlation_hmap(ruleset)
pd.plotting.scatter_matrix (ruleset.loc[:,['Class(Benign)','from=originator','originator=ret_path','SPF(pass)','DMARC(exist)','DMARC(pass)']])
plt.show()

#plot
plot_correlation_hmap(ruleset)
a =cramers_v(ruleset['Class(Benign)'], ruleset['DMARC(pass)'])


####New rules

#SPF = Passed && F <> R
def rule23(HEADER):
    if HKEY_existence(HEADER, 'received-spf') == 1 and HKEY_existence(HEADER, 'from') == 1 and HKEY_existence(HEADER, 'return-path') == 1:
        # print('true')
        rcvd_spf = HEADER['received-spf'][0]
        try:
            from_dom = reg_domain2.findall(HEADER['from'][0])[0]
        except:
            from_dom = 'NOFROM_DOM'
        try:
            rp_dom = reg_domain2.findall(HEADER['return-path'][0])[0]
        except:
            rp_dom = 'NORP_DOM'
        if from_dom not in rp_dom and HEADER['received-spf'][0].startswith('pass'):
            return 1
        else:
            return 0
    else:
        return -1
def rule24(HEADER):
    if HKEY_existence(HEADER, 'received-spf') == 1 and HKEY_existence(HEADER, 'from') == 1 and HKEY_existence(HEADER,'return-path') == 1:
        # print('true')
        rcvd_spf = HEADER['received-spf'][0]
        try:
            from_dom = reg_domain2.findall(HEADER['from'][0])[0]
        except:
            from_dom = 'NOFROM_DOM'
        try:
            rp_dom = reg_domain2.findall(HEADER['return-path'][0])[0]
        except:
            rp_dom = 'NORP_DOM'
        if from_dom not in rp_dom and HEADER['received-spf'][0].startswith('fail'):
            return 1
        else:
            return 0
    else:
        return -1
def rule25(HEADER):
    if HKEY_existence(HEADER, 'received-spf') == 1 and HKEY_existence(HEADER, 'from') == 1 and HKEY_existence(HEADER,'return-path') == 1:
        # print('true')
        rcvd_spf = HEADER['received-spf'][0]
        try:
            from_dom = reg_domain2.findall(HEADER['from'][0])[0]
        except:
            from_dom = 'NOFROM_DOM'
        try:
            rp_dom = reg_domain2.findall(HEADER['return-path'][0])[0]
        except:
            rp_dom = 'NORP_DOM'
        if from_dom in rp_dom and HEADER['received-spf'][0].startswith('fail'):
            return 1
        else:
            return 0
    else:
        return -1
def rule26(HEADER):
    if HKEY_existence(HEADER, 'dkim-signature') == 1 and HKEY_existence(HEADER, 'from') == 1 and HKEY_existence(HEADER, 'authentication-results') == 1:
        # print('true')
        dkim_stat = DKIM_STATUS(HEADER)
        try:
            dkim_dom = HEADER['dkim-signature'][0].split('d=')[1].split(' ')[0].split(';')[0]
        except:
            dkim_dom = '!@#$%^'
        try:
            from_dom = reg_domain2.findall(HEADER['from'][0])[0]
        except:
            from_dom = 'NOFROM_DOM'
        if dkim_dom in from_dom and dkim_stat=='fail':
            return 1
        else:
            return 0
    else:
        return -1
def rule27(HEADER):
    if HKEY_existence(HEADER, 'dkim-signature') == 1 and HKEY_existence(HEADER, 'from') == 1 and HKEY_existence(HEADER, 'authentication-results') == 1:
        # print('true')
        dkim_stat = DKIM_STATUS(HEADER)
        try:
            dkim_dom = HEADER['dkim-signature'][0].split('d=')[1].split(' ')[0].split(';')[0]
        except:
            dkim_dom = '!@#$%^'
        try:
            from_dom = reg_domain2.findall(HEADER['from'][0])[0]
        except:
            from_dom = 'NOFROM_DOM'
        if dkim_dom not in from_dom and dkim_stat=='fail':
            return 1
        else:
            return 0
    else:
        return -1
def rule28(HEADER):
    if HKEY_existence(HEADER, 'dkim-signature') == 1 and HKEY_existence(HEADER, 'from') == 1 and HKEY_existence(HEADER, 'authentication-results') == 1:
        # print('true')
        dkim_stat = DKIM_STATUS(HEADER)
        try:
            dkim_dom = HEADER['dkim-signature'][0].split('d=')[1].split(' ')[0].split(';')[0]
        except:
            dkim_dom = '!@#$%^'
        try:
            from_dom = reg_domain2.findall(HEADER['from'][0])[0]
        except:
            from_dom = 'NOFROM_DOM'
        if dkim_dom not in from_dom and dkim_stat=='pass':
            return 1
        else:
            return 0
    else:
        return -1

def rule28_1(HEADER):
    if HKEY_existence(HEADER, 'dkim-signature') == 1 and HKEY_existence(HEADER, 'from') == 1 and HKEY_existence(
            HEADER, 'authentication-results') == 1:
        # print('true')
        dkim_stat = DKIM_STATUS(HEADER)
        try:
            dkim_dom = HEADER['dkim-signature'][0].split('d=')[1].split(' ')[0].split(';')[0]
        except:
            dkim_dom = '!@#$%^'
        try:
            from_dom = reg_domain2.findall(HEADER['from'][0])[0]
        except:
            from_dom = 'NOFROM_DOM'

        if dkim_dom in from_dom and dkim_stat == 'pass':
            return 1
        else:
            return 0
    else:
        return -1
def rule29(HEADER):
    if HKEY_existence(HEADER, 'dkim-signature') == 1 and HKEY_existence(HEADER, 'received-spf') == 1 and HKEY_existence(HEADER, 'from') == 1 and HKEY_existence(HEADER,
                                                                                                                'authentication-results') == 1 and HKEY_existence(HEADER,
                                                                                                                                                                  'return-path') == 1:
        try:
            from_dom = reg_domain2.findall(HEADER['from'][0])[0]
        except:
            from_dom = 'NOFROM_DOM'
        try:
            rp_dom = reg_domain2.findall(HEADER['return-path'][0])[0]
        except:
            rp_dom = 'NORP_DOM'
        dkim_stat = DKIM_STATUS(HEADER)
        try:
            dkim_dom = HEADER['dkim-signature'][0].split('d=')[1].split(' ')[0].split(';')[0]
        except:
            dkim_dom = '!@#$%^'
        if from_dom in rp_dom and HEADER['received-spf'][0].startswith('pass') and dkim_dom in from_dom and dkim_stat=='pass':
            return 1
        else:
            return 0
    else:
        return -1

benign_res = []
phish_res = []

rl23=0
rl23_cntr=0
rl24=0
rl24_cntr=0
rl25=0
rl25_cntr = 0
rl26=0
rl26_cntr = 0
rl27=0
rl27_cntr = 0
rl28=0
rl28_cntr = 0
rl28_1=0
rl28_1_cntr = 0
rl29=0
rl29_cntr = 0
cntr = 0
for hdr in header_ph:
    print('rule23')
    if rule23(hdr) != -1:
        rl23 += rule23(hdr)
        rl23_cntr +=1
    print('rule24')
    if rule24(hdr)!=-1:
        rl24 += rule24(hdr)
        rl24_cntr += 1
    print('rule25')
    if rule25(hdr) != -1:
        rl25 += rule25(hdr)
        rl25_cntr += 1
    print('rule26')
    if rule26(hdr) != -1:
        rl26 += rule26(hdr)
        rl26_cntr += 1
    print('rule27')
    if rule27(hdr) != -1:
        rl27 += rule27(hdr)
        rl27_cntr += 1
    print('rule28')
    if rule28(hdr) != -1:
        rl28 += rule28(hdr)
        rl28_cntr += 1
    print('rule28_1')
    if rule28_1(hdr) != -1:
        rl28_1 += rule28_1(hdr)
        rl28_1_cntr += 1
    print('rule29')
    if rule29(hdr) != -1:
        rl29 += rule29(hdr)
        rl29_cntr += 1
    print('header',cntr)
    cntr+=1
# benign_res = [rl23/rl23_cntr,rl24/rl24_cntr,rl25/rl25_cntr,rl26/rl26_cntr,rl27/rl27_cntr,rl28/rl28_cntr,rl28_1/rl28_1_cntr,rl29/rl29_cntr]
# phish_res = [rl23/rl23_cntr,rl24/rl24_cntr,rl25/rl25_cntr,rl26/rl26_cntr,rl27/rl27_cntr,rl28/rl28_cntr,rl28_1/rl28_1_cntr,rl29/rl29_cntr]

# benign_res = [rl23,rl24,rl25,rl26,rl27,rl28,rl28_1,rl29]
phish_res = [rl23,rl24,rl25,rl26,rl27,rl28,rl28_1,rl29]
import pandas as pd
res = pd.DataFrame([benign_res,phish_res],columns=['SPF = Passed && F <> R','SPF = Failed && F <> R ',
                                                   'SPF = Failed && F = R',' F = DKIM.domain && dkim= failed','F <> DKIM.domain && dkim= failed',
                                                   'F <> DKIM.domain && dkim= passed','F == DKIM.domain && dkim= passed','(F = R && SPF = passed) && (F = DKIM.domain && dkim = pass']).to_csv('stat_res_count.csv')

# DKIM, FROM, and Return-path rules
# HEADER_list=header_b[1:2]

def DKIM_FROM_RP(HEADER_list):
    reg_domain2 = re.compile('(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]{2,6}')
    hlist_new = []
    noDKIM = []
    noSPF = []
    noSPF_noDKIM = []
    for hdr2 in HEADER_list:
        if 'from' in hdr2.keys() and 'return-path' in hdr2.keys():
            hlist_new.append(hdr2)
        else:
            continue
    print(str(round((len(HEADER_list)-len(hlist_new))/len(HEADER_list),3))+' of headers do not have from/return-path')

    hlist_new2 = []
    for hdr1 in hlist_new:
        hkeys = hdr1.keys()
        if 'dkim-signature' not in hkeys and 'received-spf' in hkeys:
            noDKIM.append(hdr1)
        if 'received-spf' not in hkeys and 'dkim-signature' in hkeys:
            noSPF.append(hdr1)
        if 'dkim-signature' not in hkeys and 'received-spf' not in hkeys:
            noSPF_noDKIM.append(hdr1)
        if 'dkim-signature' in hkeys and 'received-spf' in hkeys:
            hlist_new2.append(hdr1)
        else:
            continue
    # if len(hlist_new2)+len(noDKIM)+len(noSPF)==len(hlist_new):
    #     print('STATUS: OK')
    # else:
    #     print('STATUS: INCORRECT')

    print('No DKIM:',len(noDKIM)/len(hlist_new))
    print('No SPF:',len(noSPF)/len(hlist_new))
    print('NO DKIM NO SPF:',len(noSPF_noDKIM)/len(hlist_new))
    print('Have both DKIM/SPF:',round(len(hlist_new2)/len(hlist_new),3))
    print('-')

    F_in_R ,F_not_in_R, F_in_DKIMdom, F_not_in_DKIMdom = ([] for i in range(4))
    DKIMpass1, DKIMfail1, SPFpass1, SPFfail1, F_in_R1, F_not_in_R1, F_in_DKIMdom1, F_not_in_DKIMdom1 = ([] for i in range(8))
    DKIMpass2, DKIMfail2, SPFpass2, SPFfail2, F_in_R2, F_not_in_R2, F_in_DKIMdom2, F_not_in_DKIMdom2 = ([] for i in range(8))
    DKIMpass3, DKIMfail3, SPFpass3, SPFfail3, F_in_R3, F_not_in_R3, F_in_DKIMdom3, F_not_in_DKIMdom3 = ([] for i in range(8))
    DKIMpass4, DKIMfail4, SPFpass4, SPFfail4, F_in_R4, F_not_in_R4, F_in_DKIMdom4, F_not_in_DKIMdom4 = ([] for i in range(8))

    set_size = len(hlist_new2)
    for hdr in hlist_new2:

        try:
            from_dom = reg_domain2.findall(hdr['from'][0])[0]
        except:
            from_dom = 'NOFROM_DOM'
        try:
            rp_dom = reg_domain2.findall(hdr['return-path'][0])[0]
        except:
            rp_dom = 'NORP_DOM'
        try:
            dkim_dom = hdr['dkim-signature'][0].split('d=')[1].split(' ')[0].split(';')[0]
        except:
            dkim_dom = 'NODKIM'
        if hdr['received-spf'][len(hdr['received-spf'])-1].startswith('pass'):
            spf_stat = 'pass'
        else:
            spf_stat= 'fail'
        dkim_stat = DKIM_STATUS(hdr)

        # path1
        if from_dom in rp_dom:
            F_in_R.append(hdr)
            if spf_stat == 'pass':
                SPFpass1.append(hdr)
            else:
                SPFfail1.append(hdr)
                if dkim_dom in from_dom:
                    F_in_DKIMdom1.append(hdr)
                    if dkim_stat == 'pass':
                        DKIMpass1.append(hdr)
                    else:
                        DKIMfail1.append(hdr)
                else:
                    F_not_in_DKIMdom1.append(hdr)
        # path3
        else:
            F_not_in_R.append(hdr)
            if dkim_dom in from_dom:
                F_in_DKIMdom3.append(hdr)
                if dkim_stat == 'pass':
                    DKIMpass3.append(hdr)
                else:
                    DKIMfail3.append(hdr)
            else:
                F_not_in_DKIMdom3.append(hdr)

        # path2
        if dkim_dom in from_dom:
            F_in_DKIMdom.append(hdr)
            if dkim_stat == 'pass':
                DKIMpass2.append(hdr)
            else:
                DKIMfail2.append(hdr)
                if from_dom in rp_dom:
                    F_in_R2.append(hdr)
                    if spf_stat == 'pass':
                        SPFpass2.append(hdr)
                    else:
                        SPFfail2.append(hdr)
                else:
                    F_not_in_R2.append(hdr)
        # path 4
        else:
            F_not_in_DKIMdom.append(hdr)
            if from_dom in rp_dom:
                F_in_R4.append(hdr)
                if spf_stat == 'pass':
                    SPFpass4.append(hdr)
                else:
                    SPFfail4.append(hdr)
            else:
                F_not_in_R4.append(hdr)

    r1 = round(len(SPFpass1)/set_size,3)
    r2 = round(len(DKIMpass1)/set_size, 3)
    r3 = round(len(DKIMfail1)/set_size, 3)
    r4 = round(len(F_not_in_DKIMdom1)/set_size, 3)

    r5 = round(len(DKIMpass2) / set_size, 3)
    r6 = round(len(SPFpass2)/set_size,3)
    r7 = round(len(SPFfail2)/set_size,3)
    r8 = round(len(F_not_in_R2) / set_size, 3)

    r9  = round(len(DKIMpass3) / set_size, 3)
    r10 = round(len(DKIMfail3) / set_size, 3)
    r11 = round(len(F_not_in_DKIMdom3) / set_size, 3)

    r12 = round(len(SPFpass4)/set_size,3)
    r13 = round(len(SPFfail4)/set_size,3)
    r14 = round(len(F_not_in_R4) / set_size, 3)

    print('From == Return-path:',round(len(F_in_R)/set_size,4))
    print('From == DKIM dom:', round(len(F_in_DKIMdom) / set_size,4))
    print('From != DKIM dom:', round(len(F_not_in_DKIMdom) / set_size,4))
    print('From != Return-path:', round(len(F_not_in_R) / set_size,4))
    print('')
    print('PATH 1>>')
    print('Rule1:', r1)
    print('Rule2:', r2)
    print('Rule3:', r3)
    print('Rule4:', r4)
    print('')
    print('PATH 2>>')
    print('Rule5:', r5)
    print('Rule6:', r6)
    print('Rule7:', r7)
    print('Rule8:', r8)
    print('')
    print('PATH 3>>')
    print('Rule9:', r9)
    print('Rule10:', r10)
    print('Rule11:', r11)
    print('')
    print('PATH 4>>')
    print('Rule12:', r12)
    print('Rule13:', r13)
    print('Rule14:', r14)
DKIM_FROM_RP(header_ph)







