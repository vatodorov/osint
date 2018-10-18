######################################################
#
# Purpose: Analysis of the C2 Master list from from Bambenek Consulting
#
#
# Author: Valentin Todorov
# Date: 10/17/2018
#
######################################################

# Import libraries
import pandas as pd
import urllib.request
from collections import Counter

# Specify parameters
osint_url = 'https://osint.bambenekconsulting.com/feeds/'
file_name = 'c2-masterlist.txt'


# Define some functions I'll be using
def read_data(osint_url, file_name):
    """ Reads the C2 Master IP OSINT feed from Bambenek Consulting

    Parameters
    -------------
        osint_url - URL of the OSINT feed
        file_name - File name of the feed

    Returns
    -------------
        A list with the data from the OSINT
    """

    # Read in the file from https://osint.bambenekconsulting.com/feeds/
    osint_feed_url = osint_url + file_name

    logs_feed = urllib.request.urlopen(url=osint_feed_url).read().decode('utf-8')
    logs_feed = logs_feed.split('\n')

    # Remove the first 14 rows which are a header, and the last element, which is empty
    logs_feed.remove('')
    logs_feed = logs_feed[15:]
    return logs_feed


def create_data_frame(logs_feed):
    """ Creates a dataframe for analysis

    Parameters
    -------------
        logs_feed - Transformed logs from the function read_data(osint_url, file_name)

    Returns
    -------------
        A dataframe
    """

    df = pd.DataFrame({'col': logs_feed})
    df = pd.DataFrame(df.col.str.split(',', -1).tolist(),
                      columns=['domain', 'domain_ip', 'fqdn_isp', 'fqdn_isp_ip', 'malware', 'url_feed'])
    return df


def clean_data(df):
    """ Transforms and cleans the dataframe created from the OSINT feed

    Parameters
    -------------
        df - Dataframe created from the OSINT feed

    Returns
    -------------
        A dataframe ready for analysis
    """

    # Extract the malware name
    df['malware'] = df['malware'].str.extract('Master Indicator Feed for ([a-z]+) non-sinkholed domains',
                                              expand=True).fillna(0)

    # Parse the IPs of the ISPs
    split_fn = lambda x: pd.Series([i for i in x.split('|')])
    fqdn_isp_ip_df = df['fqdn_isp_ip'].apply(split_fn)
    column_names = list(fqdn_isp_ip_df.columns)
    fqdn_isp_ip_df.columns = ['fqdn_isp_ip_' + str(column_names[x]) for x in range(len(column_names))]

    final_osint_df = df.join(fqdn_isp_ip_df)
    return final_osint_df


def bar_plot(df, field_name, graph_title, threshold_value):
    """ Creates bar plots for analysis

    Parameters
    -------------
        df - Dataframe created from the OSINT feed
        field_name - The column for which I want the frequency
        threshold_value - Specify the minimum number of instances to have for printing (useful for sparse data)

    Returns
    -------------
        A bar plot
    """

    x = df[field_name].value_counts().sort_values()
    x[x > threshold_value].plot(kind='barh', figsize=(12, 8), title=graph_title)
    return


def parse_and_flatten(df, field_name):
    """ Creates bar plots for analysis

    Parameters
    -------------
        df - Dataframe created from the OSINT feed
        field_name - The column I want to parse

    Returns
    -------------
        A flattened list
    """

    # Parse and flatten the list
    lst = list(df[field_name])
    lst = [x.split('|') for x in lst]

    lst_flat = []
    for slist in lst:
        for x in slist:
            lst_flat.append(x)
    return lst_flat


def summarize(lst, threshold):
    """ Counts instances of elements and outputs those that have more instances than the threshold value

    Parameters
    -------------
        lst -
        threshold -

    Returns
    -------------

    """

    freq = Counter(lst)
    freq_most = dict((key, val) for key, val in freq.items() if val > threshold)
    summary = pd.Series(list(freq_most.values()), index=list(freq_most.keys()))
    return summary


# Create the data for analysis - print some overall stats
cc_list = read_data(osint_url, file_name)
cc_df = create_data_frame(cc_list)
cc_data = clean_data(cc_df)
cc_data.info()

# Frequency of domain IPs - graph the top 10
domain_ip_lst = parse_and_flatten(cc_data, 'domain_ip')
domain_ip_sum = summarize(domain_ip_lst, 2)
domain_ip_sum.sort_values().plot(kind='barh', figsize=(12, 8), title='IP addresses of domains')

# Frequency of malware names
bar_plot(cc_data, 'malware', graph_title='Malware frequency', threshold_value=0)

# Frequency of IPs of the ISPs
fqdn_isp_ip_lst = parse_and_flatten(cc_data, 'fqdn_isp_ip')
fqdn_isp_ip_sum = summarize(fqdn_isp_ip_lst, 10)
fqdn_isp_ip_sum.sort_values().plot(kind='barh', figsize=(12, 8), title='IP addresses of Service Providers')

# Analysis of the ISP names
fqdn_isp_lst = parse_and_flatten(cc_data, 'fqdn_isp')
fqdn_isp_sum = summarize(fqdn_isp_lst, 5)
fqdn_isp_sum.sort_values().plot(kind='barh', figsize=(12, 8),
                                title='Frequency of Events by Domain Names of Service Providers')
