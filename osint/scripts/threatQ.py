######################################################
# Purpose: Analysis of the C2 Master list from Bambenek Consulting
#
# Author: Valentin Todorov
# Date: 12/26/2018
#
######################################################

# Import libraries
import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
import urllib.request
from collections import Counter
import re
matplotlib.use('Agg')


# Specify parameters
osint_url = 'https://osint.bambenekconsulting.com/feeds/'
file_name = 'c2-masterlist.txt'


# Define some functions I'll be using
def read_data(osint_url, file_name):
    """ Reads the C2 Master IP OSINT feed from Bambenek Consulting

    Parameters
    -------------
        osint_url: URL of the OSINT feed
        file_name: File name of the feed

    Returns
    -------------
        A list with the data from the OSINT feed
    """

    # Read in the file from https://osint.bambenekconsulting.com/feeds/
    osint_feed_url = osint_url + file_name

    logs_feed = urllib.request.urlopen(url=osint_feed_url).read().decode('utf-8')
    logs_feed = logs_feed.split('\n')
    return logs_feed


def get_date(logs_feed, date_loc=3):
    """ Extract the date of the last update of the feed

    Parameters
    -------------
        logs_feed: Transformed logs from the function read_data(osint_url, file_name)
        date_loc: The location of the date string in the feed imported from Bambenek

    Returns
    -------------
        Date in the format YYYY-MM-DD
    """

    line = logs_feed[date_loc]
    date = re.findall('\d+-\d+-\d+', line)
    return date


def get_timestamp(logs_feed, timestamp_loc=3):
    """ Extracts the time of the last update of the feed

    Parameters
    -------------
        logs_feed: Transformed logs from the function read_data(osint_url, file_name)
        date_loc: The location of the date string in the feed imported from Bambenek

    Returns
    -------------
        Time in the format HH:MM (24 hour format)
    """

    line = logs_feed[timestamp_loc]
    timestamp = re.findall('\d+:\d+', line)
    return timestamp


def create_data_frame(logs_feed, drop_elements=15):
    """ Creates a dataframe for analysis

    Parameters
    -------------
        logs_feed: Transformed logs from the function read_data(osint_url, file_name)
        drop_elements: Drop the first n elements from the feed, which are the header. The default value is 15

    Returns
    -------------
        A dataframe with the feeds from Bambenek
    """

    # Drop the first n elements from the feed, which are the header
    # Also remove the last element, which is empty
    logs_feed = logs_feed[drop_elements:]
    logs_feed.remove('')

    df = pd.DataFrame({'col': logs_feed})
    df = pd.DataFrame(df.col.str.split(',', -1).tolist(),
                      columns=['domain', 'domain_ip', 'domain_registrar', 'domain_registrar_ip', 'malware', 'url_feed'])
    return df


def clean_data(df):
    """ Transforms and cleans the dataframe created from the OSINT feed

    Parameters
    -------------
        df: Dataframe created from the OSINT feed

    Returns
    -------------
        A dataframe ready for analysis
    """

    # Extract the malware name
    df['malware'] = df['malware'].str.extract('Master Indicator Feed for ([a-z]+) non-sinkholed domains',
                                              expand=True).fillna(0)

    # Parse the IPs of the ISPs
    split_fn = lambda x: pd.Series([i for i in x.split('|')])
    domain_reg_df = df['domain_registrar_ip'].apply(split_fn)
    column_names = list(domain_reg_df.columns)
    domain_reg_df.columns = ['domain_registrar_ip_' + str(column_names[x]) for x in range(len(column_names))]

    final_osint_df = df.join(domain_reg_df)
    return final_osint_df


def bar_plot(df, field_name, graph_title, threshold_value, x_axis_label, y_axis_label):
    """ Creates bar plots for analysis

    Parameters
    -------------
        df: Dataframe created from the OSINT feed
        field_name: The column for which the frequency will be plotted
        threshold_value: Specify the minimum number of instances to have for printing (useful for sparse data)

    Returns
    -------------
        A bar plot
    """

    x = df[field_name].value_counts().sort_values()
    x[x > threshold_value].plot(kind='barh', figsize=(12, 8), title=graph_title, x=x_axis_label, y=y_axis_label)
    return


def parse_and_flatten(df, field_name):
    """ Parses and flattens a list of lists. As a result, each element in the final list is a value, not sublists

    Parameters
    -------------
        df: Dataframe created from the OSINT feed
        field_name: The column I want to parse

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
        lst: The parsed list from the function parse_and_flatten()
        threshold: Threshold of the instances each list element need to have to be added to the output

    Returns
    -------------
        A list
    """

    freq = Counter(lst)
    freq_most = dict((key, val) for key, val in freq.items() if val > threshold)
    summary = pd.Series(list(freq_most.values()), index=list(freq_most.keys()))
    return summary


# Create the data for analysis - print some overall stats
cc_list = read_data(osint_url, file_name)
cc_df = create_data_frame(cc_list, drop_elements=15)
cc_data = clean_data(cc_df)
cc_data.info()

# Get the data of the feed
feed_date = get_date(cc_list, date_loc=3)
feed_time = get_timestamp(cc_list, timestamp_loc=3)

# Frequency of domain IPs - graph the top 10
domain_ip_lst = parse_and_flatten(cc_data, 'domain_ip')
domain_ip_sum = summarize(domain_ip_lst, 2)
domain_ip_sum.sort_values().plot(kind='barh', figsize=(12, 8), title='IP addresses of domains with C2 malware (as of %s)' % feed_date[0])
plt.savefig('top10_c2_malware_source_IPs.png')
plt.close()

# Frequency of malware names
bar_plot(cc_data, 'malware', graph_title='Count of infected domains by malware family (as of %s)' % feed_date[0], threshold_value=0,
         x_axis_label='Count of infected domains by malware family',
         y_axis_label=None)
plt.savefig('malware_frequency.png')
plt.close()

# Frequency of IPs of the domain registrars
domain_reg_ip_lst = parse_and_flatten(cc_data, 'domain_registrar_ip')
domain_reg_ip_sum = summarize(domain_reg_ip_lst, 10)
domain_reg_ip_sum.sort_values().plot(kind='barh', figsize=(12, 8),
                                     title='IP addresses of domain registrars that host websites with C2 malware (as of %s)' % feed_date[0])
plt.savefig('top10_domain_registrar_IPs.png')
plt.close()


# Analysis of the registrars that registered the domains
domain_reg_lst = parse_and_flatten(cc_data, 'domain_registrar')
domain_reg_sum = summarize(domain_reg_lst, 5)
domain_reg_sum.sort_values().plot(kind='barh', figsize=(12, 8),
                                  title='Count of malware infected domains by Domain Registrars (as of %s)' % feed_date[0])
plt.savefig('domain_registrars.png')
plt.close()
