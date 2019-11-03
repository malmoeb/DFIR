#!/usr/bin/env python

import argparse
import os
import time
import threading
from urllib.parse import urlparse
import json

# Fixes Python3 to Python2 backwards compatability
try:
    import queue
except ImportError:
    import Queue as queue

# Third party modules
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except ImportError as error:
    missing_module = str(error).split(' ')[-1]
    print('[*] Missing module: {}'.format(missing_module))
    print('[*] Try running "pip install {}", or do an Internet search for installation instructions.'.format(
        missing_module.strip("'")))
    exit()


def test_api_connection(api_url):
    """Attempts to connect to the Burp API with a URL that includes the API key."""
    try:
        resp = requests.get(api_url, verify=False)
        if resp.ok:
            return True
        else:
            print('Invalid API URL or Key. Server Response: {}'.format(resp.status_code))
            return False
    except Exception as e:
        if args.debug:
            print('Error: {}'.format(e))
        return False

def normalize_urls(urls):
    """Accepts a list of urls and formats them to the proto://address:port format.
    Returns a new list of the processed urls.
    """
    url_list = []
    http_port_list = ['80', '280', '81', '591', '593', '2080', '2480', '3080',
                      '4080', '4567', '5080', '5104', '5800', '6080',
                      '7001', '7080', '7777', '8000', '8008', '8042', '8080',
                      '8081', '8082', '8088', '8180', '8222', '8280', '8281',
                      '8530', '8887', '9000', '9080', '9090', '16080']
    https_port_list = ['832', '981', '1311', '7002', '7021', '7023', '7025',
                       '7777', '8333', '8531', '8888']

    if csv:
        for url in urls:
            url_parts = url.split(";")
            u = url_parts[5] + '://' + url_parts[1] + ":" + url_parts[4]
            print(u)
            url_list.append(u)
    else:
        for url in urls:
            u = urlparse(url)
            if u.scheme == 'http':
                if ':' in u.netloc:
                    url_list.append(url)
                else:
                    url = u.scheme + '://' + u.netloc + ':80'
                    if u.path:
                        url += u.path
                        url_list.append(url)
                    else:
                        url_list.append(url)
            elif u.scheme == 'https':
                if ':' in u.netloc:
                    url_list.append(url)
                    continue
                else:
                    url = u.scheme + '://' + u.netloc + ':443'
                    if u.path:
                        url += u.path
                        url_list.append(url)
                    else:
                        url_list.append(url)
            else:
                if ':' in u.netloc:
                    port = u.netloc.split(':')[-1]
                    if port in http_port_list:
                        url = 'http://' + url
                        url_list.append(url)
                    if port in https_port_list or port.endswith('43'):
                        url = 'https://' + url
                        url_list.append(url)
    return url_list


def start_burp_scan(api_url, url):
    """Initiates request to the Burp API to start a scan for a specified
    target URL. Scope is limited to the URL by default to prevent going
    out of the scope of the url being scanned.
    """
    # Tests connection to the API. Exits the function if unsuccessful.
    if not test_api_connection(api_url):
        return False
    api_scan_url = api_url.strip('/') + '/scan'

    # Automatically sets the scope to the URL. This prevents the scanner
    # to scan out of the scope of the URL you are providing.

    data = {}
    data["scan_configurations"] = []
    data["scope"] = {"include": [{"rule": url, "type": "SimpleScopeDef"}]}
    data["urls"] = [url]

    if args.audit_config:
        with open(args.audit_config, 'r') as ac:
            audit_config = ac.read()
            data['scan_configurations'].append({"config": audit_config, "type": "CustomConfiguration"})
    if args.crawl_config:
        with open(args.crawl_config, 'r') as cc:
            crawl_config = cc.read()
            data['scan_configurations'].append({"config": crawl_config, "type": "CustomConfiguration"})

    print(data)

    try:
        if args.proxy:
            resp = requests.post(api_scan_url, json=data, proxies=proxy)
        else:
            resp = requests.post(api_scan_url, json=data)
    except Exception as e:
        if args.debug:
            print(e)
        return False
    if resp.status_code == 201:
        scan_id = resp.headers.get('location')
        return scan_id
    else:
        if args.debug:
            print('Unable to start Burp scan, probably something wrong with config settings.')
        return False


def prepare_scan(url):
    """
    Scans the URL to see if a web service is available, then scans with Burp.
    """
    try:
        resp = requests.get(url, verify=False, timeout=timeout)
    except Exception as e:
        print('Error connecting to {}'.format(url))
        if args.debug:
            print('Error connecting to {}: {}'.format(url, e))
        return
    task_id = start_burp_scan(burp_api_url, url)
    if task_id:
        print('Started scanning {}. Task Id: {}'.format(url, task_id))
        time.sleep(10)
        get_results(task_id, url)


def get_results(task_id, url):
    """Check for scan results and if done, write result to JSON file."""
    status_url = burp_api_url + "/scan/" + task_id
    scan_url = urlparse(url).netloc

    while True:
        try:
            resp = requests.get(status_url)
        except Exception as e:
            print('Error connecting to {}'.format(status_url))
            if args.debug:
                print('Error connecting to {}: {}'.format(status_url, e))
            return

        if resp:
            status = resp.json()
            print("URL: " + scan_url + " ID: " + task_id + " Status: " + str(status['scan_metrics']['crawl_and_audit_progress']) + '%')

            if status['scan_status'] == 'succeeded':
                print("DONE!")
                filename = 'out/' + scan_url + "_" + task_id + '.json'
                with open(filename, 'w') as outfile:
                    json.dump(status, outfile)
                break
            elif status['scan_status'] == 'auditing' or status['scan_status'] == 'crawling':
                time.sleep(15)
            else:
                print('Something went wrong!')
                break


def create_folder():
    """Creates directories if missing"""
    if not os.path.exists("out/"):
        os.makedirs("out/")

def process_queue():
    """Processes the url queue and calls the scan_with_burp function"""
    while True:
        current_url = url_queue.get()
        prepare_scan(current_url)
        url_queue.task_done()


def main():
    """Normalizes the URLs and starts multithreading"""
    if not test_api_connection(burp_api_url):
        exit()
    create_folder()
    processed_urls = normalize_urls(urls)

    for i in range(number_of_threads):
        t = threading.Thread(target=process_queue)
        t.daemon = True
        t.start()

    for current_url in processed_urls:
        url_queue.put(current_url)

    url_queue.join()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug",
                        help="Show detailed exceptions",
                        action="store_true")
    parser.add_argument("-pr", "--proxy",
                        help="Specify a proxy to use (-p 127.0.0.1:8080)")
    parser.add_argument("-u", "--url",
                        help="specify a single url formatted http(s)://addr:port.")
    parser.add_argument("-uf", "--url_file",
                        help="specify a file containing urls formatted http(s)://addr:port.")
    parser.add_argument("-ac", "--audit_config",
                        help="Use config file for audit settings")
    parser.add_argument("-cc", "--crawl_config",
                        help="Use config file for crawl settings")
    parser.add_argument("-t", "--threads",
                        nargs="?",
                        type=int,
                        const=30,
                        default=30,
                        help="Specify number of threads (default=30)")
    parser.add_argument("-to", "--timeout",
                        nargs="?",
                        type=int,
                        default=10,
                        help="Specify number of seconds until a connection timeout (default=10)")
    parser.add_argument("-a", "--api_address",
                        nargs="?",
                        const='127.0.0.1:1337',
                        default='127.0.0.1:1337',
                        help="Specify the URL of the Burp API in addr:port format (default=127.0.0.1:1337)")
    parser.add_argument("-k", "--key",
                        nargs="?",
                        const='',
                        default='',
                        help="Specify the Burp API key (default=''")

    args = parser.parse_args()

    number_of_threads = args.threads
    timeout = args.timeout
    burp_api_addr = args.api_address
    API_KEY = args.key
    burp_api_url = 'http://{}/{}/v0.1/'.format(burp_api_addr, API_KEY)

    if not args.url and not args.url_file:
        parser.print_help()
        print('\n[-] Please specify a single URL (-u) or file containing a list of URLs (-uf)\n')
        exit()
    if args.url and args.url_file:
        parser.print_help()
        print("\n[-] Please specify a URL (-u) or an input file containing URLs (-uf). Not both\n")
        exit()
    if args.proxy:
        try:
            proxy_host = args.proxy.split(':')[0]
            proxy_port = args.proxy.split(':')[1]
        except IndexError:
            parser.print_help()
            print(
                "\n[-] Error parsing the proxy. Check to make sure the correct format is used. Example -pr 127.0.0.1:8080\n")
            exit()
        proxy = {'http': proxy_host + ':' + proxy_port}
    if args.url:
        urls = [args.url]
        csv = False
    if args.url_file:
        urlfile = args.url_file
        csv = False

        if urlfile.lower().endswith('.csv'):
            csv = True

        if not os.path.exists(urlfile):
            print("\n[-] The file cannot be found or you do not have permission to open the file.\n")
            exit()
        with open(urlfile) as fh:
            urls = fh.read().splitlines()
            if csv:
                del urls[0]

    print("***** WELCOME TO BurpCLI *****")

    print('\n[*] Loaded {} URL(s)...\n'.format(len(urls)))
    time.sleep(3)

    # suppress SSL warnings in the terminal
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # initiates the queue and sets the print lock
    url_queue = queue.Queue()
    print_lock = threading.Lock()
    main()