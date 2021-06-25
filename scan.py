import requests 
import argparse
import hashlib 
import sys

#ARGUMENTS
def parse_arguments():
    parser = argparse.ArgumentParser()

    #REQUIRED ARGUMENTS
    parser.add_argument("-f", dest = "file" , required = True)
    parser.add_argument("-k", dest = "key", required = True)

    #OPTIONAL ARGUMENTS
    parser.add_argument("-hash", dest = "hash", required = False, default = "md5")
    parser.add_argument("-m", dest = "metadata", required = False, default = None)

    #FILE NAME
    parser.add_argument("-n", dest = "preserve", action = "store_true", required = False, default = None)
    #PASSWORD PROTECTED FILES ONLY
    parser.add_argument("-p", dest = "pwd", required = False, default = None)
    #SAMPLE SHARING (0 or 1)
    parser.add_argument("-s", dest = "share", action = "store_true", default = None, required = False)
    parser.add_argument("-w", dest = "workflow", default = None )


    args = parser.parse_args()
    if args.preserve:
        args.preserve = args.file
    validate(args)
    return args

#VALIDATE ARGUMENTS
def validate(args):
    workflow_values = ['mcl', 'metadefender', 'rest', 'sanitize', 'disabled', 'unarchive']
    if args.workflow and args.workflow not in workflow_values:
        print("Invalid workflow variable given, allowed values: mcl-metadefender-rest-sanitize-disabled-unarchive")
        sys.exit(0)

#SCAN FILES (supports https and binary)
def scan_file(api_key, file, file_name = None, archive_pwd = None, sharing = None, user_agent = None):
    #URL to accress files
    url = "https://api.metadefender.com/v4/file"
    headers = {'apikey': api_key, 'archivepwd': archive_pwd, 'samplesharing': sharing, 
                'user_agent': user_agent}
    try: 
        response = requests.post(url = url, data = file, headers = headers)
        output_data = response.json()
    except requests.exceptions.RequestException as err_req:
        print ("REQUEST ERROR: ", err_req)
        sys.exit(0)
    except requests.exceptions.HTTPError as err_http:
        print ("HTTP ERROR: ", err_http)
        sys.exit(0)
    except requests.exceptions.ConnectionError as err_conn:
        print ("CONNECTION ERORR: ", err_conn)
        sys.exit(0)
    except requests.exceptions.Timeout as err_to:
        print ("TIMEOUT ERROR: ", err_to)
        sys.exit(0)
    except: 
        print ("Unable to scan file, please try again.")
        sys.exit(0)
    return output_data['data_id']

#RETRIEVE DATA THROUGH API 
def retrieve_data(url, api_key, datatype, metadata = '0'):
    headers = {'apikey': api_key, 'file-metadata': metadata}
    try:
        response = requests.get(url = url,headers = headers)
        output_data = response.json()
    except requests.exceptions.RequestException as err_req:
        print ("REQUEST ERROR:", err_req)
        sys.exit(0)
    except requests.exceptions.HTTPError as err_http:
        print ("HTTP ERROR:", err_http)
        sys.exit(0)
    except requests.exceptions.ConnectionError as err_conn:
        print ("CONNECTION ERORR:", err_conn)
        sys.exit(0)
    except requests.exceptions.Timeout as err_to:
        print ("TIMEOUT ERROR:", err_to)
        sys.exit(0)
    except:
        print ("Unable to scan {0}".format(datatype))
        sys.exit(0)

    return output_data

#CALCULATE HASH 
def calculate_hash(hash_type, file_name, chunk_size = 65536):
    try:
        if hash_type == "md5":
            hash = hashlib.md5()
        elif hash_type == "sha1":
            hash = hashlib.sha1()
        elif hash_type == "sha256":
            hash = hashlib.sha256()
        with open(file_name, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hash.update(chunk)
    except:
        print("Unable to hash file...")
        sys.exit(0)
    return hash.hexdigest()

#DISPLAY RESULTS (FORMATTED)
def display_results(results):
    print("filename: {file_name}".format(file_name=results['file_info']['display_name']))
    print("overall_status: {status}".format(status=results['scan_results']['scan_all_result_a']))

    for k,v in results['scan_results']['scan_details'].items():
        print("\nengine: {engine}".format(engine=k))
        print("threat_found: {thread}".format(thread=v['threat_found'] if v['threat_found'] else 'clean'))
        print("scan_result: {result}".format(result=v['scan_result_i']))
        print("def_time: {time}".format(time=v['def_time']))

#RUN SCAN
if __name__ == '__main__':
    args = parse_arguments()

    #Steps:
    #1: CALCULATE HASH OF FILE
    file_hash = calculate_hash(args.hash, args.file).upper()

    #2: CHECK FOR CACHED RESULTS
    url = "https://api.metadefender.com/v4/hash/{0}".format(file_hash)
    scan_result = retrieve_data(url=url, api_key = args.key, metadata=args.metadata, datatype = "hash")

    #3: IF CACHED SKIP TO 6
    if "Not Found" not in scan_result.values():
        display_results(scan_result)
        sys.exit(0)

    #4: IF NO CACHE RESULTS, GET DATA_ID
    with open(args.file, 'rb') as f:
        file = f.read()
    data_id = scan_file(api_key = args.key, file = file, file_name = args.preserve, archive_pwd = args.pwd,sharing = args.share, user_agent = args.workflow)

    #5: PULL DATA_ID TO RETRIEVE RESULTS
    url = "https://api.metadefender.com/v4/file/{0}".format(data_id)
    scan_result = retrieve_data(url = url, api_key = args.key, metadata = args.metadata, datatype = "dataId")
    while scan_result['scan_results']['progress_percentage'] != 100:
            scan_result = retrieve_data(url = url, api_key = args.key, metadata=args.metadata, datatype = "dataId")

    #6: DISPLAY RESULTS
    display_results(scan_result)