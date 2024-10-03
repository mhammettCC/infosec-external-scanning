import configparser, csv, re, shutil, os, subprocess, platform, requests
import pandas as pd
from slack_sdk.web import WebClient
from slack_sdk.errors import SlackApiError
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def create_dirs(folder_name):
    data_folder = folder_name
    if not os.path.exists(data_folder):
        os.makedirs(data_folder)
        print(f"<create_dirs> '{data_folder}' : created successfully")

def read_configs(filename, header, value):
    # config.ini
    #
    # [JIRA]
    # JIRA_API_KEY = your_api_key_here
    # JIRA_UAT_API_KEY = your_api_key_here
    # Load INI file
    # example usage: read_configs('config.ini', 'JIRA', 'JIRA_API_KEY')
    config = configparser.ConfigParser()
    config.read(filename)

    # Access the API key
    value = config[header][value]
    return value

def nmap_convert_text_to_csv(input_file, output_file):
    # Example usage:
    # input_file = '../data/external_port_IVM_tagging/gcp_pub_scan'
    # output_file = '../data/external_port_IVM_tagging/gcp_pub_scan.csv'
    # convert_text_to_csv(input_file, output_file)
    # print(input_file)
    with open(input_file, 'r', newline='') as file:
        content = file.read()
    content = content.replace('\r\n', '\n')
    # Regular expression to handle IP addresses, ports, and optional space after separator
    # results_pattern = r"Results from: ([\d\.]+)\n([\d\/\w\s]+)\n---------------------------------"
    results_pattern = r"Results from: ([\d\. ]+)\n([\d\/\w\s]+)\n-+\s"
    matches = re.findall(results_pattern, content)
    # Prepare the data for CSV
    data = []
    for match in matches:
        ip_address = match[0]
        ports_info = match[1].strip().split('\n')
        for port_info in ports_info:
            port_data = re.split(r'\s+', port_info)
            port_number = port_data[0]
            state = port_data[1]
            service = port_data[2]
            data.append([ip_address, port_number, state, service])
    # Write to CSV
    with open(output_file, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['IP Address', 'Port', 'State', 'Service'])
        writer.writerows(data)
    return output_file


def port_array_from_csv(input_file):
    port_values = []

    # Open the CSV file
    with open(input_file, mode='r') as file:
        reader = csv.DictReader(file)  # Read the CSV as a dictionary

        # Check if 'Port' is a valid column
        if 'Port' not in reader.fieldnames:
            raise ValueError("The 'Port' column does not exist in the CSV file.")

        # Iterate through the rows and collect the values from the 'Port' column
        for row in reader:
            port = row['Port'].split('/')[0]
            if port not in port_values:
                port_values.append(port)

    return port_values


def rename_files_to_previous(directory):
    # Check if the given path is a directory
    if not os.path.isdir(directory):
        raise ValueError(f"{directory} is not a valid directory.")

    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)

        # Skip if it's not a file
        if os.path.isfile(file_path):
            new_file_path = os.path.join(directory, "previous_file.txt")

            # Rename the file to 'previous_file.txt'
            os.rename(file_path, new_file_path)
            print(f"Renamed '{filename}' to 'previous_file.txt'")


def rename_file(file_path, prepend):
    # Check if the file exists
    if not os.path.isfile(file_path):
        raise ValueError(f"<rename_file> {file_path} is not a valid file.")

    # Get the directory of the file and basename (file name)
    directory = os.path.dirname(file_path)
    basename = os.path.basename(file_path)

    # Define the new name with prepend
    new_file_path = os.path.join(directory, f"{prepend}_{basename}")

    # Check if the new file name already exists
    if os.path.exists(new_file_path):
        print(f"<rename_file> File '{new_file_path}' already exists. Skipping rename.")
    else:
        # Rename the file if no file with the new name exists
        os.rename(file_path, new_file_path)
        print(f"<rename_file> Renamed '{file_path}' to '{new_file_path}'")

def move_files_to_timestamped_dir(directory, exclude_files):
    # Example usage
    # exclude_files = ['previous_report.csv', 'another_file.txt']
    # move_files_to_timestamped_dir('/path/to/your/directory', exclude_files)

    # Get the current timestamp and format it as YYYY_MM_DD_HH_MM
    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M")

    # Create a new directory based on the timestamp
    timestamped_dir = os.path.join(directory, timestamp)
    os.makedirs(timestamped_dir, exist_ok=True)

    # Iterate over all files in the directory
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)

        # Check if it's a file and not in the exclude list
        if os.path.isfile(file_path) and filename not in exclude_files:
            # Move the file to the new timestamped directory
            shutil.move(file_path, os.path.join(timestamped_dir, filename))
            print(f"<move_files_to_timestamped_dir> Moved '{filename}' to '{timestamped_dir}'")

    print(f"<move_files_to_timestamped_dir> All files moved to {timestamped_dir} except {exclude_files}.")


def find_latest_timestamped_folder(directory):
    # Regular expression to match timestamp in folder names (YYYY_MM_DD_HH_MM)
    timestamp_pattern = r"(\d{4}_\d{2}_\d{2}_\d{2}_\d{2})"

    latest_folder = None
    latest_timestamp = None

    # Iterate through the directory to find folders with a timestamp
    for foldername in os.listdir(directory):
        folder_path = os.path.join(directory, foldername)

        # Check if it's a directory and contains a timestamp
        if os.path.isdir(folder_path):
            match = re.search(timestamp_pattern, foldername)
            if match:
                # Parse the timestamp into a datetime object
                timestamp_str = match.group(1)
                timestamp = datetime.strptime(timestamp_str, "%Y_%m_%d_%H_%M")

                # Compare with the latest timestamp
                if latest_timestamp is None or timestamp > latest_timestamp:
                    latest_timestamp = timestamp
                    latest_folder = folder_path

    return latest_folder


def find_file_in_folder(folder_path, search_term="previous"):
    # Iterate over files in the folder to search for the specified term in the name
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)

        # Check if it's a file and if the filename contains the search term
        if os.path.isfile(file_path) and search_term in filename:
            print(f"<find_file_in_folder> Found file: {filename}")
            return file_path

    print(f"<find_file_in_folder> No file containing '{search_term}' found in {folder_path}")
    return None


def find_latest_folder_and_search_file(directory, search_term="previous"):
    # Example usage
    # latest_file = find_latest_folder_and_search_file('/path/to/your/directory', 'previous')
    # Find the latest timestamped folder
    latest_folder = find_latest_timestamped_folder(directory)

    if latest_folder:
        print(f"<find_latest_folder_and_search_file> Latest folder found: {latest_folder}")
        # Search for the file within the latest folder
        return find_file_in_folder(latest_folder, search_term)
    else:
        print(f"<find_latest_folder_and_search_file> No timestamped folder found in {directory}")
        return None


def find_all_timestamped_folders(directory):
    # Regular expression to match timestamp in folder names (YYYY_MM_DD_HH_MM)
    timestamp_pattern = r"(\d{4}_\d{2}_\d{2}_\d{2}_\d{2})"

    timestamped_folders = []

    # Iterate through the directory to find folders with a timestamp
    for foldername in os.listdir(directory):
        folder_path = os.path.join(directory, foldername)

        # Check if it's a directory and contains a timestamp
        if os.path.isdir(folder_path):
            match = re.search(timestamp_pattern, foldername)
            if match:
                # Parse the timestamp into a datetime object
                timestamp_str = match.group(1)
                timestamp = datetime.strptime(timestamp_str, "%Y_%m_%d_%H_%M")
                timestamped_folders.append((timestamp, foldername, folder_path))

    return timestamped_folders


def keep_latest_n_folders(directory, n):
    # Example usage
    # keep_latest_n_folders('/path/to/your/directory', 3)
    # Find all timestamped folders
    timestamped_folders = find_all_timestamped_folders(directory)

    # Sort folders by timestamp in descending order
    timestamped_folders.sort(reverse=True, key=lambda x: x[0])  # Sort by timestamp

    # Keep the latest n folders
    folders_to_keep = timestamped_folders[:n]
    folders_to_remove = timestamped_folders[n:]  # The rest will be removed

    # Print folders to keep
    print(f"Keeping the latest {n} folders:")
    for _, foldername, folder_path in folders_to_keep:
        print(f" - {foldername}")

    # Optionally, remove the other folders
    for _, foldername, folder_path in folders_to_remove:
        os.rmdir(folder_path)  # Remove the folder (make sure it's empty)
        print(f"Removed: {foldername}")

def extract_row_and_create_file(row_name, csv_file_path, output_file_path):
    output = []

    # Open the CSV file and extract the 'ip_address' column
    with open(csv_file_path, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file)

        for c in csv_reader:
            row = c.get(row_name)  # Adjust if the column header is different
            if row:
                output.append(row)

    # Save the extracted IP addresses to the output file
    with open(output_file_path, mode='w') as output_file:
        for o in output:
            output_file.write(f"{o}\n")

    print(f"<extract_row_and_create_file> Extracted {len(output)} {row_name} to {output_file_path}")

def run_script_w_output(script_path, *args):
    try:
        # Create the command list by combining the script path with the arguments
        cmd = [script_path] + list(args)

        if platform.system() == 'Windows':
            # For Windows, run a batch file with parameters
            result = subprocess.run(cmd, check=True, text=True)
        else:
            # For Linux/macOS, run a shell script with parameters
            result = subprocess.run(['bash'] + cmd, check=True, universal_newlines=True)

        # The output is displayed in real-time by default since we are not capturing it
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"<run_script_w_output> Error occurred: {e}")
        return e.returncode

def send_slack_message(channel, message):
    # pip install slack-sdk
    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config.ini'))
    token = read_configs(config_path, 'Slack', 'SLACK_API_KEY')
    client = WebClient(token)
    try:
        response = client.chat_postMessage(
            channel=channel,
            text=message
        )
        print("<send_slack_message> Message sent successfully: ", response["ts"])
    except SlackApiError as e:
        print(f"Error posting message: {e}")

def search_tags(filter, outfile_name):
    # example usage : search_tags('ext_port', '../data/external_port_IVM_tagging/tag_ids.csv'))
    print(f'<search_tags>Starting tag search for "{filter}":')
    tag_array = []
    url = f'{base_url}/api/3/tags'
    page = 0  # Start from page 0
    page_size = 100  # Pull 50 results per request

    with open(outfile_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        # Write the header row
        writer.writerow(['Name', 'ID'])

        # Make the first request to get the total number of pages
        response = requests.get(url=url, verify=False, auth=(uname, passw), params={'page': page, 'size': page_size})
        response_json = response.json()

        # Get the total number of pages from the response
        total_pages = response_json['page']['totalPages']

        # Iterate through all the pages
        while page < total_pages:
            # If it's not the first page, make the request again for subsequent pages
            if page > 0:
                response = requests.get(url=url, verify=False, auth=(uname, passw),
                                        params={'page': page, 'size': page_size})
                response_json = response.json()

            resources = response_json.get('resources', [])
            print(f'<search_tags> Processing page {page} / {total_pages}')

            # Iterate through resources and filter based on the filter variable
            for r in resources:
                tag_id = r.get('id')
                name = r.get('name')

                # Apply the filter condition (adjust based on what you want to filter)
                if filter in str(r):  # Example: checking if filter is part of any value in resource
                    print(f'<search_tags> --- Found: {name}')
                    writer.writerow([name, tag_id])

            # Move to the next page
            page += 1
        return outfile_name

def download_report(id, save_dir):
    # example usage: download_report('1300', '../data/external_port_IVM_tagging')
    url_get_report = f'{base_url}/api/3/reports/{id}/history/latest/output'
    response = requests.get(url=url_get_report, auth=(uname, passw))
    print(response.status_code)
    # Check if the request was successful
    if response.status_code == 200:
        # Extract the filename from the response headers
        content_disposition = response.headers.get('Content-Disposition')
        if content_disposition:
            filename = content_disposition.split('filename=')[1].strip('"')
        else:
            # If no filename is provided, default to report_<id>.csv
            filename = f"ivm_report_{id}.csv"

        # Ensure the file has a .csv extension
        if not filename.endswith('.csv'):
            filename = filename.split('.')[0] + '.csv'

        # Create the full path for saving the file
        file_path = os.path.join(save_dir, filename)

        # Save the report to the specified directory
        with open(file_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)

        print(f"<download_report> CSV report saved to {file_path}")
        return file_path
    else:
        print(f"<download_report> Failed to download report. Error: {response.status_code}, {response.text}")
        return None

def add_tag_to_asset(asset_id, tag_id):
    url = f'{base_url}/api/3/tags/{tag_id}/assets/{asset_id}'
    payload = {
        "tagId": tag_id
    }
    response = requests.put(url=url, auth=(uname, passw), json=payload)
    if response.status_code == 200:
        print(f'<add_tag_to_asset> Tag added to asset {asset_id}')
    elif response.status_code == 500:
        print(f'<add_tag_to_asset> Tag was already added to asset {asset_id}')
    else:
        print(f'<add_tag_to_asset> Failed to add tag to asset {asset_id}: {response.text}')

def create_tag(tag_name):
    url = f'{base_url}/api/3/tags'

    # filter_json = [{"field": "ip-address" , "operator": "is", "value": ip_address}]
    params = {
                "color": "default",
                "name": tag_name,
                "type": "custom"
            }
    sesh = requests.session()  # Holds API call session
    response = sesh.post(url=url, verify=False, auth=(uname, passw), json=params)
    print(f'<create_tag> Tag {tag_name} added/validated')

def tag_assets():
    # Convert NMAP scan to CSV
    print('<nmap_convert_text_to_csv> Convert NMAP scan to CSV')
    nmap_csv = nmap_convert_text_to_csv(input_file, output_file)
    # Create array of ports from NMAP scan
    print('<port_array_from_csv> Finding all unique ports from NMAP scan')
    port_array = port_array_from_csv(nmap_csv)
    print(f'<port_array_from_csv> Unique port array: {port_array}')
    # Pull list of ports from IVM
    print('<search_tags> Pulling all ext_port tags from IVM')
    tag_ids_csv = search_tags('ext_port', tag_ids_output_file)
    print(f'<search_tags> Pulled file {tag_ids_csv}')
    print('Comparing unique ports from NMAP scan with port list in IVM')
    with open(tag_ids_csv, 'r') as file:
        reader = csv.DictReader(file)
        csv_port_array = []
        for row in reader:
            csv_port = row.get('Name').split(':')[1]
            csv_port_array.append(csv_port)
        for p in port_array:
            if p not in csv_port_array:
                tag_name = 'ext_port:' + str(p)
                create_tag(tag_name)
    print('<search_tags> Re-pulling tag IDs for reference')
    tag_ids_csv = search_tags('ext_port', tag_ids_output_file)
    print('Making IP and Tag asset ID mapping')
    ip_service_df = pd.read_csv(ip_service_df_path)
    asset_df = pd.read_csv(asset_df_path)
    port_df = pd.read_csv(port_df_path)

    # Strip spaces from IP addresses
    ip_service_df['IP Address'] = ip_service_df['IP Address'].str.strip()
    asset_df['ip_address'] = asset_df['ip_address'].str.strip()

    # Split 'Port' in ip_service_df to match with 'ext_port' from port_df
    ip_service_df['Port'] = ip_service_df['Port'].str.split('/').str[0]

    # Prepare a list to collect the results
    results = []

    # Iterate through each entry in ip_service_df
    for _, ip_row in ip_service_df.iterrows():
        ip_address = ip_row['IP Address']

        port = ip_row['Port']

        # Find matching asset
        asset_row = asset_df[asset_df['ip_address'] == ip_address]
        if not asset_row.empty:
            asset_id = asset_row['asset_id'].values[0]

            # Find matching port
            port_row = port_df[port_df['Name'] == f'ext_port:{port}']
            if not port_row.empty:
                port_id = port_row['ID'].values[0]
                results.append({'asset_id': asset_id, 'ID': port_id})

    # Create a DataFrame from results and save to CSV
    ip_tag_mapping_df = pd.DataFrame(results)
    ip_tag_mapping_df.to_csv(ip_tag_mapping, index=False)
    with open(ip_tag_mapping, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            asset_id = row['asset_id']
            tag_id = row['ID']
            add_tag_to_asset(asset_id, tag_id)

def get_assets_by_tag(tag_id):
    # Endpoint to get assets under a specific tag
    url = f"{base_url}/api/3/tags/{tag_id}/assets"
    response = requests.get(url, auth=(uname, passw))
    if response.status_code == 200:
        response_json = response.json()
        asset_count = len(response_json['resources'])
        return asset_count
    else:
        # Handle errors
        raise Exception(f"<get_assets_by_tag> Error retrieving assets: {response.status_code} - {response.text}")

###--- MAIN SECTION ---###
# Global Variables
config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config.ini'))
passw = read_configs(config_path, 'Rapid7', 'R7_CT_PASSWORD')
uname = read_configs(config_path, 'Rapid7', 'R7_CT_USER')
base_url = read_configs(config_path, 'Rapid7', 'BASE_URL')
folder_name = 'data'
nmap_script_path = r'/home/mhammett/robot/external_port_IVM_tagging/nmap_f_from_file.sh'  # No dont change file name, only path, can be .sh as well
nmap_targets_path = r'./data/nmap_targets' # No dont change file name, only path
nmap_results_path = r'./data'
ip_service_df_path = r'/home/mhammett/robot/external_port_IVM_tagging/data/nmap_convert_target_results.csv' # No dont change file name, only path
asset_df_path = r'/home/mhammett/robot/external_port_IVM_tagging/data/report.csv' # No dont change file name, only path
port_df_path = r'/home/mhammett/robot/external_port_IVM_tagging/data/tag_ids.csv' # No dont change file name, only path
slack_channel = 'cs_test'

#Specific Variables
file_name = f'{folder_name}/converted_nmap.csv'
input_file = f'{folder_name}/nmap_targets_results'
output_file = f'{folder_name}/nmap_convert_target_results.csv'
tag_ids_output_file = f'{folder_name}/tag_ids.csv'
report_id = '1300' # Do not change
nmap_targets = f'{folder_name}/nmap_targets'
ip_tag_mapping = f'{folder_name}/ip_tag_mapping.csv'

send_slack_message(slack_channel, '`<External Port Labeling>` Running external port scanning and labeling')
create_dirs(folder_name)
try:
   print(">>>>>>>>>>>>>DOWNLOADING IVM REPORT")
   ivm_report_download = download_report(report_id, folder_name)
   print(">>>>>>>>>>>>>PULLING TARGET LIST FROM IVM")
   target_list = extract_row_and_create_file('ip_address', asset_df_path, nmap_targets)
except Exception as e:
   print(f"An error occurred: {str(e)}")
   send_slack_message(slack_channel, '`<External Port Labeling>` There was an error downloading the report or converting the target list')
try:
    # input('Press Enter after Dropping VPN')
    print(">>>>>>>>>>>>>RUNNING NMAP")
    print(nmap_script_path)
    print(nmap_targets_path)
    print(nmap_results_path)
    run_script_w_output(nmap_script_path, nmap_targets_path, nmap_results_path)
except Exception as e:
    print(f"An error occurred: {str(e)}")
    send_slack_message(slack_channel, '`<External Port Labeling>` There was an error running the nmap scan')
try:
    # input('Press Enter after VPN re-established')
    print(">>>>>>>>>>>>>TAGGING ASSETS")
    tag_assets()
    appended_slack_massage = "\nExternal Port Exposure Count Report: (Port:count)\n"
    with open(tag_ids_output_file, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            tag_count = get_assets_by_tag(row['ID'])
            port = row['Name'].split(':')[1]
            appended_slack_massage += f'{port}:{tag_count}\n'

    print('Renaming report file')
    rename_file(f'{folder_name}/report.csv', 'previous')
    print('Moving files for archiving')
    move_files_to_timestamped_dir(folder_name, [])
    previous_report = find_latest_folder_and_search_file(folder_name, 'previous') # This will be for comparing latest previous to current
    keep_latest_n_folders(folder_name, 6) # This is to keep the latest 6 timestamped file names
    send_slack_message(slack_channel,f'`<External Port Labeling>` Workflow complete see <https://consoleconnect.managed.rapid7.com:3780/group.jsp?groupid=260|Externally Exposed Ports group in IVM>{appended_slack_massage}')
except Exception as e:
    print(f"An error occurred: {str(e)}")
    send_slack_message(slack_channel, '`<External Port Labeling>` There was an error tagging, moving, or comparing results')
