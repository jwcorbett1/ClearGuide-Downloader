# This script is based on the ClearGuide example script and other API documentation found at:
#     https://nc.iteris-clearguide.com/about?type=analytics-api


# Use the operating system's native SSL certificate store
import truststore
truststore.inject_into_ssl()


import requests
import urllib.parse
import json
import secrets
import hashlib
import base64
import datetime
import pathlib


# Global constants
COLUMN_HEADING = "route_number"
CLIENT_ID = "CaSCWF6viMWFg67UisSY99hHQFQpiEmQRxFc2NVv"
REDIRECT_URL = "https://nc.iteris-clearguide.com/"
ROUTE_TIME_SERIES_URL = "https://api.iteris-clearguide.com/v1/route/timeseries/"
LOGIN_URL = "https://auth.iteris.com/api/login/"
AUTHORIZE_URL = "https://auth.iteris.com/o/authorize/"
TOKEN_URL = "https://auth.iteris.com/o/token/"
CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"


# List of defined routes in ClearGuide
# The ID needed by the ClearGuide API is not the ID shown in ClearGuide menus
# However, the ID shown in the menus is still needed for the PowerBI dashboard
# To locate the ID for the ClearGuide API:
#     1. Render a timeseries for the route
#     2. The URL will contain the correct ID number
#     3. Look in the query string for a parameter like "...&id=188862&..."
#     4. The number between the "=" and the next "&" is the API ID number
ROUTE_LIST = [
    # Format: ID from query string = ID shown in ClearGuide menus = name of route
    "188862 = 19156 = HE-0001, HO-0002A, I-4700 West",
    "188863 = 19157 = HE-0001, HO-0002A, I-4700 East",
    "188994 = 19162 = I-4400BB, I-4400C West",
    "188995 = 19163 = I-4400BB, I-4400C East",
    "189063 = 19166 = I-5719B North",
    "189064 = 19167 = I-5719B South",
    "189068 = 19169 = I-5746C Inner",
    "189069 = 19170 = I-5746C Outer",
    "189093 = 19171 = I-5889, I-5889B East",
    "189094 = 19172 = I-5889, I-5889B West",
    "189095 = 19173 = HI-0010 East",
    "189096 = 19174 = HI-0010 West",
    "191700 = 19250 = I-5918 North",
    "191701 = 19251 = I-5918 South",
    "191733 = 19252 = HB-0002 HB-0003 HB-0004 West",
    "191734 = 19253 = HB-0002 HB-0003 HB-0004 East",
    "191735 = 19254 = I-5878, I-5883, I-5986B North",
    "191766 = 19255 = I-5878, I-5883, I-5986B South",
    "191799 = 19256 = I-5987 A North",
    "191800 = 19257 = I-5987 A South",
    "191801 = 19258 = I-5987 B North",
    "191802 = 19259 = I-5987 B South",
    "191803 = 19260 = I-6016 North",
    "191804 = 19261 = I-6016 South",
    "191832 = 19263 = I-3306 A, W-5707C East",
    "191833 = 19264 = I-3306 A, W-5707C West",
    "191834 = 19265 = U-2719, U-4437 East",
    "191835 = 19266 = U-2719, U-4437 West",
    "191931 = 19268 = I-5831B East",
    "191932 = 19269 = I-5831B West",
    "191933 = 19270 = I-5993 East",
    "191934 = 19271 = I-5993 West",
    "191935 = 19272 = I-6001 North",
    "191936 = 19273 = I-6001 South",
    "191937 = 19274 = I-5934 North",
    "191938 = 19275 = I-5934 South",
]


# Global variables
session = requests.session()
id_token = ""
s_timestamp = 0
e_timestamp = 0


# Raise an exception based on the provided Response object
def raise_exception(response: requests.Response, message: str, include_redirect_url = False):
    # append the status code and error message to the provided text
    message += f" Status Code: {response.status_code}."
    error = json.loads(response.text)["msg"]  # extract error message from JSON
    message += f" Error Message: {error}"
    # optionally, also append the redirect URL
    if (include_redirect_url and
            response.history and
            response.history[0].status_code == 302):
        location = response.history[0].headers.get("Location")
        message += f" Redirect URL: {location}"
    # raise the exception
    raise Exception(message)


# Step 1 of the OAuth 2.0 process - log into the API
def send_user_credentials(username: str, password: str):
    # reset the session in case the user is already logged in
    global session
    session = requests.session()
    # send over the username and password
    credentials = {
        "username": username,
        "password": password,
    }
    response = session.post(LOGIN_URL, data=credentials)
    # check if the login was successful
    if response.status_code != 200:
        raise_exception(response, message="Error sending user credentials.")


# Step 2a of the OAuth 2.0 process - create a random code verifier string
def create_code_verifier(length = 100):
    # loop for "length" times and append 1 randomly selected character each time
    code_verifier = ""
    for _ in range(length):
        code_verifier += secrets.choice(CHARACTERS)
    # return the code verifier
    return code_verifier


# Step 2b of the OAuth 2.0 process - create a SHA256 hash challenge from the verifier
def create_code_challenge(code_verifier: str):
    # encode, hash, digest, re-encode, decode, and then strip any "=" signs
    ascii_encoded = code_verifier.encode("ascii")
    sha256_digest = hashlib.sha256(ascii_encoded).digest()
    base64_encoded = base64.urlsafe_b64encode(sha256_digest)
    code_challenge = base64_encoded.decode("ascii").strip("=")
    # return the code challenge
    return code_challenge


# Step 2c of the OAuth 2.0 process - submit the challenge to receive an authorization code
def request_authorization_code(code_challenge: str):
    # package the code challenge into a query string
    query_parameters = {
        "response_type": "code",
        "response_mode": "query",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URL,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    query_string = urllib.parse.urlencode(query_parameters)
    query_url = f"{AUTHORIZE_URL}?{query_string}"
    # use the current session to send over the code challenge
    response = session.get(query_url)
    # check if the response makes sense
    if (not response.history
         or response.history[0].status_code != 302  # not redirected?
         or response.status_code != 200
         or REDIRECT_URL not in response.url):  # incorrect URL returned?
        raise_exception(
            response,
            message="Error requesting authorization code.",
            include_redirect_url=True)
    # unpackage the authorization code from the returned query string
    query_string = response.url.split("?")[1]
    query_parameters = urllib.parse.parse_qs(query_string)
    authorization_code = query_parameters["code"][0]
    # return the authorization code
    return authorization_code


# Step 3 of the OAuth 2.0 process - submit the code and verifier to receive an id token
# You are finished logging in after completing this step
def request_id_token(authorization_code: str, code_verifier: str):
    # assemble the authorization parameters
    post_parameters = {
        "client_id": CLIENT_ID,
        "code": authorization_code,
        "code_verifier": code_verifier,
        "redirect_uri": REDIRECT_URL,
        "grant_type": "authorization_code",
    }
    # use the current session to send over the authorization parameters
    response = session.post(TOKEN_URL, data=post_parameters)
    # check if the id token was granted
    if response.status_code != 200:
        raise_exception(response, message="Error requesting id token.")
    # extract the id token from the returned JSON
    json = response.json()
    global id_token
    id_token = json["id_token"]


# Complete all the steps to log into the Iteris ClearGuide Analytics API
def log_into_clearguide(username: str, password: str, verifier_length = 100):
    send_user_credentials(username, password)
    code_verifier = create_code_verifier(verifier_length)
    code_challenge = create_code_challenge(code_verifier)
    authorization_code = request_authorization_code(code_challenge)
    request_id_token(authorization_code, code_verifier)


# Set the start and end times to use when downloading reports
def set_report_time_period(start_timestamp: int, end_timestamp: int):
    global s_timestamp
    s_timestamp = start_timestamp
    global e_timestamp
    e_timestamp = end_timestamp


# Retrieve time-series traffic metrics for a defined route
def download_route_time_series_report(route_id: str):
    # assemble the authorization header
    authorization_header = { "Authorization": f"Bearer {id_token}" }
    # package the ClearGuide API parameters into a query string
    query_parameters = {
        "customer_key": "nc",
        "e_timestamp": e_timestamp,
        "format": "csv",
        "granularity": "hour",
        "holidays": "true",
        "metrics": "avg_speed,tti_ff",
        "route_id": route_id,
        "s_timestamp": s_timestamp,
    }
    query_string = urllib.parse.urlencode(query_parameters)
    query_url = f"{ROUTE_TIME_SERIES_URL}?{query_string}"
    # use the current session to send over the ClearGuide API query
    response = session.get(query_url, headers=authorization_header)
    # check if the query was successful
    if response.status_code != 200:
        raise_exception(response, message="Error downloading route timeseries.")
    # return the raw CSV data
    return response.text


# Request a date from the user and convert it to a Unix timestamp
def input_timestamp(message: str):
    # request the date and convert it to a floating-point timestamp
    input_date = input(message)
    input_date = input_date.replace("/", "-")
    input_datetime = datetime.datetime.strptime(input_date, "%m-%d-%Y")
    float_timestamp = input_datetime.timestamp()
    # convert the timestamp to an integer and return
    return int(float_timestamp)


# Create a new subfolder within "Downloads" and build a file path to it
# The subfolder will be named based on the currently set start and end dates
def construct_file_path():
    # build the path to the user's "Downloads" folder - looks weird, but works
    downloads_folder = str(pathlib.Path.home()) + "/Downloads"
    # format the timestamps like "mm-dd-yyyy"
    start_date = datetime.datetime.fromtimestamp(s_timestamp)
    start_string = start_date.strftime("%m-%d-%Y")
    end_date = datetime.datetime.fromtimestamp(e_timestamp)
    end_string = end_date.strftime("%m-%d-%Y")
    # create the new subfolder
    file_path = downloads_folder + f"/{start_string} thru {end_string}"
    pathlib.Path(file_path).mkdir(exist_ok=True)
    # return the path to the new subfolder
    return file_path


# Output a pre-formatted string as a CSV file
# Optionally, append a new column with the provided heading and value
def output_csv_file(file_path: str, csv_data: str, column_heading = "", column_value = ""):
    # if the column heading and value were provided, append the new column
    if column_heading and column_value:
        column_heading = column_heading.strip()  # clean up string
        column_value = column_value.strip()  # clean up string
        # split the data into individual lines
        csv_lines = csv_data.split("\n")
        for i in range(len(csv_lines) - 1):  # index must be 0 to length - 1
            csv_lines[i] = csv_lines[i].strip() + ","
            if i == 0:
                csv_lines[0] += column_heading   # append heading to first line
            else:
                csv_lines[i] += column_value  # append value to all other lines
        csv_data = "\n".join(csv_lines)
    # output the CSV data to a new file with the provided file path
    with open(file_path, "w", newline="") as file:
        file.write(csv_data)


# Log into the ClearGuide API and download all routes in the route list
def main():
    # log into the Iteris ClearGuide Analytics API
    username = input("\nEnter your ClearGuide username: ")
    password = input("Enter your ClearGuide password: ")
    log_into_clearguide(username, password)
    print("Success!!! You are now logged into the Iteris ClearGuide Analytics API.")
    # configure the start and end timestamps to use
    start_timestamp = input_timestamp("\nEnter the start date (mm-dd-yyyy): ")
    end_timestamp = input_timestamp("Enter the  end  date (mm-dd-yyyy): ")
    print()
    end_timestamp += (23 * 3600)  # expand to end of selected day
    set_report_time_period(start_timestamp, end_timestamp)
    # create a new folder in the user's Downloads folder
    file_path = construct_file_path()
    # get today's date as a string
    download_date = datetime.date.today()
    date_string = download_date.strftime("%m-%d-%Y")
    # for each route in the list, download its data and save it to a CSV file
    for route in ROUTE_LIST:
        # split the route info into API ID, shown ID, and route name
        route_parts = route.split("=")
        route_id = route_parts[0].strip()
        route_number = route_parts[1].strip()
        filename = route_parts[2].strip() + ".csv"  # use route name as filename
        # download the raw CSV data and save as a new file
        print(f"Downloading {filename}...")
        full_file_path = file_path + f"/{date_string} {filename}"
        output_csv_file(
            file_path=full_file_path,
            csv_data=download_route_time_series_report(route_id),
            column_heading=COLUMN_HEADING,
            column_value=route_number)
    # let the user know everything was successful
    print("\nSuccess!!! Data for all defined routes has been downloaded.")
    print(f"The data was downloaded to: {file_path}")


# Run the script
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
        print("An error occurred. Please re-run the script.")
