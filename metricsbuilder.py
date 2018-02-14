import os
import base64
import json
import requests
import argparse
import datetime
import re


# - Offline servers
# - Users who have never logged in
# - Users who have not logged in in ___ days
# - Apps that are not associated with a group
# - Servers with no apps
# - All groups and users contained within them


class controller:
    ##################################################
    # Replace the below fields with your own details #
    ##################################################

    ORGANIZATION_ID = ""
    TEAMSERVER_URL = ""
    API_KEY = ""
    SERVICE_KEY = ""
    USERNAME = ""

    def __init__(self):
        parser = argparse.ArgumentParser(description='Communicate with the Contrast Rest API')

        parser.add_argument("-o", help='Specify the path to write text files to', nargs=1,
                            type=str, metavar="")

        argt = parser.parse_args()
        if argt.o:
            self.outputpath = argt.o[0]
        else:
            self.outputpath = os.getcwd()
        print("Writing output to", self.outputpath)

        # print("\nController started\n")

        self.AUTHORIZATION = base64.b64encode((self.USERNAME + ':' + self.SERVICE_KEY).encode('utf-8'))

    def getOfflineServers(self):
        endpoint = self.ORGANIZATION_ID + "/servers/filter?expand=applications,server_license," \
                                          "skip_links&includeArchived=false&offset=0&quickFilter=OFFLINE" \
                                          "&sort=-lastActivity"
        url = self.TEAMSERVER_URL + endpoint

        header = {
            "API-Key": self.API_KEY,
            "Authorization": self.AUTHORIZATION,
        }

        # Get response
        response = requests.get(url=url, headers=header, stream=True)
        jsonreader = json.loads(response.text)

        # Setup file to output results to
        filename = self.outputpath + "/OfflineServers.txt"
        filewriter = open(filename, 'w+')

        # Loop through each server and determine if it is offline
        if jsonreader["success"] is True:
            todaydate = datetime.datetime.today()
            servernum = 1
            print("The following servers are offline as of %s:" % todaydate)
            filewriter.write("The following servers are offline as of %s:\n" % todaydate)
            for server in jsonreader["servers"]:
                if server['status'] == "OFFLINE":  # If the status is offline, add it to our list
                    linetowrite = ("\t%d. %s" % (servernum, server['name']))
                    filewriter.write(linetowrite + "\n")
                    print(linetowrite)
                    servernum += 1
        filewriter.close()

    def getNeverLoggedInUsers(self):
        endpoint = self.ORGANIZATION_ID + "/users?expand=preferences,login,role," \
                                          "skip_links&offset=0&q=&quickFilter=ALL&sort=name"
        url = self.TEAMSERVER_URL + endpoint

        header = {
            "API-Key": self.API_KEY,
            "Authorization": self.AUTHORIZATION,
        }

        # Get response from the request
        response = requests.get(url=url, headers=header, stream=True)
        jsonreader = json.loads(response.text)

        # Setup file to output results to
        filename = self.outputpath + "/NeverLoggedInUsers.txt"
        filewriter = open(filename, 'w+')

        # Loop through each user to determine if they have ever logged in
        if jsonreader["success"] is True:
            user_num = 1
            print("\nThe following users have never logged into the teamserver")
            filewriter.write("The following users have never logged into the teamserver\n")
            for user in jsonreader["users"]:

                # Get their last login time. If there is last_login_time, they've never logged and we add it to the list
                try:
                    lastlogintime = user['login']['last_login_time']
                except:
                    linetowrite = ("\t%d. %s" % (user_num, user['user_uid']))
                    filewriter.write(linetowrite + "\n")
                    print(linetowrite)
                    user_num += 1
        filewriter.close()

    def getUsersLoggedInDays(self, days):
        # Fail the command if the number of days is not positive
        if days < -1:
            print("\n* * The number of days must be greater than 0")

        else:
            endpoint = self.ORGANIZATION_ID + "/users?expand=preferences,login,role," \
                                              "skip_links&offset=0&q=&quickFilter=ALL&sort=name"
            url = self.TEAMSERVER_URL + endpoint
            header = {
                "API-Key": self.API_KEY,
                "Authorization": self.AUTHORIZATION,
            }
            # 18
            # Send the request and get its response
            response = requests.get(url=url, headers=header, stream=True)
            jsonreader = json.loads(response.text)

            # Setup file to output the text to
            filestring = "/UsersWhoHaventLoggedIn_%d_days.txt" % days
            filename = self.outputpath + filestring
            filewriter = open(filename, 'w+')

            # Loop through each user and get their last login time, compare it to the specified # of days
            if jsonreader["success"] is True:
                print("\nThe following users have logged into the teamserver in the last %d day(s):" % days)
                filewriter.write(
                    "The following users have logged into the teamserver in the last %d day(s):\n" % days)
                usercount = 1
                for user in jsonreader["users"]:
                    try:
                        # Get the user's last login time and convert it to a string
                        lastlogintime = datetime.datetime.fromtimestamp(
                            user['login']['last_login_time'] / 1000.0).strftime(
                            '%Y-%m-%d')

                        # Parse out month, day and year and find the difference between today and that date
                        year, month, day = lastlogintime.split("-")
                        dt_lastlogintime = datetime.datetime(int(year), int(month), int(day))
                        todaydate = datetime.datetime.today()
                        date_diff = (todaydate - dt_lastlogintime).days

                        # If difference between dates is greater than the one specified, add it to our output
                        if float(date_diff) < float(days):
                            linetowrite = (
                                "\t%d. %s logged in %d days ago" % (usercount, user['user_uid'], date_diff))
                            filewriter.write(linetowrite + "\n")
                            print(linetowrite)
                            usercount += 1
                    except Exception as e:
                        # print(e)
                        continue
            filewriter.close()

    def getApplicationsWithNoGroup(self):
        endpoint = self.ORGANIZATION_ID + "/groups"
        url = self.TEAMSERVER_URL + endpoint

        header = {
            "API-Key": self.API_KEY,
            "Authorization": self.AUTHORIZATION,
        }

        # Get response from the request
        response = requests.get(url=url, headers=header, stream=True)
        jsonreader = json.loads(response.text)

        # Setup file to output results to
        filename = self.outputpath + "/ApplicationsWithNoGroup.txt"
        filewriter = open(filename, 'w+')

        if jsonreader["success"] is True:

            # Get all group ids from custom groups
            group_ids = []
            custom_groups = jsonreader['custom_groups']['groups']
            for custom_group in custom_groups:
                # print(custom_group['name'])
                group_ids.append(custom_group['group_id'])

            # Get all group ids from default groups
            predefined_groups = jsonreader['predefined_groups']['groups']
            for predefined_group in predefined_groups:
                group_ids.append(predefined_group['group_id'])

            # Query each group and build a list of all apps registered within a group
            registered_application_ids = []
            for group_id in group_ids:
                url = self.TEAMSERVER_URL + "/" + self.ORGANIZATION_ID + "/groups/" + str(group_id)
                response = requests.get(url=url, headers=header, stream=True)
                jsonreader = json.loads(response.text)

                if jsonreader["success"] is True:

                    # Make sure the group has an application. Loop through each group and get all app ids which are
                    # included in a group.
                    if jsonreader['group']['applications'] is not None:
                        applications_group = jsonreader['group']['applications']
                    for application_group in applications_group:
                        applications = application_group['applications']
                        for application in applications:
                            registered_application_ids.append(application['app_id'])
                else:
                    print("\nUnable to query individual group id")

            # Get a list of all applications. Need to exclude merged and archived applications.
            endpoint = self.ORGANIZATION_ID + "/applications?includeMerged=false&includeArchived=false"
            url = self.TEAMSERVER_URL + endpoint

            response = requests.get(url=url, headers=header, stream=True)
            jsonreader = json.loads(response.text)

            # Loop through each application and see if it's in our list of registered apps
            if jsonreader["success"] is True:
                applications = jsonreader['applications']
                missing_app_ids = {}

                # If the application is not in our list of registered apps, add it to our final list
                for application in applications:
                    if application['app_id'] not in registered_application_ids:
                        missing_app_ids[application['app_id']] = application['name']

                # print(missing_app_ids.__len__(), missing_app_ids)

                # Loop through all missing applications and output it to the text file
                print("\nThe following applications are not included in a group:")
                filewriter.write("The following applications are not included in a group:\n")
                application_num = 1
                for missing_app_id, missing_app_name in missing_app_ids.items():
                    linetowrite = ("\t%d. %s" % (application_num, missing_app_name))
                    filewriter.write(linetowrite + "\n")
                    print(linetowrite)
                    application_num += 1

            else:
                print("\nUnable to get the list of all applications")

        else:
            print("\nUnable to connect to the teamserver")
        filewriter.close()

    # def getServersWithNoApplications(self):
        # The endpoint automatically returns all servers with no applications
        endpoint = self.ORGANIZATION_ID + '/servers/filter?applicationsIds=None'
        url = self.TEAMSERVER_URL + endpoint
        header = {
            "API-Key": self.API_KEY,
            "Authorization": self.AUTHORIZATION,
        }

        response = requests.get(url=url, headers=header, stream=True)
        jsonreader = json.loads(response.text)

        filename = self.outputpath + "/ServersWithNoApplications.txt"
        filewriter = open(filename, 'w+')

        # Loop through all servers
        if jsonreader["success"] is True:
            servernumber = 1
            print("\nThe following servers do not have an application:")
            filewriter.write("The following servers do not have an application:\n")

            # Add server to our list
            for server in jsonreader['servers']:
                linetowrite = (
                    "\t%d. %s running at hostname: '%s'" % (servernumber, server['name'], server['hostname']))
                filewriter.write(linetowrite + "\n")
                print(linetowrite)
                servernumber += 1

    def getUsersInGroups(self):
        endpoint = "/groups?expand=users,applications,skip_links&offset=0&q=&quickFilter=ALL&sort=name"
        url = self.TEAMSERVER_URL + "/" + self.ORGANIZATION_ID + "/" + endpoint

        header = {
            "API-Key": self.API_KEY,
            "Authorization": self.AUTHORIZATION,
        }

        response = requests.get(url=url, headers=header, stream=True)
        jsonreader = json.loads(response.text)

        filename = self.outputpath + "/UsersInGroups.txt"
        filewriter = open(filename, 'w+')

        if jsonreader['success'] is True:

            # Build up list of all group IDs
            group_ids = []
            for custom_group in jsonreader['custom_groups']['groups']:
                group_ids.append(custom_group['group_id'])
            for predefined_group in jsonreader['predefined_groups']['groups']:
                group_ids.append(predefined_group['group_id'])

            # Loop through all groups and get users in each group
            endpoint = "/groups/"

            for group_id in group_ids:
                url = self.TEAMSERVER_URL + "/" + self.ORGANIZATION_ID + "/" + endpoint + str(group_id)

                response = requests.get(url=url, headers=header, stream=True)
                jsonreader = json.loads(response.text)

                linetowrite = "\n" + jsonreader['group']['name'] + "\n"
                filewriter.write(linetowrite)
                print("\n" + jsonreader['group']['name'])

                try:
                    for user in jsonreader['group']['users']:
                        linetowrite = ("\t" + user['uid'] + "\n")
                        print(("\t" + user['uid']))
                        filewriter.write(linetowrite)

                except Exception as e:
                    print(e)
                    continue

    def metricsbuilder(self, days):
        # Fail the command if the number of days is not positive

        # https://app.contrastsecurity.com/Contrast/api/ng/142bb017-de7e-4af7-b5b9-f0782aa6d369/security/audit?expand=skip_links&limit=20&offset=0&startDate=2017-12-28

        if days < -1:
            print("\n* * The number of days must be greater than 0")

        else:
            endpoint = self.ORGANIZATION_ID + "/users?expand=preferences,login,role," \
                                              "skip_links&offset=0&q=&quickFilter=ALL&sort=name"
            url = self.TEAMSERVER_URL + endpoint
            header = {
                "API-Key": self.API_KEY,
                "Authorization": self.AUTHORIZATION,
            }
            # 18
            # Send the request and get its response
            response = requests.get(url=url, headers=header, stream=True)
            jsonreader = json.loads(response.text)

            # Setup file to output the text to
            filestring = "/usage_metrics.csv"
            filename = self.outputpath + filestring
            filewriter = open(filename, 'w+')

            # Loop through each user and get their last login time, compare it to the specified # of days
            if jsonreader["success"] is True:
                total_users = jsonreader["users"].__len__()
                print("\nThe following users have not logged into the teamserver for more than %d day(s):" % days)
                # filewriter.write(
                #     "The following users have not logged into the teamserver for more than %d day(s):\n" % days)
                usercount = 0
                for user in jsonreader["users"]:
                    try:
                        # Get the user's last login time and convert it to a string
                        lastlogintime = datetime.datetime.fromtimestamp(
                            user['login']['last_login_time'] / 1000.0).strftime(
                            '%Y-%m-%d')

                        # Parse out month, day and year and find the difference between today and that date
                        year, month, day = lastlogintime.split("-")
                        dt_lastlogintime = datetime.datetime(int(year), int(month), int(day))
                        todaydate = datetime.datetime.today()
                        date_diff = (todaydate - dt_lastlogintime).days

                        earlier_date = (datetime.datetime.today() - datetime.timedelta(days)).strftime("%Y-%m-%d")
                        todaydate_formatted = todaydate.strftime("%Y-%m-%d")

                        # If difference between dates is greater than the one specified, add it to our output
                        if float(date_diff) < float(days):
                            usercount += 1

                    except Exception as e:
                        # print(e)
                        continue
                login_percentage = float(float(usercount) / float(total_users)) * 100.0
                print(str(login_percentage) + "% of users have logged into teamserver the past " + str(days) + " days.\n")
                # linetowrite = (str(earlier_date) + "," + str(todaydate_formatted) + ',' + str(login_percentage) + ',')

            earlier_date = (datetime.datetime.today() - datetime.timedelta(days)).strftime("%Y-%m-%d")
            endpoint = self.ORGANIZATION_ID + "/security/audit?expand=skip_links&limit=1000000&startDate=%s" % earlier_date

            url = self.TEAMSERVER_URL + endpoint
            header = {
                "API-Key": self.API_KEY,
                "Authorization": self.AUTHORIZATION,
            }
            # 18
            # Send the request and get its response
            response = requests.get(url=url, headers=header, stream=True)
            jsonreader = json.loads(response.text)

            trace_status_change_counter = 0
            trace_num = 0
            # trace_status_matcher = re.compile('([\w\.]+@[\w\.]+com)\smarked status to (\w+).+([\d\w]{4}-[\d\w]{4}-[\d\w]{4}-[\d\w]{4})')
            trace_status_matcher = re.compile('([\w\.]+@[\w\.]+com)\smarked status to (\w+).+\s[for traces\(\)]+([\w\d\-\,]+)')
            trace_status_keyword = "trace_status_change"

            trace_deleted_counter = 0
            trace_deleted_keyword = "trace_deleted"

            report_usage_counter = 0
            report_usage_keyword = "report_generated"

            agent_downloaded_counter = 0
            agent_downloaded_keyword = "agent_download"

            license_applied_counter = 0
            license_applied_keyword = "license_applied"

            linetowrite = ""
            print("Total number of lines: ", jsonreader['logs'].__len__())
            filewriter.write("date,action,username,message\n")
            for log in jsonreader['logs']:
                log_message = log['message']

                epoch_timestamp = log['date']
                timestamp = datetime.datetime.fromtimestamp(epoch_timestamp / 1000.0).strftime('%Y-%m-%d')
                username = ""
                message = ""
                keyword = ""

                line = ""

                trace_status_matches = trace_status_matcher.findall(log_message)
                if trace_status_matches:
                    username = trace_status_matches[0][0]
                    message = trace_status_matches[0][1]
                    keyword = trace_status_keyword
                    trace_status_change_counter += 1
                    trace_num = trace_status_matches[0][2].count(",") + 1

                elif log_message.__contains__("deleted trace"):
                    trace_deleted_matcher = re.compile("User\s([\.\@\w]+)\sdeleted\strace\s([A-Z0-9\-]+)")
                    matches = trace_deleted_matcher.findall(log_message)
                    try:
                        username = matches[0][0]
                        message = matches[0][1]
                    except:
                        username = "na"
                        message = "na"
                    keyword = trace_deleted_keyword
                    trace_deleted_counter += 1
                elif log_message.__contains__("report"):
                    report_downloaded_matcher = re.compile("User\s([\.\@\w]+)\screated a new report")
                    matches = report_downloaded_matcher.findall(log_message)
                    try:
                        username = matches[0]
                    except:
                        username = ""
                    message = "report generated"
                    keyword = report_usage_keyword
                    report_usage_counter += 1
                elif log_message.__contains__("downloaded") and not log_message.__contains__("agent_"):
                    # agent_download_matcher = re.compile('\@.+downloaded\s(\w+)\s\w+')
                    agent_download_matcher = re.compile('User\s([\w\@\.]+com)[downloaded\s]+([\w\s\_]+)[a|A]gent')
                    keyword = agent_downloaded_keyword
                    try:
                        matches = agent_download_matcher.findall(log_message)
                        username = matches[0][0]
                        if log_message.__contains__("JAVA_LAUNCHER"):
                            message = "JAVA_LAUNCHER"
                        else:
                            message = matches[0][1]
                    except:
                        message = "na"
                        username = "na"
                    agent_downloaded_counter += 1
                elif log_message.__contains__("License"):
                    # license_applied_matcher = re.compile("Enterprise License[\s\w\:]+\'([\w\s\\\'\:]+)\'[\sby]+(.+)")
                    # license_applied_matcher = re.compile("Enterprise License applied to application:[\s\\\']+(.+)[\\\'\s]+by\s(.+)")
                    license_applied_matcher = re.compile("Enterprise License applied to application:[\s\\\']+(.+)\'[\\\'\s]+by\s(.+)")
                    license_applied_matches = license_applied_matcher.findall(log_message)
                    keyword = license_applied_keyword
                    try:
                        username = license_applied_matches[0][1]
                        message = license_applied_matches[0][0]
                    except:
                        username = "na"
                        message = "na"
                    license_applied_counter += 1

                # print(log_message)
                try:
                    if username is not "":
                        if keyword is "trace_status_change":
                            for trace in range(0, trace_num):
                                print(log_message)
                                line = timestamp + ',' + keyword + ',' + username + ',' + message + ',\n'
                                filewriter.write(line)
                                print(line)
                        else:
                            print(log_message)
                            line = timestamp + ',' + keyword + ',' + username + ',' + message + ',\n'
                            filewriter.write(line)
                            print(line)

                        # print("====> ",timestamp, keyword, username, message)
                except:
                    continue



            # filewriter.write(linetowrite)
            filewriter.close()

    def test(self):
        diffdate = datetime.datetime.today() - datetime.timedelta(7)
        # diff_date = todaydate - datetime.timedelta(7)
        print(diffdate.strftime("%Y-%m-%d"))


controller = controller()
# controller.getServersWithNoApplications()
controller.getUsersLoggedInDays(days=60)
# controller.getApplicationsWithNoGroup()
controller.getNeverLoggedInUsers()
# controller.getOfflineServers()
# controller.getUsersInGroups()
controller.metricsbuilder(days=900)
# controller.test()
