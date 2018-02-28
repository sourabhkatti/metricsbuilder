import os
import base64
import json
import requests
import argparse
import re
import calendar
from datetime import datetime, timedelta


# - Offline servers
# - Users who have never logged in
# - Users who have not logged in in ___ days
# - Apps that are not associated with a group
# - Servers with no apps
# - All groups and users contained within them
# - Export the audit log into a csv


class controller:
    ##################################################
    # Replace the below fields with your own details #
    ##################################################


    # ORGANIZATION_ID = ""
    # TEAMSERVER_URL = ""
    # API_KEY = ""
    # SERVICE_KEY = ""
    # USERNAME = ""

    ORGANIZATION_ID = "0f767995-4882-4c7c-889f-994d945ff0d5"
    TEAMSERVER_URL = "https://apptwo.contrastsecurity.com/Contrast/api/ng/"
    API_KEY = "B6Y14MfSBsmLC6k4GxhIlGk297ZuvG9N"
    SERVICE_KEY = "ZAXHB4LTKMH25NQ1"
    USERNAME = "sourabh.katti@contrastsecurity.com"

    # ORGANIZATION_ID = "142bb017-de7e-4af7-b5b9-f0782aa6d369"
    # TEAMSERVER_URL = "https://app.contrastsecurity.com/Contrast/api/ng/"
    # API_KEY = "vgy5soZn15wnVPHH539pF8F7niofbl4N"
    # SERVICE_KEY = "4K5V00T6JB90KPAD"
    # USERNAME = "danielan@us.ibm.com"

    header = {}

    FOUND_DATE = "FIRST"
    SORTING = "ALL"
    LICENSED_ONLY = False
    application_licensed_status = {}

    # Starting date: January 1, 2018
    startingMonth = 9
    startingDay = 1
    startingYear = 2017
    startingHour = 21

    # Ending date: February 10, 2018
    endingMonth = 9
    endingDay = 30
    endingYear = 2017
    endingHour = 21

    endTimeEpoch = 0
    startTimeEpoch = 0

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

        self.AUTHORIZATION = base64.b64encode((self.USERNAME + ':' + self.SERVICE_KEY).encode('utf-8'))
        self.header = {
            "Authorization": self.AUTHORIZATION,
            "API-Key": self.API_KEY
        }

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

    def getUsersNotLoggedInDays(self, days):
        # returns all users who have not logged in during the last "days" number of days
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
                print("\nThe following users have NOT logged into the teamserver in the last %d day(s):" % days)
                filewriter.write(
                    "The following users have NOT logged into the teamserver in the last %d day(s):\n" % days)
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
                        if float(date_diff) > float(days):
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

    def getServersWithNoApplications(self):
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

    def getUsersInGroups(self, applications=None):
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
            print("Build up list of all group IDs")
            group_ids = []
            for custom_group in jsonreader['custom_groups']['groups']:
                group_ids.append(custom_group['group_id'])
            for predefined_group in jsonreader['predefined_groups']['groups']:
                group_ids.append(predefined_group['group_id'])

            # Loop through all groups and get users in each group
            endpoint = "/groups/"
            lineheader = "Group Name, Email Address"
            print("Looping through groups")
            for group_id in group_ids:
                url = self.TEAMSERVER_URL + "/" + self.ORGANIZATION_ID + "/" + endpoint + str(group_id)

                response = requests.get(url=url, headers=header, stream=True)
                jsonreader = json.loads(response.text)

                if applications is None:
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
                else:
                    application_username_filename = self.outputpath + "/UsersAssociatedToApplications.csv"
                    application_username_filewriter = open(application_username_filename, 'w+')
                    applications_in_group = jsonreader['group']['applications']

                    if jsonreader['group']['users'].__len__() > 0:
                        if applications_in_group is not None:
                            for application in applications['applications']:
                                # print(application['name'])
                                linetowrite = ""

                                if applications_in_group.__len__() > 0:
                                    for application_in_group in applications_in_group[0]['applications']:
                                        if application['name'] == application_in_group['name']:
                                            linetowrite = application['name'] + ','
                                            for user in jsonreader['group']['users']:
                                                linetowrite += user['uid'] + ','
                                            linetowrite += "\n"
                                            print(linetowrite)
                                            application_username_filewriter.write(linetowrite)
                                else:
                                    linetowrite = application['name'] + ','
                                    for user in jsonreader['group']['users']:
                                        linetowrite += user['uid'] + ','
                                    linetowrite += "\n"
                                    print(linetowrite)
                                    application_username_filewriter.write(linetowrite)



            application_username_filewriter.close()

    def getPercentUsersLoggedIn(self, days):
        endpoint = self.ORGANIZATION_ID + "/users?expand=preferences,login,role," \
                                          "skip_links&offset=0&q=&quickFilter=ALL&sort=name"
        url = self.TEAMSERVER_URL + endpoint
        header = {
            "API-Key": self.API_KEY,
            "Authorization": self.AUTHORIZATION,
        }
        response = requests.get(url=url, headers=header, stream=True)
        jsonreader = json.loads(response.text)

        # Setup file to output the text to
        filestring = "/usage_metrics.csv"
        filename = self.outputpath + filestring
        filewriter = open(filename, 'w+')

        # Loop through each user and get their last login time, compare it to the specified # of days
        if jsonreader["success"] is True:
            total_users = jsonreader["users"].__len__()
            # print("\nThe following users have logged into the teamserver for more than %d day(s):" % days)
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
            login_percentage = int(round(float(float(usercount) / float(total_users)) * 100.0))
            print(str(login_percentage) + "% of users have logged into teamserver the past " + str(days) + " days.\n")

    def parseAuditLog(self, days):

        # Setup file to output the text to
        filestring = "/usage_metrics.csv"
        filename = self.outputpath + filestring
        filewriter = open(filename, 'w+')

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

        trace_status_keyword = "trace_status_change"

        trace_deleted_counter = 0
        trace_deleted_keyword = "trace_deleted"

        report_usage_counter = 0
        report_usage_keyword = "report_generated"

        agent_downloaded_counter = 0
        agent_downloaded_keyword = "agent_download"

        license_applied_counter = 0
        license_applied_keyword = "license_applied"

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

            trace_status_matcher = re.compile(
                '([\w\.]+@[\w\.]+com)\smarked status to (\w+).+\s[for traces\(\)]+([\w\d\-\,]+)')
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
                agent_download_matcher = re.compile('User\s([\w\@\.]+com)[downloaded\s]+([\w\s\_\.]+)[a|A]gent')
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
                license_applied_matcher = re.compile(
                    "Enterprise License applied to application:[\s\\\']+(.+)\'[\\\'\s]+by\s(.+)")
                license_applied_matches = license_applied_matcher.findall(log_message)
                keyword = license_applied_keyword
                try:
                    username = license_applied_matches[0][1]
                    message = license_applied_matches[0][0]
                except:
                    username = "na"
                    message = "na"
                license_applied_counter += 1

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

        filewriter.close()

    def metricsbuilder(self, days):

        # Fail the command if the number of days is not positive
        if days < -1:
            print("\n* * The number of days must be greater than 0")

        else:
            self.getPercentUsersLoggedIn(days)
            self.parseAuditLog(days)

    # Get date range for the vulnerabilities to pull from teamserver
    def getDateRange(self):
        if self.startingMonth is 0:
            print("Please specify the date range to pull vulnerability information.")
            self.startingMonth = int(input("\tStarting month number (1-12): "))
            while self.startingMonth < 1 or self.startingMonth > 12:
                print("The month should be between 1 and 12!")
                self.startingMonth = int(input("\tStarting month number (1-12): "))

        if self.startingDay is 0:
            self.startingDay = int(input("\tStarting day (1-31): "))
            while self.startingDay < 1 or self.startingDay > 31:
                print("The day should be between 1 and 31!")
                self.startingDay = int(input("\tStarting day (1-31): "))

        if self.endingMonth is 0:
            self.endingMonth = int(input("\tEnding month number (1-12): "))
            while self.endingMonth < 1 or self.endingMonth > 12:
                print("The month should be between 1 and 12!")
                self.endingMonth = int(input("\tEnding month number (1-12): "))

        if self.endingDay is 0:
            self.endingDay = int(input("\tEnding day (1-31): "))
            while self.endingDay < 1 or self.endingDay > 31:
                print("The day should be between 1 and 31!")
                self.endingDay = int(input("\tEnding day (1-31): "))

    # Manage how vulnerabilities are associated with time
    def dateTrendManager(self, printMetrics=True):

        # Get the months and days we'll be looking through
        self.getDateRange()

        yearlyMetrics = {}

        # Loop through all years
        year_index = self.startingYear

        if self.LICENSED_ONLY:
            applications = self.getApplications()
            self.application_licensed_status = self.getApplicationLicenseStatus(applications)

            # self.startTimeEpoch = int(
            #     datetime.datetime(year_index, month_index, 1, 0, 0, 0, 0).timestamp()) * 1000
            # self.endTimeEpoch = int(
            #     datetime.datetime(year_index, month_index, endingDay, 23, 59, 59, 99).timestamp()) * 1000

        # If time range spans multiple years, loop through all months in those years except the ending year
        if year_index < self.endingYear:
            # Loop through all months in  previous years
            starting_month_index = self.startingMonth
            while year_index < self.endingYear:
                monthlyMetrics = {}
                for month_index in range(starting_month_index, 13):
                    month = datetime(year_index, month_index, 1).strftime("%B")
                    endingDay = calendar.monthrange(year_index, month_index)[1]  # Get the number of days in the month
                    self.startTimeEpoch = int((
                                                  datetime(year_index, month_index, 1, 0, 0, 0, 0) - timedelta(
                                                      hours=3)).timestamp()) * 1000
                    self.endTimeEpoch = int((
                                                datetime(year_index, month_index, endingDay, 23, 59, 59,
                                                         99) - timedelta(hours=3)).timestamp()) * 1000
                    print("\n==========> Getting vulns in between %s %d, %d and %s %d, %d" % (
                        month, 1, year_index, month, endingDay, year_index))
                    monthlyMetrics[month] = self.getVulnsByDate()  # Get vulnerabilities for the month
                yearlyMetrics[year_index] = monthlyMetrics
                year_index += 1
                starting_month_index = 1

            # Loop through all months in the current year except the last month
            monthlyMetrics = {}
            starting_month_index = 1
            for month_index in range(starting_month_index, self.endingMonth):
                month = datetime(year_index, month_index, 1).strftime("%B")
                endingDay = calendar.monthrange(year_index, month_index)[1]  # Get the number of days in the month
                self.startTimeEpoch = int((
                                              datetime(year_index, month_index, 1, 0, 0, 0, 0) - timedelta(
                                                  hours=3)).timestamp()) * 1000
                self.endTimeEpoch = int((
                                            datetime(year_index, month_index, endingDay, 23, 59, 59, 99) - timedelta(
                                                hours=3)).timestamp()) * 1000
                print("\n==========> Getting vulns in between %s %d, %d and %s %d, %d" % (
                    month, 1, year_index, month, endingDay, year_index))
                monthlyMetrics[month] = self.getVulnsByDate()  # Get vulnerabilities for current month

            # Get vulns for the last month
            month_index = self.endingMonth
            month = datetime(year_index, month_index, 1).strftime("%B")
            self.startTimeEpoch = int((
                                          datetime(year_index, month_index, 1, 0, 0, 0, 0) - timedelta(
                                              hours=3)).timestamp()) * 1000
            self.endTimeEpoch = int((
                                        datetime(year_index, month_index, self.endingDay, 23, 59, 59, 99) - timedelta(
                                            hours=3)).timestamp()) * 1000
            print("\n==========> Getting vulns in between %s %d, %d and %s %d, %d" % (
                month, 1, year_index, month, self.endingDay, year_index))
            monthlyMetrics[month] = self.getVulnsByDate()  # Get vulnerabilities for current month
            yearlyMetrics[year_index] = monthlyMetrics

        else:

            # If the starting year and ending year are the same, loop through all months except the last month
            monthlyMetrics = {}
            for month_index in range(self.startingMonth, self.endingMonth):
                month = datetime(year_index, month_index, 1).strftime("%B")
                endingDay = calendar.monthrange(year_index, month_index)[1]  # Get the number of days in the month
                self.startTimeEpoch = int((
                                              datetime(year_index, month_index, 1, 0, 0, 0, 0) - timedelta(
                                                  hours=3)).timestamp()) * 1000
                self.endTimeEpoch = int((
                                            datetime(year_index, month_index, endingDay, 23, 59, 59, 99) - timedelta(
                                                hours=3)).timestamp()) * 1000
                print("\n==========> Getting vulns in between %s %d, %d and %s %d, %d" % (
                    month, 1, year_index, month, endingDay, year_index))
                monthlyMetrics[month] = self.getVulnsByDate()  # Get vulnerabilities for current month

            # Get vuln metrics for the last month
            month_index = self.endingMonth
            month = datetime(year_index, month_index, 1).strftime("%B")
            self.startTimeEpoch = int((
                                          datetime(year_index, month_index, 1, 0, 0, 0, 0) - timedelta(
                                              hours=3)).timestamp()) * 1000
            self.endTimeEpoch = int((
                                        datetime(year_index, month_index, self.endingDay, 23, 59, 59, 99) - timedelta(
                                            hours=3)).timestamp()) * 1000
            print("\n==========> Getting vulns in between %s %d, %d and %s %d, %d" % (
                month, 1, year_index, month, self.endingDay, year_index))
            monthlyMetrics[month] = self.getVulnsByDate()  # Get vulnerabilities for current month
            yearlyMetrics[year_index] = monthlyMetrics

        cumulative_yearly_metrics, serious_categories = self.getCumulativeCounts(yearlyMetrics,
                                                                                 printMetrics=printMetrics)
        # print(cumulative_yearly_metrics)
        self.writeCumulativeMetrics(cumulative_yearly_metrics, serious_categories, printMetrics)

    def writeCumulativeMetrics(self, cumulativeMetrics, serious_categories, printMetrics):
        cumulative_metrics_filename = self.outputpath + "/CumulativeMetrics.csv"
        cumulative_filewriter = open(cumulative_metrics_filename, 'w+')

        serious_metrics = self.outputpath + "/SeriousMetrics.csv"
        serious_filewriter = open(serious_metrics, 'w+')

        metrics_linetowrite = [
            "Year,Month,Total Traces,Serious Traces,Cumulative Total Traces,Cumulative Serious Traces"]

        serious_category_header = "Year,Month"
        serious_category_total = 0
        serious_category_lines = []
        # for category in serious_categories:
        #     serious_category_linetowrite += str(category) + ','

        for category in serious_categories.keys():
            serious_category_header += ',' + category
        serious_category_header += ',Total'

        for year, monthlymetrics in cumulativeMetrics.items():
            for month, metrics in monthlymetrics.items():
                monthly_serious_category_count = 0
                serious_category_linetowrite = str(year) + ',' + str(month) + ','
                mec_linetowrite = str(year) + ',' + str(month) + ',' + str(metrics['total_traces']) + ',' + str(
                    metrics[
                        'serious_traces']) + ',' + str(metrics['cumulative_total_traces']) + ',' + str(
                    metrics['cumulative_serious_traces'])
                try:
                    # Loop through all serious categories found during date range
                    if serious_categories.__len__() > 0:
                        # Loop through all serious categories in the month
                        for category, total_category_count in serious_categories.items():
                            # try:
                            # If the category is the current serious metric
                            if category in metrics['serious_category_counts'].keys():
                                count = metrics['serious_category_counts'][category]
                                monthly_serious_category_count += count
                                serious_category_linetowrite += str(count) + ','
                            else:
                                serious_category_linetowrite += '0,'
                    serious_category_total += monthly_serious_category_count
                    # except:
                    #     serious_category_linetowrite += '0,'
                except Exception as e:
                    print(e)

                serious_category_linetowrite += str(monthly_serious_category_count)
                metrics_linetowrite.append(mec_linetowrite)
                serious_category_lines.append(serious_category_linetowrite)

        for line in metrics_linetowrite:
            cumulative_filewriter.write(line + '\n')

        serious_filewriter.write(serious_category_header + '\n')
        for line in serious_category_lines:
            serious_filewriter.write(line + '\n')
        linetowrite = "Total,Total"
        for count in serious_categories.values():
            linetowrite += ',' + str(count)
        linetowrite += ',' + str(serious_category_total)
        serious_filewriter.write(linetowrite)

        cumulative_filewriter.close()
        serious_filewriter.close()

    # Calculate cumulative vulnerability metrics
    def getCumulativeCounts(self, yearlymetrics, printMetrics=True):
        cumulative_total_counts = 0
        cumulative_serious_total_counts = 0
        serious_categories = {}
        for year, monthlymetrics in yearlymetrics.items():
            for month, metrics in monthlymetrics.items():
                try:
                    cumulative_total_counts += metrics['total_traces']
                    cumulative_serious_total_counts += metrics['serious_traces']

                    metrics['cumulative_total_traces'] = cumulative_total_counts
                    metrics['cumulative_serious_traces'] = cumulative_serious_total_counts

                    if metrics['serious_category_counts'].__len__() > 0:
                        monthly_serious_categories = metrics['serious_category_counts']
                        for category, count in monthly_serious_categories.items():
                            if category in serious_categories.keys():
                                serious_categories[category] += count
                            else:
                                serious_categories[category] = count
                    else:
                        pass
                    if printMetrics:
                        print(year, month, metrics['total_traces'], cumulative_total_counts, metrics['serious_traces'],
                              cumulative_serious_total_counts)
                except Exception as e:
                    print(e)
                    continue
        return yearlymetrics, serious_categories

    # Get vulnerabilities based on the specified date range
    def getVulnsByDate(self):
        print(
            "Fetch Vulnerabilities, sorting by " + self.SORTING + " and " + self.FOUND_DATE + " found in the date range...")

        endpoint = self.TEAMSERVER_URL + self.ORGANIZATION_ID + "/orgtraces" \
                                                                "/filter/?endDate=" + str(
            self.endTimeEpoch) + "&expand=application,servers,violations,bugtracker," \
                                 "skip_links&quickFilter=" + self.SORTING + "&limit=100000&sort=-lastTimeSeen&startDate=" + str(
            self.startTimeEpoch) + \
                   "&timestampFilter=" + self.FOUND_DATE

        # endpoint = self.TEAMSERVER_URL + self.ORGANIZATION_ID + "/orgtraces" \
        #                                                         "/filter/?endDate=1517461140000&expand=application,servers,violations,bugtracker," \
        #                          "skip_links&quickFilter=" + self.SORTING + "&limit=100000&sort=-lastTimeSeen&startDate=1514782800000&timestampFilter=" + self.FOUND_DATE

        print("\tSending request to teamserver", end="")

        try:
            # Get all vulns which need an issue opened for them
            r = requests.get(url=endpoint, headers=self.header)
            vulns = json.loads(r.text)
            print(".... Done!")
            return self.getVulnMetrics(vulns['traces'])
        except Exception as e:
            print("ERROR: Unable to connect to teamserver. Please check your authentication details.")
            print(e)
            return {}

    # Parse vulnerabilities and build metrics
    def getVulnMetrics(self, vulns):
        print("\nParsing Vulnerabilities...")

        traceNum = vulns.__len__()

        # total_traces = Total number of traces found in this time span
        # serious_traces = Total number of CRITICAL or HIGH vulns
        # serious_category_counts = Total number of serious categories and the number of vulns found in each one
        # changed_status = Number of vulns with a status other than Reported
        # remediated_status = Number of vulns with a status of Remediated, Not a Problem or Fixed
        metrics = {}
        metrics['serious_traces'] = 0
        metrics['changed_status'] = 0
        metrics['remediated_status'] = 0
        metrics['serious_category_counts'] = {}
        metrics['total_traces'] = 0

        if traceNum > 0:
            print("\tTotal number of traces: %d" % traceNum)
            metrics['total_traces'] = traceNum

            seriousVulnCounter = 0
            seriousCategoryCounter = {}

            remediatedStatusCount = 0
            statusCount = 0

            unlicensedCounter = 0

            for vuln in vulns:
                if self.LICENSED_ONLY:
                    if vuln['application']['parent_app_id'] is not None:
                        vuln_app_id = vuln['application']['parent_app_id']
                    else:
                        vuln_app_id = vuln['application']['app_id']
                    if self.application_licensed_status[vuln_app_id] is False:
                        unlicensedCounter += 1
                    else:
                        # Check severity for serious vulns and increment counter for that severity
                        if vuln['default_severity'] in ("CRITICAL", "HIGH"):
                            seriousVulnCounter += 1
                            if vuln['rule_name'] in seriousCategoryCounter.keys():
                                seriousCategoryCounter[vuln['rule_name']] += 1
                            else:
                                seriousCategoryCounter[vuln['rule_name']] = 1

                        if vuln['status'] in ("Remediated", "Fixed", "Not a Problem", "Suspicious", "Confirmed"):
                            if vuln['status'] in ("Remediated", "Fixed", "Not a Problem"):
                                remediatedStatusCount += 1
                            statusCount += 1
                else:
                    if vuln['default_severity'] in ("CRITICAL", "HIGH"):
                        seriousVulnCounter += 1
                        if vuln['rule_name'] in seriousCategoryCounter.keys():
                            seriousCategoryCounter[vuln['rule_name']] += 1
                        else:
                            seriousCategoryCounter[vuln['rule_name']] = 1

                    if vuln['status'] in ("Remediated", "Fixed", "Not a Problem", "Suspicious", "Confirmed"):
                        if vuln['status'] in ("Remediated", "Fixed", "Not a Problem"):
                            remediatedStatusCount += 1
                        statusCount += 1
            print("\tTotal Unlicensed Vulnerabilities: ", unlicensedCounter)
            print("\n\tSerious Vulnerabilities Metrics")
            print("\t\t- Number of serious vulnerabilities: %d" % seriousVulnCounter)
            metrics['serious_traces'] = seriousVulnCounter

            category_counts = {}
            for category, count in seriousCategoryCounter.items():
                print("\t\t\t* %s: %d" % (category, count))
                category_counts[category] = count
            metrics['serious_category_counts'] = category_counts

            print("\n\tVulnerability Status")
            print("\t\t- Number of vulns in a status besides Reported:", statusCount)
            metrics['changed_status'] = statusCount

            print("\t\t- Number of vulnerabilities marked Remediated, Not a Problem or Fixed:",
                  remediatedStatusCount)
            metrics['remediated_status'] = remediatedStatusCount

            return metrics

        else:
            print("\tThere were no traces found during the specified date range")
            metrics['serious_traces'] = 0
            metrics['changed_status'] = 0
            metrics['remediated_status'] = 0
            metrics['total_traces'] = 0
            metrics['serious_category_counts'] = {}
            return metrics

    def applicationMetricsManager(self):
        applications = self.getApplications()
        # self.writeApplicationMetrics(applications)
        self.getUsersInGroups(applications=applications)

    # Get application metrics (count of applications)
    def getApplications(self):
        print("\nApplication Metrics")
        endpoint = self.TEAMSERVER_URL + self.ORGANIZATION_ID + "/applications/filter?expand=scores,license," \
                                                                "trace_breakdown,compliance_policy," \
                                                                "production_protected," \
                                                                "skip_links&filterText=&includeArchived=false" \
                                                                "&includeMerged=true&limit=100000&quickFilter" \
                                                                "=ALL&sort=appName"
        try:
            r = requests.get(url=endpoint, headers=self.header)
            if r.status_code == 504:
                limit = 50
                offset = 0
                endpoint = self.TEAMSERVER_URL + self.ORGANIZATION_ID + "/applications/filter?expand=scores,license," \
                                                                        "trace_breakdown,compliance_policy," \
                                                                        "production_protected," \
                                                                        "skip_links&filterText=&includeArchived=false" \
                                                                        "&includeMerged=true&limit=50&quickFilter" \
                                                                        "=ALL&sort=appName"
                r = requests.get(url=endpoint, headers=self.header)
                applications = json.loads(r.text)
                app_count = applications['count']
                print("\t- Number of applications:", app_count)

                for offset in range(limit, app_count, limit):
                    endpoint = self.TEAMSERVER_URL + self.ORGANIZATION_ID + (
                        "/applications/filter?expand=scores,license," \
                        "trace_breakdown,compliance_policy," \
                        "production_protected," \
                        "skip_links&filterText=&includeArchived=false" \
                        "&includeMerged=true&limit=%d&offset=%d"
                        "&quickFilter" \
                        "=ALL&sort=appName" % (limit, offset))
                    r = requests.get(url=endpoint, headers=self.header)
                    next_applications = json.loads(r.text)
                    for application in next_applications['applications']:
                        applications['applications'].append(application)
                    print("\t\tApplications picked up: ", offset)
                return applications
            else:
                applications = json.loads(r.text)
                print("\t- Number of applications:", applications['count'])
                return applications
        except:
            print("ERROR: Unable to retrieve applications")

    def writeApplicationMetrics(self, applications):

        filename = self.outputpath + '/ApplicationTraceBreakdown.csv'
        filewriter = open(filename, 'w+')

        app_severity_breakdown_header = "Application Name,Critical,High,Medium,Low,Note\n"
        app_severity_breakdown_lines = [app_severity_breakdown_header]

        for application in applications['applications']:
            app_severity_breakdown_linetowrite = ""
            app_severity_breakdown_linetowrite += application['name'] + ','
            app_severity_breakdown_linetowrite += str(application['trace_breakdown']['criticals']) + ','
            app_severity_breakdown_linetowrite += str(application['trace_breakdown']['highs']) + ','
            app_severity_breakdown_linetowrite += str(application['trace_breakdown']['meds']) + ','
            app_severity_breakdown_linetowrite += str(application['trace_breakdown']['lows']) + ','
            app_severity_breakdown_linetowrite += str(application['trace_breakdown']['notes']) + '\n'
            app_severity_breakdown_lines.append(app_severity_breakdown_linetowrite)

        for line in app_severity_breakdown_lines:
            filewriter.write(line)

        filewriter.close()

    def getApplicationLicenseStatus(self, applications):
        app_license_status = {}
        if applications['count'] > 0:
            for application in applications['applications']:
                if application['license']['level'] == 'Licensed':
                    app_license_status[application['app_id']] = True
                else:
                    app_license_status[application['app_id']] = False
        return app_license_status

    def getApplicationsWithNoTag(self):
        # Text to search tags with
        search_text = "BU:"
        endpoint = self.ORGANIZATION_ID + "/applications?includeMerged=false&includeArchived=false"
        url = self.TEAMSERVER_URL + endpoint

        response = requests.get(url=url, headers=self.header, stream=True)
        jsonreader = json.loads(response.text)

        # filename = '/appsWithNoBU.csv'
        # filewriter = open(filename, 'w+')

        applications = jsonreader['applications']
        app_count = 0
        for application in applications:
            tagged = False
            tags = application['tags']
            try:
                for tag in tags:
                    datatag = tag.find(search_text)
                    if datatag is not -1:
                        tagged = True
            except:
                # print(application['name'])
                pass
            if not tagged:
                app_count += 1
                print(str(app_count) + ". " + application['name'])
                # filewriter.close()

    def test(self):
        a = datetime(2017, 12, 1, 0, 0, 0, 0)
        b = (a - timedelta(hours=3)).timestamp()
        print(a)
        print(b)


controller = controller()
# controller.getServersWithNoApplications()
# controller.getUsersNotLoggedInDays(days=30)
# controller.getApplicationsWithNoGroup()
# controller.getNeverLoggedInUsers()
# controller.getOfflineServers()
# controller.getUsersInGroups()
# controller.metricsbuilder(days=90)
# controller.dateTrendManager()
controller.applicationMetricsManager()
# controller.test()
